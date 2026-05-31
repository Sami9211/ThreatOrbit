import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from log_api.config import CORS_ORIGINS, REPORT_OUTPUT_PATH, SUPPORTED_FORMATS
from log_api.models import AnomalyFinding, AnalysisResult, LogFormat
from log_api.parsers.syslog import parse_syslog
from log_api.parsers.apache import parse_apache
from log_api.parsers.windows_event import parse_windows_event
from log_api.parsers.generic import parse_generic
from log_api.detectors.pattern import run_pattern_detector
from log_api.detectors.statistical import run_statistical_detector
from log_api.detectors.ml_detector import run_ml_detector
from log_api.detectors.temporal import run_temporal_detector
from log_api.alerts.alerter import process_findings, summarise, top_source_ips
from log_api.reporter.report import generate_html_report
from log_api.stix_from_findings import findings_to_stix_bundle
from log_api.metrics import LogMetrics
from log_api.db import init_db, get_conn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Log Anomaly API", version="1.2.0")

_cors_origins = [o.strip() for o in CORS_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_results: dict = {}
metrics = LogMetrics()


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": "Validation error", "detail": exc.errors()})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "detail": str(exc)})


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "log_api"}


@app.get("/ready")
def ready():
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"ready": True}
    except Exception as e:
        return {"ready": False, "error": str(e)}


@app.get("/metrics")
def get_metrics():
    return metrics.to_dict()


@app.get("/trends/severity")
def severity_trends():
    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in _results.values():
        for k, v in r.summary.items():
            buckets[k] = buckets.get(k, 0) + v
    return {"total_analyses": len(_results), "severity_totals": buckets}


@app.get("/")
def root():
    return {"service": "Log Anomaly API", "status": "running",
            "supported_formats": SUPPORTED_FORMATS}


# ---------------------------------------------------------------------------
# Core analysis endpoint
# ---------------------------------------------------------------------------

@app.post("/analyse")
async def analyse(
    file: UploadFile = File(...),
    log_format: LogFormat = Query(LogFormat.APACHE),
    generate_report: bool = Query(True),
    run_async: bool = Query(False, alias="async"),
):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="File is empty")
    if len(lines) > 2_000_000:
        raise HTTPException(status_code=400, detail="File too large for single-run analysis")

    job_id = str(uuid.uuid4())
    _save_job(job_id, "running", {})

    if run_async:
        # Fire-and-forget; client polls GET /jobs/{job_id}
        asyncio.create_task(
            _analyse_background(job_id, lines, log_format.value, generate_report)
        )
        return JSONResponse({"job_id": job_id, "status": "queued"})

    # Synchronous path: runs in thread pool so the event loop stays free
    try:
        result = await asyncio.to_thread(_run_analysis, lines, log_format.value, generate_report)
        _results[job_id] = result
        _save_job(job_id, "completed", result.summary)
        metrics.mark_success(len(result.findings))
        return result
    except Exception as e:
        _save_job(job_id, "failed", {"error": str(e)})
        metrics.mark_failure()
        raise HTTPException(status_code=500, detail=str(e))


async def _analyse_background(job_id: str, lines: list, log_format: str, generate_report: bool):
    try:
        result = await asyncio.to_thread(_run_analysis, lines, log_format, generate_report)
        _results[job_id] = result
        _save_job(job_id, "completed", result.summary)
        metrics.mark_success(len(result.findings))
    except Exception as e:
        _save_job(job_id, "failed", {"error": str(e)})
        metrics.mark_failure()
        logger.exception("Background analysis failed for job %s", job_id)


# ---------------------------------------------------------------------------
# Job / result endpoints
# ---------------------------------------------------------------------------

@app.get("/jobs/{job_id}")
def job_status(job_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, status, created_at, updated_at, summary_json "
            "FROM analysis_jobs WHERE id=?",
            (job_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    resp: dict = {"id": row[0], "status": row[1], "created_at": row[2], "updated_at": row[3]}
    if row[4]:
        try:
            resp["summary"] = json.loads(row[4])
        except Exception:
            resp["summary"] = row[4]

    if row[1] == "completed" and row[0] in _results:
        resp["result_url"] = f"/results/{row[0]}"

    return resp


@app.get("/report", response_class=HTMLResponse)
def report():
    if not os.path.exists(REPORT_OUTPUT_PATH):
        raise HTTPException(status_code=404, detail="No report generated yet.")
    with open(REPORT_OUTPUT_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/results/{result_id}")
def get_result(result_id: str):
    if result_id not in _results:
        raise HTTPException(status_code=404, detail="Result not found")
    return _results[result_id]


@app.get("/results/{result_id}/stix")
def export_result_stix(result_id: str):
    if result_id not in _results:
        raise HTTPException(status_code=404, detail="Result not found")
    bundle = findings_to_stix_bundle(_results[result_id])
    resp = JSONResponse(content=bundle)
    resp.headers["Content-Type"] = "application/stix+json"
    return resp


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_analysis(lines: List[str], log_format: str, generate_report: bool) -> AnalysisResult:
    start = time.time()
    parser = {
        "syslog": parse_syslog,
        "apache": parse_apache,
        "windows_event": parse_windows_event,
        "generic": parse_generic,
    }.get(log_format, parse_generic)

    entries, parse_errors = parser(lines)

    findings: List[AnomalyFinding] = []
    findings.extend(run_pattern_detector(entries))
    findings.extend(run_statistical_detector(entries))
    findings.extend(run_ml_detector(entries))
    findings.extend(run_temporal_detector(entries))

    final_findings = process_findings(findings)
    result = AnalysisResult(
        log_format=log_format,
        total_lines=len(lines),
        parsed_lines=len(entries),
        parse_errors=parse_errors,
        analysis_duration_seconds=round(time.time() - start, 3),
        findings=final_findings,
        summary=summarise(final_findings),
        top_source_ips=top_source_ips(final_findings),
        analysed_at=datetime.now(timezone.utc),
        detectors_used=["Pattern", "Statistical", "ML", "Temporal"],
    )

    if generate_report:
        generate_html_report(result, REPORT_OUTPUT_PATH)

    return result


def _save_job(job_id: str, status: str, summary: dict):
    now = datetime.now(timezone.utc).isoformat()
    summary_str = json.dumps(summary) if isinstance(summary, dict) else str(summary)
    with get_conn() as conn:
        exists = conn.execute(
            "SELECT id FROM analysis_jobs WHERE id=?", (job_id,)
        ).fetchone()
        if exists:
            conn.execute(
                "UPDATE analysis_jobs SET status=?, updated_at=?, summary_json=? WHERE id=?",
                (status, now, summary_str, job_id),
            )
        else:
            conn.execute(
                "INSERT INTO analysis_jobs (id, status, created_at, updated_at, summary_json) "
                "VALUES (?,?,?,?,?)",
                (job_id, status, now, now, summary_str),
            )
        conn.commit()
