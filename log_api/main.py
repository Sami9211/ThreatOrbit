import asyncio
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Security, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from starlette.exceptions import HTTPException as StarletteHTTPException

from log_api.config import ADMIN_API_KEY, CORS_ORIGINS, SUPPORTED_FORMATS, USER_API_KEY
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
from log_api.reporter.report import _build_html
from log_api.stix_from_findings import findings_to_stix_bundle
from log_api.metrics import LogMetrics
from log_api.db import init_db, get_conn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure the schema exists. Migrated off the deprecated
    # @app.on_event("startup") hook; no shutdown work today.
    init_db()
    yield


app = FastAPI(title="Log Anomaly API", version="1.2.0", lifespan=lifespan)

_cors_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
# A wildcard origin with credentials is invalid per the CORS spec (browsers
# reject it) and unsafe; if one is configured, drop credentials so the policy is
# valid and explicit rather than silently broken. Mirrors dashboard_api's stance.
_cors_credentials = "*" not in _cors_origins
if not _cors_credentials:
    logger.warning("CORS_ORIGINS is '*'; disabling allow_credentials. Set explicit origins in production.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

metrics = LogMetrics()

# Hard cap on an uploaded log file (anti-DoS); override via env if needed.
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))  # 50 MB

# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _key_matches(provided: str, *valid: str) -> bool:
    """Constant-time API-key check (mirrors threat_api/dashboard_api) so the
    comparison isn't a timing side channel."""
    return any(provided and v and hmac.compare_digest(provided, v) for v in valid)


def require_user_key(api_key: str = Security(_api_key_header)):
    """Standard analyst access: accepts USER key or ADMIN key."""
    if not _key_matches(api_key, USER_API_KEY, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


def require_admin_key(api_key: str = Security(_api_key_header)):
    """Admin-only access: only the ADMIN key is accepted."""
    if not _key_matches(api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Admin access required")


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
    # Log the detail server-side with a correlation id; return only the id to the
    # caller so internal paths/dependency errors aren't disclosed.
    rid = uuid.uuid4().hex[:12]
    logger.exception("Unhandled exception [%s] on %s %s", rid, request.method, request.url.path)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "id": rid})


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

# Startup moved to the `lifespan` handler above (FastAPI on_event is deprecated).


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
    except Exception:
        logger.exception("readiness check failed")
        return {"ready": False}


@app.get("/metrics")
def get_metrics():
    return metrics.to_dict()


@app.get("/trends/severity", dependencies=[Depends(require_user_key)])
def severity_trends():
    # Aggregated from persisted job summaries so it's correct across workers and
    # survives restarts (not the serving worker's in-memory slice).
    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    n = 0
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT summary_json FROM analysis_jobs WHERE status='completed'").fetchall()
    for (summary_json,) in rows:
        if not summary_json:
            continue
        n += 1
        try:
            for k, v in json.loads(summary_json).items():
                buckets[k] = buckets.get(k, 0) + v
        except Exception:
            pass
    return {"total_analyses": n, "severity_totals": buckets}


@app.get("/")
def root():
    return {"service": "Log Anomaly API", "status": "running",
            "supported_formats": SUPPORTED_FORMATS}


# ---------------------------------------------------------------------------
# Core analysis endpoint
# ---------------------------------------------------------------------------

@app.post("/analyse", dependencies=[Depends(require_user_key)])
async def analyse(
    file: UploadFile = File(...),
    log_format: LogFormat = Query(LogFormat.APACHE),
    generate_report: bool = Query(True),
    run_async: bool = Query(False, alias="async"),
):
    # Bound memory at ingress: read at most MAX_UPLOAD_BYTES+1 and reject if
    # exceeded, BEFORE decoding/splitting - so a multi-GB upload (or one enormous
    # line with no newlines) can't exhaust memory. (Was: read the whole file,
    # then check the line count.)
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
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
        _persist_result(job_id, result, generate_report)
        _save_job(job_id, "completed", result.summary)
        metrics.mark_success(len(result.findings))
        return result
    except Exception:
        rid = uuid.uuid4().hex[:12]
        logger.exception("analysis failed [%s] for job %s", rid, job_id)
        _save_job(job_id, "failed", {"error": "analysis failed"})
        metrics.mark_failure()
        raise HTTPException(status_code=500, detail=f"Analysis failed (id={rid})")


async def _analyse_background(job_id: str, lines: list, log_format: str, generate_report: bool):
    try:
        result = await asyncio.to_thread(_run_analysis, lines, log_format, generate_report)
        _persist_result(job_id, result, generate_report)
        _save_job(job_id, "completed", result.summary)
        metrics.mark_success(len(result.findings))
    except Exception:
        _save_job(job_id, "failed", {"error": "analysis failed"})
        metrics.mark_failure()
        logger.exception("Background analysis failed for job %s", job_id)


# ---------------------------------------------------------------------------
# Job / result endpoints
# ---------------------------------------------------------------------------

@app.get("/jobs/{job_id}", dependencies=[Depends(require_user_key)])
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

    if row[1] == "completed":
        resp["result_url"] = f"/results/{row[0]}"
        resp["report_url"] = f"/results/{row[0]}/report"

    return resp


@app.get("/report", response_class=HTMLResponse, dependencies=[Depends(require_user_key)])
def report():
    """The most recently completed analysis's report. Prefer the per-job
    /results/{id}/report - this 'latest' view is kept for backward compatibility."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT report_html FROM analysis_jobs WHERE status='completed' AND report_html IS NOT NULL "
            "ORDER BY updated_at DESC LIMIT 1").fetchone()
    if not row or not row[0]:
        raise HTTPException(status_code=404, detail="No report generated yet.")
    return HTMLResponse(content=row[0])


@app.get("/results/{result_id}", dependencies=[Depends(require_user_key)])
def get_result(result_id: str):
    result = _load_result(result_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return result


@app.get("/results/{result_id}/report", response_class=HTMLResponse,
         dependencies=[Depends(require_user_key)])
def get_result_report(result_id: str):
    """The report for ONE analysis (rendered from its stored result) - no shared
    file, so concurrent analyses never overwrite each other's report."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT report_html FROM analysis_jobs WHERE id=?", (result_id,)).fetchone()
    if not row or not row[0]:
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(content=row[0])


@app.get("/results/{result_id}/stix", dependencies=[Depends(require_user_key)])
def export_result_stix(result_id: str):
    result = _load_result(result_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    bundle = findings_to_stix_bundle(result)
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
    return result   # report is rendered + persisted per-job by _persist_result


def _persist_result(job_id: str, result: AnalysisResult, generate_report: bool):
    """Store the full result (+ a per-job rendered report) on the job row, so it
    survives restarts and is readable by any worker. Replaces the in-memory dict
    and the single shared report file."""
    report_html = _build_html(result) if generate_report else None
    with get_conn() as conn:
        conn.execute(
            "UPDATE analysis_jobs SET result_json=?, report_html=? WHERE id=?",
            (result.model_dump_json(), report_html, job_id))
        conn.commit()


def _load_result(job_id: str):
    """Reconstruct a stored AnalysisResult, or None if absent."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT result_json FROM analysis_jobs WHERE id=?", (job_id,)).fetchone()
    if not row or not row[0]:
        return None
    try:
        return AnalysisResult.model_validate_json(row[0])
    except Exception:
        logger.exception("failed to parse stored result for %s", job_id)
        return None


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
