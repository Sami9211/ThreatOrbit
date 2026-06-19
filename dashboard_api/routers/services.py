"""Companion-service bridge: proxy the Threat API and Log API into the dashboard.

The two ingestion services authenticate with X-API-Key headers that must not
reach the browser, so the dashboard proxies them server-side: the operator
stays on JWT auth, keys stay in the environment. Every upstream call degrades
gracefully - when a service is down the caller gets {"available": false}
(or 503 for actions) rather than an opaque error.
"""
import json
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile

from dashboard_api.auth import current_user, require_perm
from dashboard_api.config import (
    LOG_API_URL, SERVICES_ADMIN_KEY, SERVICES_API_KEY, THREAT_API_URL,
)
from dashboard_api.db import audit, dumps, get_conn, record_job

router = APIRouter(prefix="/services", tags=["services"], dependencies=[Depends(current_user)])

_TIMEOUT = 8.0


def _headers(admin: bool = False) -> dict:
    key = SERVICES_ADMIN_KEY if admin else SERVICES_API_KEY
    return {"X-API-Key": key} if key else {}


def _get(base: str, path: str, admin: bool = False, params: dict | None = None):
    """GET an upstream service; returns parsed JSON or None when unreachable."""
    try:
        r = httpx.get(f"{base}{path}", headers=_headers(admin), params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return None


def _service_state(base: str) -> dict:
    health = _get(base, "/health")
    return {"url": base, "available": health is not None, "health": health}


@router.get("/status")
def services_status():
    """Reachability + key configuration for both companion services."""
    return {
        "threatApi": _service_state(THREAT_API_URL),
        "logApi": _service_state(LOG_API_URL),
        "keyConfigured": bool(SERVICES_API_KEY),
    }


# ── Threat API (ingestion engine) ─────────────────────────────────────────────

@router.get("/threat/source-health")
def threat_source_health():
    data = _get(THREAT_API_URL, "/source-health")
    if data is None:
        return {"available": False, "sources": []}
    return {"available": True, "sources": data}


@router.get("/threat/iocs")
def threat_iocs(limit: int = Query(50, le=1000)):
    data = _get(THREAT_API_URL, "/iocs", params={"limit": max(1, min(limit, 500))})
    if data is None:
        return {"available": False, "items": []}
    return {"available": True, "items": data}


@router.post("/threat/fetch")
def threat_fetch(user: dict = Depends(require_perm("services.run"))):
    """Trigger an ingestion run on the Threat API. Returns the upstream job id."""
    try:
        r = httpx.post(f"{THREAT_API_URL}/fetch", headers=_headers(admin=True), timeout=_TIMEOUT)
        r.raise_for_status()
        body = r.json()
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Threat API is unreachable - start it on " + THREAT_API_URL)
    with get_conn() as conn:
        audit(conn, user["email"], "services.threat_fetch", body.get("job_id"))
        conn.commit()
    return body


@router.get("/threat/jobs/{job_id}")
def threat_job(job_id: str):
    data = _get(THREAT_API_URL, f"/jobs/{job_id}")
    if data is None:
        raise HTTPException(status_code=503, detail="Threat API is unreachable")
    return data


@router.get("/threat/opencti-status")
def opencti_status():
    data = _get(THREAT_API_URL, "/opencti/status")
    if data is None:
        return {"available": False}
    return {"available": True, **data}


# Threat-API indicator types → dashboard IOC store types.
_TYPE_MAP = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash",
             "md5": "hash", "sha1": "hash", "sha256": "hash", "email": "email"}


@router.post("/threat/sync-iocs")
def sync_threat_iocs(limit: int = Query(500, le=10000), user: dict = Depends(require_perm("services.run"))):
    """Pull indicators from the Threat API ingestion store into the dashboard
    CTI IOC store (deduplicated by value). This is the live bridge between the
    OSINT engine and the operator console."""
    upstream = _get(THREAT_API_URL, "/iocs", params={"limit": max(1, min(limit, 1000))})
    if upstream is None:
        raise HTTPException(status_code=503, detail="Threat API is unreachable - start it on " + THREAT_API_URL)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    imported = duplicates = skipped = 0
    with get_conn() as conn:
        for item in upstream:
            value = (item.get("value") or "").strip()
            itype = _TYPE_MAP.get((item.get("ioc_type") or "").lower())
            if not value or itype is None:
                skipped += 1
                continue
            if conn.execute("SELECT 1 FROM iocs WHERE value=?", (value,)).fetchone():
                duplicates += 1
                continue
            confidence = max(0, min(100, int(item.get("confidence") or 50)))
            severity = "critical" if confidence >= 85 else "high" if confidence >= 70 \
                else "medium" if confidence >= 40 else "low"
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), itype, value,
                 item.get("threat_type") or "malicious-activity", confidence, severity,
                 f"threat-api:{item.get('source') or 'osint'}", item.get("malware_family") or "",
                 item.get("first_seen") or now, item.get("last_seen") or now,
                 dumps(list(item.get("tags") or []))),
            )
            imported += 1
        audit(conn, user["email"], "services.sync_iocs", None,
              f"imported={imported} duplicates={duplicates} skipped={skipped}")
        record_job(conn, "threat.sync_iocs", "completed",
                   {"imported": imported, "duplicates": duplicates, "skipped": skipped,
                    "actor": user["email"]})
        conn.commit()
    if imported:
        from dashboard_api.webhooks import dispatch
        dispatch("ioc.confirmed", {"imported": imported, "source": "threat-api-sync",
                                   "importedBy": user["email"]})
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(upstream)}


# ── Log API (anomaly analysis) ────────────────────────────────────────────────

_LOG_FORMATS = {"syslog", "apache", "windows_event", "generic"}


@router.post("/logs/analyse")
async def logs_analyse(
    file: UploadFile = File(...),
    log_format: str = Form("generic"),
    create_alerts: bool = Form(True),
    user: dict = Depends(current_user),
):
    """Forward a log file to the Log API for anomaly analysis. By default each
    finding is also persisted as a real SIEM alert (the live detection pipeline)."""
    if log_format not in _LOG_FORMATS:
        raise HTTPException(status_code=400, detail=f"log_format must be one of {sorted(_LOG_FORMATS)}")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(content) > 16 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 16 MB)")
    try:
        r = httpx.post(
            f"{LOG_API_URL}/analyse",
            headers=_headers(),
            params={"log_format": log_format},
            files={"file": (file.filename or "upload.log", content, "text/plain")},
            timeout=60.0,
        )
        r.raise_for_status()
        body = r.json()
    except httpx.HTTPStatusError as e:
        detail = "Log API rejected the file"
        try:
            detail = e.response.json().get("detail", detail)
        except (json.JSONDecodeError, ValueError):
            pass
        raise HTTPException(status_code=e.response.status_code, detail=detail)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Log API is unreachable - start it on " + LOG_API_URL)

    findings = body.get("findings", []) if isinstance(body, dict) else []
    alerts_created = 0
    if create_alerts and findings:
        from dashboard_api.detections import alerts_from_log_findings
        alerts_created = alerts_from_log_findings(findings, file.filename or "upload.log", user["email"])
    with get_conn() as conn:
        audit(conn, user["email"], "services.log_analyse", file.filename,
              f"format={log_format} bytes={len(content)} alerts={alerts_created}")
        record_job(conn, "logs.analyse", "completed",
                   {"file": file.filename, "format": log_format,
                    "findings": len(findings), "alertsCreated": alerts_created,
                    "actor": user["email"]})
        conn.commit()
    if isinstance(body, dict):
        body["alertsCreated"] = alerts_created
    return body


@router.get("/logs/results/{result_id}")
def logs_result(result_id: str):
    data = _get(LOG_API_URL, f"/results/{result_id}")
    if data is None:
        raise HTTPException(status_code=503, detail="Log API is unreachable")
    return data


@router.get("/logs/trends")
def logs_trends():
    data = _get(LOG_API_URL, "/trends/severity")
    if data is None:
        return {"available": False}
    return {"available": True, **data}
