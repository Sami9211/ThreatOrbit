"""External audit sink: ship each audit event to an off-box, tamper-evident
store (the customer's SIEM, or append-only/object-lock storage).

The in-DB `audit_log` is the system of record but lives in the same database an
attacker who got in might alter. Streaming a copy to an external endpoint gives
the tamper-evidence a security review asks for (SOC 2 CC7.x / log integrity).

Delivery is fire-and-forget on a single background worker so the request path is
never blocked, optionally HMAC-signed (same scheme as outbound webhooks). It's a
copy-on-write stream: events are shipped as `audit()` writes them, so it is
at-least-once and — in the rare case an audited action's transaction later rolls
back — may include an attempt that didn't persist. Unset URL = complete no-op.
"""
import logging
import queue
import threading

logger = logging.getLogger("dashboard_api.audit_sink")

# Tests flip this True to ship inline (no worker thread / timing).
SYNC_SHIP = False

_queue: "queue.Queue[dict]" = queue.Queue(maxsize=10000)
_worker_started = False
_lock = threading.Lock()
_TIMEOUT = 5.0


def _url() -> str:
    from dashboard_api import config
    return getattr(config, "AUDIT_SINK_URL", "")


def _secret() -> str:
    from dashboard_api import config
    return getattr(config, "AUDIT_SINK_SECRET", "")


def enabled() -> bool:
    return bool(_url())


def _post(event: dict) -> bool:
    import json

    import httpx

    from dashboard_api.webhooks import sign_payload
    body = json.dumps(event, separators=(",", ":"), default=str).encode()
    headers = {"Content-Type": "application/json", "X-ThreatOrbit-Event": "audit.event"}
    secret = _secret()
    if secret:
        headers["X-ThreatOrbit-Signature"] = sign_payload(secret, body)
    try:
        r = httpx.post(_url(), content=body, headers=headers, timeout=_TIMEOUT)
        return r.status_code < 400
    except httpx.HTTPError:
        logger.warning("Audit sink delivery failed")
        return False


def _worker():
    while True:
        event = _queue.get()
        try:
            _post(event)
        except Exception:  # a sink hiccup must never kill the worker
            logger.exception("Audit sink worker error")


def _ensure_worker():
    global _worker_started
    with _lock:
        if not _worker_started:
            threading.Thread(target=_worker, daemon=True, name="audit-sink").start()
            _worker_started = True


def ship(event: dict) -> None:
    """Hand an audit event to the external sink. No-op when unconfigured; never
    raises into the caller (a telemetry failure must not fail the request)."""
    if not enabled():
        return
    try:
        if SYNC_SHIP:
            _post(event)
        else:
            _ensure_worker()
            _queue.put_nowait(event)
    except queue.Full:
        logger.warning("Audit sink queue full; dropping event")
    except Exception:
        logger.exception("Audit sink enqueue error")
