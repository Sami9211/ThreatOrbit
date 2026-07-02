"""External audit sink: ship each audit event to an off-box, tamper-evident
store (the customer's SIEM, or append-only/object-lock storage).

The in-DB `audit_log` is the system of record but lives in the same database an
attacker who got in might alter. Streaming a copy to an external endpoint gives
the tamper-evidence a security review asks for (SOC 2 CC7.x / log integrity).

Delivery is an **outbox drain** with a persisted cursor: the committed
`audit_log` table IS the durable queue, and `audit_sink_cursor` records the
last row id successfully delivered. The background worker drains rows beyond
the cursor in id order and only advances the cursor on success, so a sink
outage or a process restart replays the undelivered tail instead of losing it
— at-least-once, in order (consumers can dedupe on the event `id`). `ship()`
is a wake-up nudge, not the data path; a periodic poll catches events whose
transaction committed after the nudge, plus anything left over from before a
restart. Only committed rows are shipped, so a rolled-back action is never
mirrored. Multi-replica deployments elect one drainer via the shared DB lease
(`leader.acquire("audit-sink")`); a failover overlap can re-deliver, never
drop. Requests are optionally HMAC-signed (same scheme as outbound webhooks).
Unset URL = complete no-op.
"""
import logging
import threading

logger = logging.getLogger("dashboard_api.audit_sink")

# Tests flip this True to ship inline (no worker thread / timing): ship()
# posts the passed event directly, bypassing the outbox.
SYNC_SHIP = False

_wake = threading.Event()
_worker_started = False
_lock = threading.Lock()
_TIMEOUT = 5.0
_BATCH = 200            # max rows drained per pass
_POLL_SECONDS = 5.0     # catch-all tick (post-commit races, restart replay)
_BACKOFF_MAX = 60.0     # cap between retries while the sink is down
_LEASE = "audit-sink"   # one drainer across replicas (DB-backed lease)


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


# ── Outbox cursor ─────────────────────────────────────────────────────────────

def _get_cursor(conn) -> int:
    row = conn.execute("SELECT last_id FROM audit_sink_cursor WHERE id=1").fetchone()
    return int(row["last_id"]) if row else 0


def _set_cursor(conn, last_id: int) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    conn.execute(
        "INSERT INTO audit_sink_cursor (id, last_id, updated) VALUES (1,?,?) "
        "ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id, updated=excluded.updated",
        (last_id, now))
    conn.commit()


def drain_once() -> dict:
    """One drain pass: deliver committed audit rows beyond the cursor, in id
    order, advancing the cursor only through contiguous successes. Returns a
    summary; safe to call from anywhere (used by the worker and by tests)."""
    from dashboard_api.db import get_conn
    delivered = 0
    if not enabled():
        return {"delivered": 0, "pending": 0}
    with get_conn() as conn:
        cursor = _get_cursor(conn)
        rows = conn.execute(
            "SELECT id, ts, actor, action, target, detail FROM audit_log "
            "WHERE id > ? ORDER BY id LIMIT ?", (cursor, _BATCH)).fetchall()
        last_ok = cursor
        ok = True
        for r in rows:
            if not _post({"id": r["id"], "ts": r["ts"], "actor": r["actor"],
                          "action": r["action"], "target": r["target"],
                          "detail": r["detail"]}):
                ok = False
                break   # keep order: stop at the first failure, retry it next pass
            last_ok = r["id"]
            delivered += 1
        if last_ok != cursor:
            _set_cursor(conn, last_ok)
        pending = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE id > ?", (last_ok,)).fetchone()["n"]
    return {"delivered": delivered, "pending": pending, "ok": ok}


def _worker():
    consecutive_failures = 0
    while True:
        wait = min(2.0 ** consecutive_failures, _BACKOFF_MAX) if consecutive_failures \
            else _POLL_SECONDS
        _wake.wait(timeout=wait)
        _wake.clear()
        if not enabled():
            continue
        try:
            from dashboard_api import leader
            if not leader.acquire(_LEASE):
                continue   # another replica is draining; we replay if it dies
            out = drain_once()
            consecutive_failures = 0 if out.get("ok", True) else consecutive_failures + 1
        except Exception:  # a sink hiccup must never kill the worker
            logger.exception("Audit sink worker error")
            consecutive_failures += 1


def _ensure_worker():
    global _worker_started
    with _lock:
        if not _worker_started:
            threading.Thread(target=_worker, daemon=True, name="audit-sink").start()
            _worker_started = True


def ship(event: dict) -> None:
    """Nudge the sink about a new audit event. The event itself is already in
    `audit_log` (the outbox); delivery happens off the committed row, so this
    is a wake-up only. No-op when unconfigured; never raises into the caller
    (a telemetry failure must not fail the request)."""
    if not enabled():
        return
    try:
        if SYNC_SHIP:
            _post(event)   # test mode: inline, no worker/timing
        else:
            _ensure_worker()
            _wake.set()
    except Exception:
        logger.exception("Audit sink nudge error")
