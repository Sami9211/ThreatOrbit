"""Webhook delivery: fire registered endpoints when platform events occur.

Dispatch is fire-and-forget on a daemon thread so request latency never
depends on a subscriber's endpoint. Each delivery POSTs a JSON envelope
{event, ts, data} with a short timeout; success stamps last_delivery, a
failed delivery marks the webhook `failing` (it keeps receiving future
events until paused or deleted, so transient outages self-heal).
"""
import json
import logging
import threading
from datetime import datetime, timezone

import httpx

from dashboard_api.db import get_conn

logger = logging.getLogger("dashboard_api.webhooks")

_TIMEOUT = 5.0

# Tests flip this to True to deliver inline instead of on a thread.
SYNC_DELIVERY = False


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _subscribers(event: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, url, events FROM webhooks WHERE status != 'paused'"
        ).fetchall()
    subs = []
    for r in rows:
        try:
            events = json.loads(r["events"] or "[]")
        except (ValueError, TypeError):
            events = []
        if event in events:
            subs.append({"id": r["id"], "url": r["url"]})
    return subs


def _deliver(event: str, payload: dict, subs: list[dict]):
    envelope = {"event": event, "ts": _now(), "data": payload}
    for sub in subs:
        ok = False
        try:
            r = httpx.post(sub["url"], json=envelope, timeout=_TIMEOUT)
            ok = r.status_code < 400
        except httpx.HTTPError:
            ok = False
        with get_conn() as conn:
            if ok:
                conn.execute(
                    "UPDATE webhooks SET last_delivery=?, status='active' WHERE id=?",
                    (_now(), sub["id"]),
                )
            else:
                conn.execute("UPDATE webhooks SET status='failing' WHERE id=?", (sub["id"],))
            conn.commit()
        if not ok:
            logger.warning("Webhook delivery failed: %s -> %s", event, sub["url"])


def dispatch(event: str, payload: dict):
    """Deliver `event` to every active subscriber. Never raises."""
    try:
        subs = _subscribers(event)
    except Exception:  # storage unavailable — never break the request path
        logger.exception("Webhook subscriber lookup failed for %s", event)
        return
    if not subs:
        return
    if SYNC_DELIVERY:
        _deliver(event, payload, subs)
    else:
        threading.Thread(target=_deliver, args=(event, payload, subs), daemon=True).start()
