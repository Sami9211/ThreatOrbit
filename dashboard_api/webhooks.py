"""Webhook delivery: fire registered endpoints when platform events occur.

Dispatch is fire-and-forget on a daemon thread so request latency never
depends on a subscriber's endpoint. Each delivery POSTs a JSON envelope
{event, ts, data} with a short timeout; success stamps last_delivery, a
failed delivery marks the webhook `failing` (it keeps receiving future
events until paused or deleted, so transient outages self-heal).
"""
import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone

import httpx

from dashboard_api.db import get_conn

logger = logging.getLogger("dashboard_api.webhooks")

_TIMEOUT = 5.0
_SIG_HEADER = "X-ThreatOrbit-Signature"
_ID_HEADER = "X-ThreatOrbit-Delivery"
_EVENT_HEADER = "X-ThreatOrbit-Event"


def new_webhook_secret() -> str:
    """A signing secret an integrator stores to verify deliveries (shown once)."""
    return "whsec_" + uuid.uuid4().hex + uuid.uuid4().hex


def sign_payload(secret: str, body: bytes, ts: int | None = None) -> str:
    """Build the `X-ThreatOrbit-Signature: t=<unix>,v1=<hex>` header value.
    Same scheme as the inbound Stripe verifier (billing.verify_webhook): the
    HMAC-SHA256 is taken over `"<t>.<body>"` so a captured delivery can't be
    replayed with a different timestamp."""
    ts = int(time.time()) if ts is None else ts
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify_signature(secret: str, body: bytes, sig_header: str, *, tolerance: int = 300) -> bool:
    """Reference verifier for subscribers (and our tests): True iff the header
    is a valid, in-tolerance signature of `body` under `secret`."""
    if not (secret and sig_header):
        return False
    parts = [p.split("=", 1) for p in sig_header.split(",") if "=" in p]
    ts = next((v for k, v in parts if k == "t"), None)
    sigs = [v for k, v in parts if k == "v1"]
    if not ts or not sigs:
        return False
    try:
        if tolerance and abs(time.time() - int(ts)) > tolerance:
            return False
    except ValueError:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)

# Tests flip this to True to deliver inline instead of on a thread.
SYNC_DELIVERY = False


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _subscribers(event: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, url, events, secret FROM webhooks WHERE status != 'paused'"
        ).fetchall()
    subs = []
    for r in rows:
        try:
            events = json.loads(r["events"] or "[]")
        except (ValueError, TypeError):
            events = []
        if event in events:
            subs.append({"id": r["id"], "url": r["url"], "secret": r["secret"]})
    return subs


# Delivery is retried on transient failure with exponential backoff. The
# idempotency id + signature are computed once and reused across attempts, so a
# subscriber sees the SAME delivery on every retry and can dedupe it. Backoff
# sleeps are skipped under SYNC_DELIVERY (tests) so the suite stays fast.
_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 1.0   # seconds; doubles each retry (1s, 2s)


def _post_with_retry(url: str, body: bytes, headers: dict) -> bool:
    for attempt in range(_MAX_ATTEMPTS):
        try:
            r = httpx.post(url, content=body, headers=headers, timeout=_TIMEOUT)
            if r.status_code < 400:
                return True
        except httpx.HTTPError:
            pass
        if attempt < _MAX_ATTEMPTS - 1 and not SYNC_DELIVERY:
            time.sleep(_BACKOFF_BASE * (2 ** attempt))
    return False


def _deliver(event: str, payload: dict, subs: list[dict]):
    envelope = {"event": event, "ts": _now(), "data": payload}
    # Sign the EXACT bytes we send (compact, stable separators), so a subscriber
    # recomputes the HMAC over the same body it received.
    body = json.dumps(envelope, separators=(",", ":")).encode()
    for sub in subs:
        headers = {
            "Content-Type": "application/json",
            _EVENT_HEADER: event,
            _ID_HEADER: str(uuid.uuid4()),          # idempotency key (stable across retries)
        }
        if sub.get("secret"):
            headers[_SIG_HEADER] = sign_payload(sub["secret"], body)
        ok = _post_with_retry(sub["url"], body, headers)
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


# ── Per-user Slack routing ────────────────────────────────────────────────────────
# Users register a personal Slack incoming-webhook URL (+ a minimum severity);
# every platform notification at-or-above that severity is mirrored to it.

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def deliver_slack(url: str, text: str) -> bool:
    """POST a Slack-format message ({"text": ...}); True on 2xx/3xx."""
    try:
        r = httpx.post(url, json={"text": text}, timeout=_TIMEOUT)
        return r.status_code < 400
    except httpx.HTTPError:
        return False


def notify_slack_users(*, severity: str, title: str,
                       detail: str | None = None, link: str | None = None):
    """Fan a platform notification out to every active user whose personal
    Slack webhook is configured and whose threshold the severity meets.
    Fire-and-forget (same model as dispatch); never raises."""
    def _fan():
        try:
            with get_conn() as conn:
                rows = conn.execute(
                    "SELECT email, slack_webhook, slack_min_severity FROM users "
                    "WHERE slack_webhook IS NOT NULL AND slack_webhook != '' "
                    "AND status='active'"
                ).fetchall()
        except Exception:
            logger.exception("Slack subscriber lookup failed")
            return
        rank = _SEV_RANK.get(severity, 0)
        text = f"*[{severity.upper()}] {title}*"
        if detail:
            text += f"\n{detail}"
        if link:
            text += f"\n{link}"
        from dashboard_api.secretstore import decrypt
        for r in rows:
            if rank >= _SEV_RANK.get(r["slack_min_severity"] or "high", 3):
                url = decrypt(r["slack_webhook"])
                if url and not deliver_slack(url, text):
                    logger.warning("Slack notification delivery failed for %s", r["email"])

    if SYNC_DELIVERY:
        _fan()
    else:
        threading.Thread(target=_fan, daemon=True).start()


def dispatch(event: str, payload: dict):
    """Deliver `event` to every active subscriber. Never raises."""
    # Mirror to live SSE clients (in-process, independent of external webhooks).
    try:
        from dashboard_api.events_stream import publish
        publish(event, payload)
    except Exception:
        pass
    try:
        subs = _subscribers(event)
    except Exception:  # storage unavailable - never break the request path
        logger.exception("Webhook subscriber lookup failed for %s", event)
        return
    if not subs:
        return
    if SYNC_DELIVERY:
        _deliver(event, payload, subs)
    else:
        threading.Thread(target=_deliver, args=(event, payload, subs), daemon=True).start()
