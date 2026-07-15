"""Server-Sent Events endpoint - real-time push to the dashboard.

`GET /stream?ticket=<t>` opens a `text/event-stream`. The browser's EventSource
can't set an Authorization header, so instead of putting the long-lived session
JWT in the URL, the client first POSTs to `/stream/ticket` (with its normal
Authorization header) to mint a short-lived, single-use ticket and passes THAT
in the query string (audit B3). Each producer (engine tick, notify(), webhook
dispatch) publishes to the in-process broker; this endpoint relays those
messages as SSE so alerts/cases/findings/notifications appear without polling.
"""
import asyncio
import json
import queue
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from dashboard_api.auth import (
    create_stream_ticket, current_user, decode_stream_ticket, decode_token,
)
from dashboard_api.db import get_conn
from dashboard_api.events_stream import publish, subscribe, unsubscribe

router = APIRouter(tags=["stream"])

_HEARTBEAT_SECONDS = 20

# Single-use enforcement for stream tickets (consumed `jti` -> expiry epoch).
# The SSE broker is already in-process, so an in-process set is consistent with
# the stream's single-worker affinity.
_consumed_tickets: dict[str, float] = {}
_consumed_lock = threading.Lock()


def _consume_ticket(jti: str, exp: float) -> bool:
    """Return True the FIRST time a jti is seen, False on reuse. Prunes expired
    entries so the set can't grow unbounded."""
    now = time.time()
    with _consumed_lock:
        for k in [k for k, e in _consumed_tickets.items() if e < now]:
            _consumed_tickets.pop(k, None)
        if not jti or jti in _consumed_tickets:
            return False
        _consumed_tickets[jti] = exp
        return True


def _principal_for_user(uid: str) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT id, status, org_id FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="user no longer exists")
    if row["status"] == "disabled":
        raise HTTPException(status_code=403, detail="account disabled")
    from dashboard_api.tenancy import org_of
    return {"id": row["id"], "org_id": org_of({"org_id": row["org_id"]})}


def _validate(ticket: str, token: str) -> dict:
    """Resolve the SSE principal. Preferred: a short-lived, single-use stream
    `ticket` (so the long-lived JWT never lands in the URL / proxy logs, audit
    B3). A raw `token` is still accepted for backward compatibility but
    deprecated."""
    if ticket:
        try:
            payload = decode_stream_ticket(ticket)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="invalid stream ticket")
        if not _consume_ticket(payload.get("jti", ""), float(payload.get("exp", 0))):
            raise HTTPException(status_code=401, detail="stream ticket already used or expired")
        return _principal_for_user(payload.get("sub"))
    if token:
        try:
            payload = decode_token(token)
        except Exception:
            raise HTTPException(status_code=401, detail="invalid token")
        if payload.get("typ") == "stream":
            raise HTTPException(status_code=401, detail="use the ticket query parameter")
        return _principal_for_user(payload.get("sub"))
    raise HTTPException(status_code=401, detail="ticket query parameter required")


@router.post("/stream/ticket")
def issue_stream_ticket(user: dict = Depends(current_user)):
    """Mint a short-lived, single-use SSE ticket for the authenticated caller.
    The browser fetches this with its normal Authorization header, then opens
    `GET /stream?ticket=…` - so the session JWT is never put in a URL."""
    return {"ticket": create_stream_ticket(user["id"]), "expires_in": 60}


@router.get("/stream")
async def event_stream(request: Request, ticket: str = Query(""), token: str = Query("")):
    """Stream live platform events to the authenticated browser via SSE."""
    principal = _validate(ticket, token)
    q = subscribe(principal["org_id"])

    async def gen():
        # Comment line opens the stream; `retry` tells EventSource the backoff.
        yield "retry: 3000\n: connected\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.to_thread(q.get, True, _HEARTBEAT_SECONDS)
                except queue.Empty:
                    yield ": keepalive\n\n"   # heartbeat keeps proxies from closing
                    continue
                yield f"event: {msg['type']}\ndata: {json.dumps(msg['data'])}\n\n"
        finally:
            unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",   # disable nginx buffering for SSE
    })


@router.get("/stream/health")
def stream_health():
    """Lightweight liveness probe for the stream broker (subscriber count)."""
    from dashboard_api.events_stream import subscriber_count
    return {"subscribers": subscriber_count()}


# Re-export so other modules can `from dashboard_api.routers.stream import publish`.
__all__ = ["router", "publish"]
