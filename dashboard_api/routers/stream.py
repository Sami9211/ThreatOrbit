"""Server-Sent Events endpoint - real-time push to the dashboard.

`GET /stream?token=<jwt>` opens a `text/event-stream`. The browser's
EventSource can't set an Authorization header, so the JWT is passed as a query
parameter and validated here. Each producer (engine tick, notify(), webhook
dispatch) publishes to the in-process broker; this endpoint relays those
messages as SSE so alerts/cases/findings/notifications appear without polling.
"""
import asyncio
import json
import queue

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from dashboard_api.auth import decode_token
from dashboard_api.db import get_conn
from dashboard_api.events_stream import publish, subscribe, unsubscribe

router = APIRouter(tags=["stream"])

_HEARTBEAT_SECONDS = 20


def _validate(token: str) -> dict:
    if not token:
        raise HTTPException(status_code=401, detail="token query parameter required")
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    with get_conn() as conn:
        row = conn.execute("SELECT id, status, org_id FROM users WHERE id=?", (payload.get("sub"),)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="user no longer exists")
    if row["status"] == "disabled":
        raise HTTPException(status_code=403, detail="account disabled")
    from dashboard_api.tenancy import org_of
    return {"id": row["id"], "org_id": org_of({"org_id": row["org_id"]})}


@router.get("/stream")
async def event_stream(request: Request, token: str = Query("")):
    """Stream live platform events to the authenticated browser via SSE."""
    principal = _validate(token)
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
