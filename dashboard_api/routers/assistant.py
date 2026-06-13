"""Dashboard assistant routes - a security-bounded, read-only agent.

POST /assistant/chat runs one assistant turn as the authenticated user (see
dashboard_api/assistant.py for the security model). GET /assistant/status
reports whether the full AI backend is configured, honestly.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api import assistant
from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn

router = APIRouter(prefix="/assistant", tags=["assistant"], dependencies=[Depends(current_user)])


class ChatTurn(BaseModel):
    role: str
    text: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatTurn] = []


@router.get("/status")
def status(user: dict = Depends(current_user)):
    """Whether the full AI assistant is configured (an API key is set). When
    false, the assistant still answers from a deterministic command set."""
    return {"configured": assistant.configured(), "mode": "ai" if assistant.configured() else "basic",
            "capabilities": [s["name"] for s in assistant._TOOL_SCHEMAS]}


@router.post("/chat")
def chat(body: ChatRequest, user: dict = Depends(current_user)):
    if len(body.message or "") > 2000:
        raise HTTPException(status_code=400, detail="Message too long (max 2000 chars)")
    if assistant.rate_limited(user["email"]):
        raise HTTPException(status_code=429, detail="Too many messages - slow down a moment")
    history = [{"role": h.role, "text": h.text} for h in (body.history or [])]
    result = assistant.chat(user, body.message, history)
    # Audit who asked what (not the full reply) so assistant use is accountable.
    try:
        with get_conn() as conn:
            audit(conn, user["email"], "assistant.chat", None,
                  f"mode={result.get('mode')} tools={','.join(result.get('toolsUsed') or [])}")
            conn.commit()
    except Exception:
        pass
    return result
