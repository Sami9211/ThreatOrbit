"""Configuration routes: platform settings, API keys."""
import hashlib
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_role
from dashboard_api.db import get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/config", tags=["config"])


class SettingsUpdate(BaseModel):
    values: dict


class ApiKeyCreate(BaseModel):
    name: str
    scope: str = "read"


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@router.get("/settings")
def get_settings(_: dict = Depends(current_user)):
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


@router.put("/settings")
def update_settings(body: SettingsUpdate, _: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        for k, v in body.values.items():
            conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (k, str(v)))
        conn.commit()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


@router.get("/api-keys")
def list_api_keys(_: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id,name,prefix,scope,last_used,created_at,created_by,revoked "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, user: dict = Depends(require_role("admin", "manager"))):
    if body.scope not in ("read", "write", "admin"):
        raise HTTPException(status_code=400, detail="scope must be read|write|admin")
    prefix = {"admin": "to_ak_live_", "write": "to_sk_live_", "read": "to_rk_live_"}[body.scope]
    secret = prefix + os.urandom(18).hex()
    kid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO api_keys (id,name,prefix,secret_hash,scope,last_used,created_at,created_by,revoked) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (kid, body.name, prefix, hashlib.sha256(secret.encode()).hexdigest(),
             body.scope, None, _now(), user["email"], 0),
        )
        conn.commit()
    # Secret is returned exactly once, at creation.
    return {"id": kid, "name": body.name, "scope": body.scope, "secret": secret}


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(key_id: str, _: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        cur = conn.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="API key not found")
        conn.commit()
    return None
