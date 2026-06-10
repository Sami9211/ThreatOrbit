"""Configuration routes: platform settings, API keys."""
import hashlib
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_role
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/config", tags=["config"])


class SettingsUpdate(BaseModel):
    values: dict


class ApiKeyCreate(BaseModel):
    name: str
    scope: str = "read"


class WebhookCreate(BaseModel):
    url: str
    events: list[str] = ["alert.created"]


class WebhookUpdate(BaseModel):
    status: str | None = None
    events: list[str] | None = None


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@router.get("/settings")
def get_settings(_: dict = Depends(current_user)):
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


@router.put("/settings")
def update_settings(body: SettingsUpdate, actor: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        for k, v in body.values.items():
            conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (k, str(v)))
        audit(conn, actor["email"], "settings.update", None, f"keys={','.join(body.values.keys())}")
        conn.commit()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


@router.get("/api-keys")
def list_api_keys(user: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id,name,prefix,scope,last_used,created_at,created_by,revoked "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        # who-saw-what: viewing secrets metadata is sensitive, so it's audited.
        audit(conn, user["email"], "access.api_keys", None, f"count={len(rows)}")
        conn.commit()
    return rows_to_dicts(rows)


@router.get("/roles")
def list_roles(_: dict = Depends(require_role("admin", "manager"))):
    """The full RBAC matrix: every capability and which roles hold it."""
    from dashboard_api.permissions import CAPABILITIES, ROLE_PERMISSIONS
    return {
        "capabilities": CAPABILITIES,
        "roles": {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()},
    }


@router.post("/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, user: dict = Depends(require_role("admin", "manager"))):
    if body.scope not in ("read", "write", "admin"):
        raise HTTPException(status_code=400, detail="scope must be read|write|admin")
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Key name is required")
    scope_prefix = {"admin": "to_ak_live_", "write": "to_sk_live_", "read": "to_rk_live_"}[body.scope]
    secret = scope_prefix + os.urandom(18).hex()
    # `prefix` stores a non-sensitive display fragment (last 4 chars of the secret).
    display_fragment = secret[-4:]
    kid = str(uuid.uuid4())
    created_at = _now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO api_keys (id,name,prefix,secret_hash,scope,last_used,created_at,created_by,revoked) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (kid, name, display_fragment, hashlib.sha256(secret.encode()).hexdigest(),
             body.scope, None, created_at, user["email"], 0),
        )
        audit(conn, user["email"], "apikey.create", kid, f"name={name} scope={body.scope}")
        conn.commit()
    # Secret is returned exactly once, at creation.
    return {"id": kid, "name": name, "prefix": display_fragment, "scope": body.scope,
            "last_used": None, "created_at": created_at, "created_by": user["email"],
            "revoked": 0, "secret": secret}


class EngineControl(BaseModel):
    enabled: bool | None = None
    generate: int | None = None   # run N immediate ticks (seed a fresh install)


@router.get("/engine")
def engine_status(_: dict = Depends(current_user)):
    """Live processing engine state + how much live data it has produced."""
    from dashboard_api.config import DATA_MODE, ENGINE_TICK_SECONDS
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='engine_enabled'").fetchone()
        alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_id IN ('R-ENGINE','R-MANUAL')").fetchone()["n"]
        total_alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        dark = conn.execute("SELECT COUNT(*) AS n FROM dark_web_findings").fetchone()["n"]
    return {
        "mode": DATA_MODE,
        "running": DATA_MODE == "live" and (row is None or row["value"] != "false"),
        "enabled": (row is None or row["value"] != "false"),
        "tickSeconds": ENGINE_TICK_SECONDS,
        "alertsProduced": alerts, "totalAlerts": total_alerts, "darkWebFindings": dark,
    }


@router.post("/engine")
def engine_control(body: EngineControl, user: dict = Depends(require_role("admin", "manager"))):
    """Pause/resume the engine, or generate a burst of live data immediately."""
    result = {}
    if body.enabled is not None:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('engine_enabled',?)",
                         ("true" if body.enabled else "false",))
            audit(conn, user["email"], "engine.toggle", None, f"enabled={body.enabled}")
            conn.commit()
        result["enabled"] = body.enabled
    if body.generate:
        from dashboard_api.engine import process_tick
        ticks = max(1, min(body.generate, 30))
        agg = {"events": 0, "alerts": 0, "iocs": 0, "darkWeb": 0, "casesEscalated": 0}
        for _ in range(ticks):
            s = process_tick()
            for k in agg:
                agg[k] += s[k]
        with get_conn() as conn:
            audit(conn, user["email"], "engine.generate", None, f"ticks={ticks} alerts={agg['alerts']}")
            conn.commit()
        result["generated"] = agg
    return result


@router.get("/jobs")
def list_jobs(limit: int = 50, _: dict = Depends(require_role("admin", "manager"))):
    """Recent background jobs (IOC syncs, risk recomputes, log analyses)."""
    limit = max(1, min(limit, 200))
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/audit-log")
def list_audit_log(
    limit: int = 100,
    action: str | None = None,
    _: dict = Depends(require_role("admin", "manager")),
):
    limit = max(1, min(limit, 500))
    clause, params = "", []
    if action:
        clause = "WHERE action=?"; params.append(action)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT id, ts, actor, action, target, detail FROM audit_log "
            f"{clause} ORDER BY id DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return rows_to_dicts(rows)


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(key_id: str, actor: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        cur = conn.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="API key not found")
        audit(conn, actor["email"], "apikey.revoke", key_id)
        conn.commit()
    return None


# ── Webhooks ──────────────────────────────────────────────────────────────────

_WEBHOOK_EVENTS = {"alert.created", "incident.resolved", "ioc.confirmed", "case.created",
                   "playbook.failed", "playbook.completed", "playbook.action",
                   "darkweb.takedown"}


@router.get("/webhooks")
def list_webhooks(_: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
    return rows_to_dicts(rows)


@router.post("/webhooks", status_code=201)
def create_webhook(body: WebhookCreate, user: dict = Depends(require_role("admin", "manager"))):
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must start with http:// or https://")
    bad = [e for e in body.events if e not in _WEBHOOK_EVENTS]
    if bad or not body.events:
        raise HTTPException(status_code=400, detail=f"events must be a non-empty subset of {sorted(_WEBHOOK_EVENTS)}")
    wid = str(uuid.uuid4())
    from dashboard_api.db import dumps
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO webhooks (id,url,events,status,last_delivery,created_at,created_by) "
            "VALUES (?,?,?,'active',NULL,?,?)",
            (wid, url, dumps(body.events), _now(), user["email"]),
        )
        audit(conn, user["email"], "webhook.create", wid, f"url={url}")
        conn.commit()
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
    return row_to_dict(row)


@router.patch("/webhooks/{webhook_id}")
def update_webhook(webhook_id: str, body: WebhookUpdate, user: dict = Depends(require_role("admin", "manager"))):
    if body.status is not None and body.status not in ("active", "paused"):
        raise HTTPException(status_code=400, detail="status must be active or paused")
    fields, values = [], []
    if body.status is not None:
        fields.append("status=?"); values.append(body.status)
    if body.events is not None:
        bad = [e for e in body.events if e not in _WEBHOOK_EVENTS]
        if bad or not body.events:
            raise HTTPException(status_code=400, detail=f"events must be a non-empty subset of {sorted(_WEBHOOK_EVENTS)}")
        from dashboard_api.db import dumps
        fields.append("events=?"); values.append(dumps(body.events))
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(webhook_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE webhooks SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Webhook not found")
        audit(conn, user["email"], "webhook.update", webhook_id)
        conn.commit()
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (webhook_id,)).fetchone()
    return row_to_dict(row)


@router.post("/webhooks/{webhook_id}/test")
def test_webhook(webhook_id: str, actor: dict = Depends(require_role("admin", "manager"))):
    """Deliver a synchronous test event so the operator can verify the endpoint."""
    from dashboard_api.webhooks import _deliver
    with get_conn() as conn:
        row = conn.execute("SELECT id, url FROM webhooks WHERE id=?", (webhook_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    _deliver("webhook.test", {"message": "ThreatOrbit test delivery", "requestedBy": actor["email"]},
             [{"id": row["id"], "url": row["url"]}])
    with get_conn() as conn:
        updated = conn.execute("SELECT status, last_delivery FROM webhooks WHERE id=?", (webhook_id,)).fetchone()
        audit(conn, actor["email"], "webhook.test", webhook_id, f"result={updated['status']}")
        conn.commit()
    return {"ok": updated["status"] == "active", "status": updated["status"],
            "last_delivery": updated["last_delivery"]}


@router.delete("/webhooks/{webhook_id}", status_code=204)
def delete_webhook(webhook_id: str, actor: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM webhooks WHERE id=?", (webhook_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Webhook not found")
        audit(conn, actor["email"], "webhook.delete", webhook_id)
        conn.commit()
    return None
