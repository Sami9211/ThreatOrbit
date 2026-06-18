"""Configuration routes: platform settings, API keys."""
import hashlib
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_perm
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
def update_settings(body: SettingsUpdate, actor: dict = Depends(require_perm("config.manage"))):
    with get_conn() as conn:
        for k, v in body.values.items():
            conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (k, str(v)))
        audit(conn, actor["email"], "settings.update", None, f"keys={','.join(body.values.keys())}")
        conn.commit()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


@router.get("/api-keys")
def list_api_keys(user: dict = Depends(require_perm("config.manage"))):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id,name,prefix,scope,last_used,created_at,created_by,revoked "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        # who-saw-what: viewing secrets metadata is sensitive, so it's audited.
        audit(conn, user["email"], "access.api_keys", None, f"count={len(rows)}")
        conn.commit()
    return rows_to_dicts(rows)


class LicenseActivate(BaseModel):
    key: str


class LicenseIssue(BaseModel):
    plan: str
    org: str
    seats: int | None = None
    connectors: int | None = None
    expires: str | None = None


class TestEmail(BaseModel):
    to: str


@router.get("/email")
def email_status(_: dict = Depends(require_perm("config.manage"))):
    """SMTP delivery readiness (the email channel for scheduled reports)."""
    from dashboard_api.mailer import status
    return status()


@router.post("/email/test")
def test_email(body: TestEmail, user: dict = Depends(require_perm("config.manage"))):
    """Send a test email (real send when SMTP is configured, else reports why)."""
    from dashboard_api.mailer import send_email
    result = send_email(body.to, "ThreatOrbit SMTP test",
                        "<p>Your ThreatOrbit email delivery is working.</p>")
    with get_conn() as conn:
        audit(conn, user["email"], "email.test", body.to, f"sent={result.get('sent')}")
        conn.commit()
    return result


@router.get("/database")
def database_backend(_: dict = Depends(require_perm("config.manage"))):
    """Active storage backend + Postgres-readiness (the Postgres option is
    staged; this surfaces what's needed to flip it on)."""
    from dashboard_api.db_backend import backend_info
    return backend_info()


@router.get("/backup")
def download_backup(user: dict = Depends(require_perm("config.manage"))):
    """Download a transactionally consistent snapshot of the platform DB
    (SQLite online-backup API - safe while the service is running). Restore
    is an offline operation: see docs/OPERATIONS.md. Postgres deployments
    should use pg_dump instead; this endpoint refuses there."""
    import tempfile
    from fastapi.responses import FileResponse
    from starlette.background import BackgroundTask
    from dashboard_api.db_backend import is_postgres
    from dashboard_api.ops import backup_sqlite, default_backup_name, verify_backup
    if is_postgres():  # pragma: no cover - opt-in backend
        raise HTTPException(status_code=400,
                            detail="Postgres backend: use pg_dump (see docs/OPERATIONS.md)")
    name = default_backup_name()
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    backup_sqlite(tmp.name)
    verify_backup(tmp.name)  # never hand out a corrupt snapshot
    with get_conn() as conn:
        audit(conn, user["email"], "config.backup", None, f"file={name}")
        conn.commit()
    return FileResponse(tmp.name, media_type="application/vnd.sqlite3", filename=name,
                        background=BackgroundTask(lambda: os.unlink(tmp.name)))


@router.get("/license")
def license_status(_: dict = Depends(current_user)):
    """The active license: plan, limits, current usage, validity."""
    from dashboard_api.licensing import PLANS, current_license, usage
    with get_conn() as conn:
        lic = current_license(conn)
        use = usage(conn)
    return {"plan": lic["plan"], "label": PLANS[lic["plan"]]["label"],
            "org": lic.get("org"), "expires": lic.get("expires"),
            "builtin": lic.get("builtin", False), "warning": lic.get("warning"),
            "limits": {"seats": lic.get("seats"), "connectors": lic.get("connectors")},
            "usage": use}


@router.post("/license/activate")
def activate_license(body: LicenseActivate, user: dict = Depends(require_perm("license.manage"))):
    """Validate + store a signed license key (rejects forged/expired keys)."""
    from dashboard_api.licensing import verify_key
    try:
        data = verify_key(body.key.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('license_key',?)",
                     (body.key.strip(),))
        audit(conn, user["email"], "license.activate", None,
              f"plan={data['plan']} org={data.get('org')}")
        conn.commit()
    return {"activated": True, **data}


@router.post("/license/issue")
def issue_license(body: LicenseIssue, user: dict = Depends(require_perm("license.manage"))):
    """Mint a signed key (vendor side, for self-hosted operators issuing
    licenses to their own tenants). The secret stays server-side."""
    from dashboard_api.licensing import generate_key
    try:
        key = generate_key(plan=body.plan, org=body.org, seats=body.seats,
                           connectors=body.connectors, expires=body.expires)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with get_conn() as conn:
        audit(conn, user["email"], "license.issue", None, f"plan={body.plan} org={body.org}")
        conn.commit()
    return {"key": key, "plan": body.plan, "org": body.org}


@router.delete("/license", status_code=204)
def clear_license(user: dict = Depends(require_perm("license.manage"))):
    """Remove the activated key (falls back to the built-in license)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key='license_key'")
        audit(conn, user["email"], "license.clear", None)
        conn.commit()
    return None


@router.get("/onboarding")
def onboarding_status(user: dict = Depends(current_user)):
    """First-run checklist, computed from REAL platform state (never stored):
    each step is done when the thing actually exists. A buyer can see exactly
    what's left to be productive - and the wizard can never drift from reality."""
    from dashboard_api.config import SEED_ADMIN_PASSWORD
    with get_conn() as conn:
        org = conn.execute("SELECT value FROM settings WHERE key='organization'").fetchone()
        users_n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        connectors_n = conn.execute("SELECT COUNT(*) FROM connectors WHERE enabled=1").fetchone()[0]
        sources_n = conn.execute("SELECT COUNT(*) FROM log_sources").fetchone()[0]
        events_n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        rules_n = conn.execute("SELECT COUNT(*) FROM detection_rules WHERE status='enabled'").fetchone()[0]
        hooks_n = conn.execute("SELECT COUNT(*) FROM webhooks").fetchone()[0]
        reports_n = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='report.generate'").fetchone()[0]
        dismissed = conn.execute(
            "SELECT value FROM settings WHERE key='onboarding_dismissed'").fetchone()
        # default admin password still in use? (only checkable when env default known)
        admin = conn.execute(
            "SELECT password_hash, password_salt FROM users WHERE role='admin' "
            "ORDER BY created_at LIMIT 1").fetchone()
    pw_changed = True
    if admin and SEED_ADMIN_PASSWORD:
        from dashboard_api.auth import verify_password
        pw_changed = not verify_password(SEED_ADMIN_PASSWORD, admin["password_hash"],
                                         admin["password_salt"])
    steps = [
        {"id": "org", "label": "Name your organization",
         "done": bool(org and org["value"].strip()), "link": "/dashboard/config"},
        {"id": "password", "label": "Change the bootstrap admin password",
         "done": pw_changed, "link": "/dashboard/config"},
        {"id": "team", "label": "Invite your team (2+ users)",
         "done": users_n >= 2, "link": "/dashboard/config"},
        {"id": "connector", "label": "Enable an intelligence connector",
         "done": connectors_n >= 1, "link": "/dashboard/feeds/sources"},
        {"id": "logs", "label": "Connect a log source / ingest logs",
         "done": sources_n >= 1 and events_n >= 1, "link": "/dashboard/siem/sources"},
        {"id": "rules", "label": "Enable detection rules",
         "done": rules_n >= 1, "link": "/dashboard/siem/rules"},
        {"id": "notify", "label": "Add a webhook for alert delivery",
         "done": hooks_n >= 1, "link": "/dashboard/config"},
        {"id": "report", "label": "Generate your first report",
         "done": reports_n >= 1, "link": "/dashboard"},
    ]
    done = sum(1 for s in steps if s["done"])
    return {"steps": steps, "done": done, "total": len(steps),
            "pct": round(done / len(steps) * 100),
            "complete": done == len(steps),
            "dismissed": bool(dismissed and dismissed["value"] == "true")}


@router.post("/onboarding/dismiss")
def dismiss_onboarding(user: dict = Depends(current_user)):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES "
                     "('onboarding_dismissed','true')")
        audit(conn, user["email"], "onboarding.dismiss", None)
        conn.commit()
    return {"dismissed": True}


@router.get("/roles")
def list_roles(_: dict = Depends(require_perm("config.manage"))):
    """The full RBAC matrix: every capability and which roles hold it."""
    from dashboard_api.permissions import CAPABILITIES, ROLE_PERMISSIONS
    return {
        "capabilities": CAPABILITIES,
        "roles": {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()},
    }


@router.post("/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, user: dict = Depends(require_perm("config.manage"))):
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


@router.get("/leader")
def leader_status(_: dict = Depends(current_user)):
    """Background-work leader-election state: which replica currently holds the
    singleton lease (engine tick + scheduler), and this node's own identity.
    On a single-replica install this node is always the leader."""
    from dashboard_api import leader
    return leader.status()


@router.get("/engine")
def engine_status(_: dict = Depends(current_user)):
    """Live processing engine state + how much live data it has produced."""
    from dashboard_api.config import DATA_MODE, ENGINE_TICK_SECONDS, INGEST_MAX_BACKLOG
    from dashboard_api import event_queue
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='engine_enabled'").fetchone()
        alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_id IN ('R-ENGINE','R-MANUAL')").fetchone()["n"]
        total_alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        dark = conn.execute("SELECT COUNT(*) AS n FROM dark_web_findings").fetchone()["n"]
        queue = event_queue.stats(conn)   # detection backlog + lag (backpressure)
    # Bounded-queue backpressure: the ingest cap + whether we're shedding now.
    queue["maxBacklog"] = INGEST_MAX_BACKLOG
    queue["shedding"] = bool(INGEST_MAX_BACKLOG) and queue["depth"] >= INGEST_MAX_BACKLOG
    return {
        "mode": DATA_MODE,
        "running": DATA_MODE == "live" and (row is None or row["value"] != "false"),
        "enabled": (row is None or row["value"] != "false"),
        "tickSeconds": ENGINE_TICK_SECONDS,
        "alertsProduced": alerts, "totalAlerts": total_alerts, "darkWebFindings": dark,
        # Pipeline backpressure: pending events, in-flight, and oldest-pending lag.
        "queue": queue,
    }


@router.post("/engine")
def engine_control(body: EngineControl, user: dict = Depends(require_perm("config.manage"))):
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
def list_jobs(limit: int = 50, _: dict = Depends(require_perm("config.manage"))):
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
    _: dict = Depends(require_perm("config.manage")),
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
def revoke_api_key(key_id: str, actor: dict = Depends(require_perm("config.manage"))):
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


def _public_webhook(d: dict) -> dict:
    """The signing secret is shown ONCE (at create / rotate); never re-listed."""
    d.pop("secret", None)
    return d


def _wh_scope(user: dict):
    """(sql_fragment, params) restricting webhook rows to the caller's org when
    tenant isolation is on; a no-op otherwise."""
    from dashboard_api import tenancy
    if tenancy.enforced():
        return " AND org_id=?", [tenancy.org_of(user)]
    return "", []


@router.get("/webhooks")
def list_webhooks(user: dict = Depends(require_perm("config.manage"))):
    clause, params = _wh_scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM webhooks WHERE 1=1{clause} ORDER BY created_at DESC", params).fetchall()
    return [_public_webhook(d) for d in rows_to_dicts(rows)]


@router.post("/webhooks", status_code=201)
def create_webhook(body: WebhookCreate, user: dict = Depends(require_perm("config.manage"))):
    from dashboard_api.net_guard import validate_external_url, UnsafeUrlError
    from dashboard_api.webhooks import new_webhook_secret
    try:
        url = validate_external_url(body.url)  # SSRF guard (blocks internal/reserved)
    except UnsafeUrlError as e:
        raise HTTPException(status_code=400, detail=str(e))
    bad = [e for e in body.events if e not in _WEBHOOK_EVENTS]
    if bad or not body.events:
        raise HTTPException(status_code=400, detail=f"events must be a non-empty subset of {sorted(_WEBHOOK_EVENTS)}")
    wid = str(uuid.uuid4())
    secret = new_webhook_secret()
    from dashboard_api.db import dumps
    from dashboard_api import tenancy
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO webhooks (id,url,events,status,last_delivery,created_at,created_by,secret,org_id) "
            "VALUES (?,?,?,'active',NULL,?,?,?,?)",
            (wid, url, dumps(body.events), _now(), user["email"], secret, tenancy.org_of(user)),
        )
        audit(conn, user["email"], "webhook.create", wid, f"url={url}")
        conn.commit()
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
    # The secret is returned here ONCE so the integrator can configure signature
    # verification; it is never exposed again by the list endpoint.
    return row_to_dict(row)


@router.patch("/webhooks/{webhook_id}")
def update_webhook(webhook_id: str, body: WebhookUpdate, user: dict = Depends(require_perm("config.manage"))):
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
    clause, sp = _wh_scope(user)
    values.append(webhook_id)
    values.extend(sp)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE webhooks SET {','.join(fields)} WHERE id=?{clause}", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Webhook not found")
        audit(conn, user["email"], "webhook.update", webhook_id)
        conn.commit()
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (webhook_id,)).fetchone()
    return _public_webhook(row_to_dict(row))


@router.post("/webhooks/{webhook_id}/test")
def test_webhook(webhook_id: str, actor: dict = Depends(require_perm("config.manage"))):
    """Deliver a synchronous test event so the operator can verify the endpoint."""
    from dashboard_api.webhooks import _deliver
    clause, sp = _wh_scope(actor)
    with get_conn() as conn:
        row = conn.execute(f"SELECT id, url, secret FROM webhooks WHERE id=?{clause}",
                           (webhook_id, *sp)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    _deliver("webhook.test", {"message": "ThreatOrbit test delivery", "requestedBy": actor["email"]},
             [{"id": row["id"], "url": row["url"], "secret": row["secret"]}])
    with get_conn() as conn:
        updated = conn.execute("SELECT status, last_delivery FROM webhooks WHERE id=?", (webhook_id,)).fetchone()
        audit(conn, actor["email"], "webhook.test", webhook_id, f"result={updated['status']}")
        conn.commit()
    return {"ok": updated["status"] == "active", "status": updated["status"],
            "last_delivery": updated["last_delivery"]}


@router.post("/webhooks/{webhook_id}/rotate-secret")
def rotate_webhook_secret(webhook_id: str, actor: dict = Depends(require_perm("config.manage"))):
    """Issue a fresh signing secret (invalidating the old one). Returned once."""
    from dashboard_api.webhooks import new_webhook_secret
    secret = new_webhook_secret()
    clause, sp = _wh_scope(actor)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE webhooks SET secret=? WHERE id=?{clause}", (secret, webhook_id, *sp))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Webhook not found")
        audit(conn, actor["email"], "webhook.rotate_secret", webhook_id)
        conn.commit()
    return {"id": webhook_id, "secret": secret}


@router.delete("/webhooks/{webhook_id}", status_code=204)
def delete_webhook(webhook_id: str, actor: dict = Depends(require_perm("config.manage"))):
    clause, sp = _wh_scope(actor)
    with get_conn() as conn:
        cur = conn.execute(f"DELETE FROM webhooks WHERE id=?{clause}", (webhook_id, *sp))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Webhook not found")
        audit(conn, actor["email"], "webhook.delete", webhook_id)
        conn.commit()
    return None
