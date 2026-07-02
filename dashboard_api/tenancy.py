"""Multi-tenancy / workspaces.

This ships the **foundation** of multi-tenancy in a fully non-breaking way:

  * an `orgs` table and an `org_id` on each user (everyone in a bootstrapped
    "default" workspace, so single-tenant deployments behave exactly as before);
  * org membership resolution on the authenticated principal;
  * org CRUD so an MSSP can create workspaces.

The second half of multi-tenancy - *isolating every data table by org_id* - is
now **wired but off by default**: every table in TENANT_TABLES carries a
defaulted `org_id` column, and each one's list endpoint scopes reads to the
caller's workspace when `DASHBOARD_MULTI_TENANT` is on (default off, so
single-tenant deployments behave exactly as before - proven by the test suite
running with the flag off). User-driven create endpoints stamp `org_of(user)`
so rows land in the creator's workspace (the single-tenant value IS the
default org, so nothing changes there either), and the aggregate/summary
endpoints (overview rollups, section KPIs) apply the same scope via
`scope_sql`. Get-by-id detail reads 404 across workspaces (`cross_org`), global
search and the SSE stream are org-scoped, and **ingested events + the alerts
they trigger carry the ingesting principal's workspace** (per-org ingest), so a
tenant only sees detections from its own logs. The *synthetic* background engine
(`process_tick`) and the deployment-level log listeners deliberately stay in the
default workspace - they are demo/deployment infrastructure, not a tenant's real
data, which flows in through the per-org ingest path. Tenant lifecycle
(suspend/export/delete-with-purge) and per-tenant quotas/retention complete the
MSSP controls. The whole path is validated end-to-end in
`tests/test_tenant_e2e.py` (create→stamp→list→detail→mutate across every core
domain, plus aggregate scoping and per-workspace import dedup); flipping
`DASHBOARD_MULTI_TENANT` on is now purely a per-deployment decision (set it in
the MSSP build's environment).
"""
import os
import uuid
from datetime import datetime, timezone

DEFAULT_ORG_ID = "org-default"
DEFAULT_ORG_NAME = "Acme Security Corp"

# When false (the default), data is NOT org-scoped - the app is single-tenant
# and behaves exactly as it always has. Flip to "true" only once every data
# table carries org_id and every query is scoped (the staged follow-up).
MULTI_TENANT = os.environ.get("DASHBOARD_MULTI_TENANT", "false").lower() == "true"

# Tables scoped by the per-tenant migration: each carries a defaulted org_id
# column and its list endpoint filters by workspace when enforcement is on.
TENANT_TABLES = (
    "alerts", "iocs", "cases", "assets", "detection_rules", "events",
    "dark_web_findings", "threat_actors", "log_sources", "feeds", "connectors",
    "playbooks", "playbook_runs", "saved_hunts", "scans", "suppressions",
    "notifications", "saved_views", "report_schedules",
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_default_org(conn) -> None:
    """Idempotently create the default workspace and place any org-less user in
    it. Safe to call on every boot; non-breaking for single-tenant installs."""
    row = conn.execute("SELECT 1 FROM orgs WHERE id=?", (DEFAULT_ORG_ID,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO orgs (id,name,slug,plan,status,created_at) VALUES (?,?,?,?,?,?)",
            (DEFAULT_ORG_ID, DEFAULT_ORG_NAME, "default", "enterprise", "active", _now()))
    # Backfill membership for anyone not yet assigned (column exists via migration).
    try:
        conn.execute("UPDATE users SET org_id=? WHERE org_id IS NULL OR org_id=''",
                     (DEFAULT_ORG_ID,))
    except Exception:
        pass


def new_org(conn, *, name: str, plan: str = "enterprise", slug: str | None = None) -> dict:
    oid = f"org-{uuid.uuid4().hex[:10]}"
    slug = (slug or name.lower().replace(" ", "-"))[:48]
    conn.execute(
        "INSERT INTO orgs (id,name,slug,plan,status,created_at) VALUES (?,?,?,?,?,?)",
        (oid, name, slug, plan, "active", _now()))
    return {"id": oid, "name": name, "slug": slug, "plan": plan, "status": "active"}


def org_of(user: dict) -> str:
    """The workspace a principal belongs to (default when unset)."""
    return user.get("org_id") or DEFAULT_ORG_ID


# ── Tenant lifecycle (create/suspend/export/delete) ───────────────────────────

def org_status(conn, org_id: str) -> str:
    """A workspace's lifecycle status ('active'/'suspended'); 'active' if unknown."""
    row = conn.execute("SELECT status FROM orgs WHERE id=?", (org_id,)).fetchone()
    return (row["status"] if row and row["status"] else "active")


def is_org_active(conn, org_id: str) -> bool:
    """Whether a workspace may be used for auth. Always True when isolation is off
    or for the default org (never suspendable - it's the deployment workspace)."""
    if not MULTI_TENANT or org_id == DEFAULT_ORG_ID:
        return True
    return org_status(conn, org_id) != "suspended"


def export_org(conn, org_id: str) -> dict:
    """A JSON-serialisable dump of every row belonging to `org_id` across the
    tenant tables + its users (secrets scrubbed) - for tenant offboarding / data
    portability. A full dump: for a large tenant `events` can be sizeable."""
    from dashboard_api.db import rows_to_dicts
    out: dict = {"orgId": org_id, "exportedAt": _now(), "tables": {}}
    org = conn.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
    out["org"] = dict(org) if org else None
    secret_cols = ("password_hash", "password_salt", "mfa_secret",
                   "mfa_recovery_codes", "slack_webhook")
    users = rows_to_dicts(conn.execute("SELECT * FROM users WHERE org_id=?", (org_id,)).fetchall())
    for u in users:
        for c in secret_cols:
            u.pop(c, None)
    out["tables"]["users"] = users
    for table in TENANT_TABLES:
        try:
            out["tables"][table] = rows_to_dicts(
                conn.execute(f"SELECT * FROM {table} WHERE org_id=?", (org_id,)).fetchall())
        except Exception:
            out["tables"][table] = []
    return out


def purge_org(conn, org_id: str) -> dict:
    """Hard-delete every row belonging to `org_id`, then the org itself (tenant
    offboarding). Caller must guard the default org and commit/audit. Returns
    per-table delete counts."""
    counts: dict = {}
    for table in TENANT_TABLES:
        try:
            counts[table] = conn.execute(f"DELETE FROM {table} WHERE org_id=?", (org_id,)).rowcount
        except Exception:
            counts[table] = 0
    for extra in ("user_org_roles", "break_glass", "users"):
        try:
            counts[extra] = conn.execute(f"DELETE FROM {extra} WHERE org_id=?", (org_id,)).rowcount
        except Exception:
            counts[extra] = 0
    counts["orgs"] = conn.execute("DELETE FROM orgs WHERE id=?", (org_id,)).rowcount
    return counts


# ── Per-tenant quotas + retention (limits stored as org-scoped settings) ───────

_LIMIT_KEY = {"users": "org_quota_users", "assets": "org_quota_assets",
              "retention_days": "org_retention_days"}
_QUOTA_TABLE = {"users": "users", "assets": "assets"}


def _get_limit(conn, org_id: str, kind: str):
    row = conn.execute("SELECT value FROM settings WHERE key=?",
                       (f"{_LIMIT_KEY[kind]}:{org_id}",)).fetchone()
    return int(row["value"]) if row and str(row["value"]).isdigit() else None


def set_org_limits(conn, org_id: str, *, max_users=None, max_assets=None, retention_days=None) -> None:
    """Set (or clear with <=0) a workspace's quotas/retention. Caller commits."""
    for kind, val in (("users", max_users), ("assets", max_assets), ("retention_days", retention_days)):
        if val is None:
            continue
        key = f"{_LIMIT_KEY[kind]}:{org_id}"
        if int(val) <= 0:                       # 0/negative → clear (unlimited / global)
            conn.execute("DELETE FROM settings WHERE key=?", (key,))
        else:
            conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, str(int(val))))


def quota_usage(conn, org_id: str) -> dict:
    """Current usage vs limit per quota'd resource (limit None = unlimited)."""
    out = {}
    for resource, table in _QUOTA_TABLE.items():
        used = conn.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE org_id=?", (org_id,)).fetchone()["n"]
        out[resource] = {"used": used, "limit": _get_limit(conn, org_id, resource)}
    out["retentionDays"] = _get_limit(conn, org_id, "retention_days")
    return out


def enforce_quota(conn, org_id: str, resource: str) -> None:
    """Raise HTTP 402 if `org_id` is at/over its quota for `resource`. No-op when
    isolation is off or no limit is set, so single-tenant installs are unaffected."""
    if not MULTI_TENANT:
        return
    limit = _get_limit(conn, org_id, resource)
    if limit is None:
        return
    used = conn.execute(f"SELECT COUNT(*) AS n FROM {_QUOTA_TABLE[resource]} WHERE org_id=?",
                        (org_id,)).fetchone()["n"]
    if used >= limit:
        from fastapi import HTTPException
        raise HTTPException(status_code=402,
                            detail=f"Workspace quota reached for {resource} ({used}/{limit})")


def org_retention_days(conn, org_id: str, default: int) -> int:
    """A workspace's retention window in days - its per-org override, else the
    deployment default."""
    v = _get_limit(conn, org_id, "retention_days")
    return v if v is not None else default


# ── Data-isolation helpers (wired into every TENANT_TABLES list endpoint) ─────────

def enforced() -> bool:
    """Whether per-tenant data isolation is switched on for this deployment."""
    return MULTI_TENANT


def cross_org(row, user: dict) -> bool:
    """True when isolation is on and `row` belongs to a different workspace than
    `user`. Use to 404 id-addressed detail reads across tenants (list endpoints
    already scope via scope_sql; get-by-id reads are id-addressed and need this
    explicit check). Safe no-op when isolation is off or the row has no org_id."""
    if not MULTI_TENANT or row is None:
        return False
    try:
        row_org = row["org_id"]
    except (KeyError, IndexError, TypeError):
        return False
    return bool(row_org) and row_org != org_of(user)


def scope_sql(org_id: str, *, alias: str = "") -> tuple[str, list]:
    """Return an (sql_fragment, params) that filters a query to `org_id` - or a
    no-op when enforcement is off. This is the seam the follow-up migration will
    drop into each data query; kept pure and tested so wiring it later is safe.

        clause, params = scope_sql(org_of(user))
        where = f"WHERE 1=1 {clause}"
        conn.execute(f"SELECT * FROM alerts {where}", params)
    """
    if not MULTI_TENANT:
        return "", []
    col = f"{alias + '.' if alias else ''}org_id"
    return f"AND {col} = ?", [org_id]
