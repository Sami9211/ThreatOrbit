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
`scope_sql`. Engine/seed/background writers deliberately stay in the default
workspace - they run as the deployment, not a user; a per-org engine context
is a deployment-level concern. Known limits of the current isolation:
get-by-id detail endpoints are id-addressed (UUIDs are unguessable, but a
strict deployment may want them to 404 cross-org), and global search spans
the deployment.
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


# ── Data-isolation helpers (wired into every TENANT_TABLES list endpoint) ─────────

def enforced() -> bool:
    """Whether per-tenant data isolation is switched on for this deployment."""
    return MULTI_TENANT


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
