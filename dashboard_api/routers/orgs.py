"""Workspace / organization routes (multi-tenancy foundation).

Lets an operator see their current workspace and an admin create/list/rename
workspaces (so an MSSP can stand up a tenant). Data is not yet isolated per
org - see dashboard_api/tenancy.py for the staged isolation seam - so these
endpoints manage the org directory only; they don't partition alerts/IOCs/etc.
yet, which keeps the change non-breaking.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.tenancy import (DEFAULT_ORG_ID, enforced, export_org, new_org,
                                   org_of, org_status, purge_org, quota_usage,
                                   set_org_limits)

router = APIRouter(prefix="/orgs", tags=["orgs"], dependencies=[Depends(current_user)])


class OrgCreate(BaseModel):
    name: str
    plan: str = "enterprise"
    slug: str | None = None


class OrgUpdate(BaseModel):
    name: str | None = None
    plan: str | None = None
    status: str | None = None


class MemberRole(BaseModel):
    role: str


class OrgLimits(BaseModel):
    maxUsers: int | None = None
    maxAssets: int | None = None
    retentionDays: int | None = None


def _now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _counts(conn, org_id: str) -> dict:
    users = conn.execute("SELECT COUNT(*) AS n FROM users WHERE org_id=?", (org_id,)).fetchone()["n"]
    return {"users": users}


@router.get("/current")
def current_org(user: dict = Depends(current_user)):
    """The workspace the caller belongs to (+ whether isolation is enforced)."""
    oid = org_of(user)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM orgs WHERE id=?", (oid,)).fetchone()
        org = row_to_dict(row) if row else {"id": oid, "name": "Default workspace",
                                            "slug": "default", "plan": "enterprise", "status": "active"}
        org.update(_counts(conn, oid))
    org["isolationEnforced"] = enforced()
    return org


@router.get("")
def list_orgs(user: dict = Depends(require_perm("config.manage"))):
    with get_conn() as conn:
        rows = rows_to_dicts(conn.execute("SELECT * FROM orgs ORDER BY created_at").fetchall())
        for o in rows:
            o.update(_counts(conn, o["id"]))
    return rows


@router.post("", status_code=201)
def create_org(body: OrgCreate, user: dict = Depends(require_perm("config.manage"))):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Workspace name is required")
    with get_conn() as conn:
        org = new_org(conn, name=name, plan=body.plan, slug=body.slug)
        audit(conn, user["email"], "org.create", org["id"], f"name={name}")
        conn.commit()
    return org


@router.get("/{org_id}/members")
def list_members(org_id: str, user: dict = Depends(require_perm("users.manage"))):
    """Everyone who can act in `org_id`: its home users (base role) plus
    per-workspace grants. Effective role per user is shown."""
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None and org_id != "org-default":
            raise HTTPException(status_code=404, detail="Workspace not found")
        home = rows_to_dicts(conn.execute(
            "SELECT id AS user_id, email, name, role FROM users WHERE org_id=?", (org_id,)).fetchall())
        for m in home:
            m["source"] = "home"
        granted = rows_to_dicts(conn.execute(
            "SELECT g.user_id, u.email, u.name, g.role, g.granted_by, g.granted_at "
            "FROM user_org_roles g JOIN users u ON u.id=g.user_id WHERE g.org_id=?", (org_id,)).fetchall())
        for m in granted:
            m["source"] = "grant"
    return {"orgId": org_id, "members": home + granted}


@router.put("/{org_id}/members/{user_id}")
def set_member_role(org_id: str, user_id: str, body: MemberRole,
                    actor: dict = Depends(require_perm("users.manage"))):
    """Grant (or update) a user's role **within** `org_id` - per-workspace role
    assignment for MSSP/SaaS. Guarded so you can't grant a role more privileged
    than you hold (no privilege escalation), mirroring custom-role creation."""
    from dashboard_api.permissions import perms_for, role_exists
    role = (body.role or "").strip()
    if not role_exists(role):
        raise HTTPException(status_code=400, detail="Unknown role")
    # No privilege escalation: the role's capabilities must be a subset of yours.
    if not perms_for(role) <= perms_for(actor["role"]):
        raise HTTPException(status_code=403, detail="Cannot grant a role beyond your own privileges")
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None and org_id != "org-default":
            raise HTTPException(status_code=404, detail="Workspace not found")
        urow = conn.execute("SELECT id, org_id FROM users WHERE id=?", (user_id,)).fetchone()
        if urow is None:
            raise HTTPException(status_code=404, detail="User not found")
        if (urow["org_id"] or "org-default") == org_id:
            raise HTTPException(status_code=400, detail="User's home workspace already uses their base role")
        conn.execute(
            "INSERT INTO user_org_roles (user_id,org_id,role,granted_by,granted_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(user_id,org_id) DO UPDATE SET role=excluded.role, "
            "granted_by=excluded.granted_by, granted_at=excluded.granted_at",
            (user_id, org_id, role, actor["email"], _now()))
        audit(conn, actor["email"], "org.member.set", f"{org_id}:{user_id}", f"role={role}")
        conn.commit()
    return {"orgId": org_id, "userId": user_id, "role": role}


@router.delete("/{org_id}/members/{user_id}")
def remove_member(org_id: str, user_id: str, actor: dict = Depends(require_perm("users.manage"))):
    """Revoke a user's per-workspace role grant in `org_id`."""
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM user_org_roles WHERE user_id=? AND org_id=?", (user_id, org_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No such workspace grant")
        audit(conn, actor["email"], "org.member.remove", f"{org_id}:{user_id}", None)
        conn.commit()
    return {"orgId": org_id, "userId": user_id, "removed": True}


@router.patch("/{org_id}")
def update_org(org_id: str, body: OrgUpdate, user: dict = Depends(require_perm("config.manage"))):
    fields, values = [], []
    for col in ("name", "plan", "status"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(v)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    # The default workspace is the deployment itself - never suspend it (that
    # would lock out the platform admin).
    if org_id == DEFAULT_ORG_ID and body.status == "suspended":
        raise HTTPException(status_code=400, detail="The default workspace cannot be suspended")
    values.append(org_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE orgs SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Workspace not found")
        audit(conn, user["email"], "org.update", org_id, f"fields={','.join(f.split('=')[0] for f in fields)}")
        conn.commit()
        row = conn.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
    return row_to_dict(row)


@router.get("/{org_id}/limits")
def get_limits(org_id: str, user: dict = Depends(require_perm("config.manage"))):
    """Per-tenant quotas (users/assets) + retention window, with current usage.
    `limit`/`retentionDays` of null means unlimited / the deployment default."""
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return {"orgId": org_id, **quota_usage(conn, org_id)}


@router.put("/{org_id}/limits")
def put_limits(org_id: str, body: OrgLimits, user: dict = Depends(require_perm("config.manage"))):
    """Set a workspace's quotas/retention (a value of 0 clears it back to
    unlimited / the global default)."""
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        set_org_limits(conn, org_id, max_users=body.maxUsers, max_assets=body.maxAssets,
                       retention_days=body.retentionDays)
        audit(conn, user["email"], "org.limits", org_id,
              f"users={body.maxUsers} assets={body.maxAssets} retention={body.retentionDays}")
        conn.commit()
        return {"orgId": org_id, **quota_usage(conn, org_id)}


@router.get("/{org_id}/export")
def export_workspace(org_id: str, user: dict = Depends(require_perm("config.manage"))):
    """Full JSON dump of a workspace's data (tenant offboarding / portability).
    Secrets are scrubbed from the user rows."""
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        data = export_org(conn, org_id)
        audit(conn, user["email"], "org.export", org_id,
              f"tables={len(data['tables'])}")
        conn.commit()
    return data


@router.delete("/{org_id}")
def delete_workspace(org_id: str, user: dict = Depends(require_perm("config.manage"))):
    """Hard-delete a workspace and ALL its data across every tenant table. Guarded:
    the default workspace can't be deleted, and a workspace must be **suspended**
    first (a deliberate two-step) so this can't be a one-click data loss."""
    if org_id == DEFAULT_ORG_ID:
        raise HTTPException(status_code=400, detail="The default workspace cannot be deleted")
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        if org_status(conn, org_id) != "suspended":
            raise HTTPException(status_code=409, detail="Suspend the workspace before deleting it")
        counts = purge_org(conn, org_id)
        audit(conn, user["email"], "org.delete", org_id,
              f"purged={sum(counts.values())}")
        conn.commit()
    return {"orgId": org_id, "deleted": True, "purged": counts}
