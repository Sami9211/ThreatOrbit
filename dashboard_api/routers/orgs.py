"""Workspace / organization routes (multi-tenancy foundation).

Lets an operator see their current workspace and an admin create/list/rename
workspaces (so an MSSP can stand up a tenant). Data is not yet isolated per
org — see dashboard_api/tenancy.py for the staged isolation seam — so these
endpoints manage the org directory only; they don't partition alerts/IOCs/etc.
yet, which keeps the change non-breaking.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.tenancy import enforced, new_org, org_of

router = APIRouter(prefix="/orgs", tags=["orgs"], dependencies=[Depends(current_user)])


class OrgCreate(BaseModel):
    name: str
    plan: str = "enterprise"
    slug: str | None = None


class OrgUpdate(BaseModel):
    name: str | None = None
    plan: str | None = None
    status: str | None = None


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


@router.patch("/{org_id}")
def update_org(org_id: str, body: OrgUpdate, user: dict = Depends(require_perm("config.manage"))):
    fields, values = [], []
    for col in ("name", "plan", "status"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(v)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(org_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE orgs SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Workspace not found")
        audit(conn, user["email"], "org.update", org_id, f"fields={','.join(f.split('=')[0] for f in fields)}")
        conn.commit()
        row = conn.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
    return row_to_dict(row)
