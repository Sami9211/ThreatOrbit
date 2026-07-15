"""Custom RBAC roles - operator-defined roles that extend the four built-ins.

A role bundles capabilities drawn from `permissions.CAPABILITIES`. The built-in
roles (admin/manager/analyst/viewer) stay code-authoritative and read-only here;
custom roles live in the `roles` table and are resolved by
`permissions.perms_for()`. To prevent privilege escalation, a creator can only
grant capabilities they themselves hold.
"""
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from dashboard_api.auth import require_perm
from dashboard_api.db import audit, dumps, get_conn, row_to_dict
from dashboard_api.permissions import CAPABILITIES, ROLE_PERMISSIONS, perms_for

router = APIRouter(prefix="/roles", tags=["roles"])
_SLUG = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


class RoleBody(BaseModel):
    id: str | None = None
    name: str
    description: str | None = None
    capabilities: list[str] = []


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _check_caps(requested: list[str], actor_role: str) -> list[str]:
    """Validate requested capabilities + enforce no privilege escalation."""
    caps = sorted(set(requested))
    bad = [c for c in caps if c not in CAPABILITIES]
    if bad:
        raise HTTPException(status_code=400, detail=f"Unknown capabilities: {bad}")
    over = [c for c in caps if c not in perms_for(actor_role)]
    if over:
        raise HTTPException(status_code=403,
                            detail=f"You cannot grant capabilities you don't hold: {over}")
    return caps


def _caps_of(row: dict) -> list[str]:
    raw = row.get("capabilities")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return []
    return raw or []


@router.get("")
def list_roles(actor: dict = Depends(require_perm("users.manage"))):
    """Built-in + custom roles, plus the capability catalogue for a role editor."""
    builtins = [{"id": r, "name": r.capitalize(), "description": None, "builtIn": True,
                 "capabilities": sorted(caps)} for r, caps in ROLE_PERMISSIONS.items()]
    with get_conn() as conn:
        rows = [row_to_dict(x) for x in conn.execute("SELECT * FROM roles ORDER BY created_at").fetchall()]
    custom = [{"id": d["id"], "name": d["name"], "description": d.get("description"),
               "builtIn": False, "capabilities": _caps_of(d)} for d in rows]
    return {"roles": builtins + custom, "capabilities": CAPABILITIES}


@router.post("", status_code=201)
def create_role(body: RoleBody, actor: dict = Depends(require_perm("users.manage"))):
    rid = (body.id or body.name).strip().lower().replace(" ", "-")
    if not _SLUG.match(rid):
        raise HTTPException(status_code=400, detail="Role id must be a slug (a-z, 0-9, -)")
    if rid in ROLE_PERMISSIONS:
        raise HTTPException(status_code=409, detail="That id is a built-in role")
    caps = _check_caps(body.capabilities, actor["role"])
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM roles WHERE id=?", (rid,)).fetchone():
            raise HTTPException(status_code=409, detail="Role already exists")
        conn.execute("INSERT INTO roles (id,name,description,capabilities,created_at,org_id) "
                     "VALUES (?,?,?,?,?, 'org-default')",
                     (rid, body.name.strip(), body.description, dumps(caps), _now()))
        audit(conn, actor["email"], "role.create", rid, f"caps={len(caps)}")
        conn.commit()
    return {"id": rid, "name": body.name.strip(), "description": body.description,
            "builtIn": False, "capabilities": caps}


@router.patch("/{rid}")
def update_role(rid: str, body: RoleBody, actor: dict = Depends(require_perm("users.manage"))):
    if rid in ROLE_PERMISSIONS:
        raise HTTPException(status_code=400, detail="Built-in roles cannot be modified")
    caps = _check_caps(body.capabilities, actor["role"])
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM roles WHERE id=?", (rid,)).fetchone():
            raise HTTPException(status_code=404, detail="Role not found")
        conn.execute("UPDATE roles SET name=?, description=?, capabilities=? WHERE id=?",
                     (body.name.strip(), body.description, dumps(caps), rid))
        audit(conn, actor["email"], "role.update", rid, f"caps={len(caps)}")
        conn.commit()
    return {"id": rid, "name": body.name.strip(), "description": body.description,
            "builtIn": False, "capabilities": caps}


@router.delete("/{rid}")
def delete_role(rid: str, actor: dict = Depends(require_perm("users.manage"))):
    if rid in ROLE_PERMISSIONS:
        raise HTTPException(status_code=400, detail="Built-in roles cannot be deleted")
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM roles WHERE id=?", (rid,)).fetchone():
            raise HTTPException(status_code=404, detail="Role not found")
        assigned = conn.execute("SELECT COUNT(*) c FROM users WHERE role=?", (rid,)).fetchone()["c"]
        if assigned:
            raise HTTPException(status_code=409,
                                detail=f"{assigned} user(s) still have this role; reassign them first")
        conn.execute("DELETE FROM roles WHERE id=?", (rid,))
        audit(conn, actor["email"], "role.delete", rid, "")
        conn.commit()
    return Response(status_code=204)
