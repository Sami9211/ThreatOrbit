"""User management routes (admin/manager create & manage; self read)."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user, hash_password, require_role
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/users", tags=["users"])

ROLES = {"admin", "manager", "analyst", "viewer"}
_PUBLIC = "id,email,name,role,status,avatar_color,mfa_enabled,last_login,created_at"


class UserCreate(BaseModel):
    email: str
    name: str
    role: str = "analyst"
    password: str
    avatar_color: str = "#7A3CFF"


class UserUpdate(BaseModel):
    name: str | None = None
    role: str | None = None
    status: str | None = None
    avatar_color: str | None = None
    mfa_enabled: bool | None = None


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@router.get("")
def list_users(_: dict = Depends(current_user)):
    with get_conn() as conn:
        rows = conn.execute(f"SELECT {_PUBLIC} FROM users ORDER BY created_at").fetchall()
    return rows_to_dicts(rows)


@router.post("", status_code=201)
def create_user(body: UserCreate, actor: dict = Depends(require_role("admin", "manager"))):
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {sorted(ROLES)}")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    ph, salt = hash_password(body.password)
    uid = str(uuid.uuid4())
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (body.email.lower(),)).fetchone():
            raise HTTPException(status_code=409, detail="A user with that email already exists")
        conn.execute(
            "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
            "avatar_color,mfa_enabled,last_login,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, body.email.lower(), body.name, body.role, "active", ph, salt,
             body.avatar_color, 0, None, _now()),
        )
        audit(conn, actor["email"], "user.create", uid, f"email={body.email.lower()} role={body.role}")
        conn.commit()
        row = conn.execute(f"SELECT {_PUBLIC} FROM users WHERE id=?", (uid,)).fetchone()
    return row_to_dict(row)


@router.patch("/{user_id}")
def update_user(user_id: str, body: UserUpdate, actor: dict = Depends(require_role("admin", "manager"))):
    fields, values = [], []
    for col in ("name", "role", "status", "avatar_color", "mfa_enabled"):
        val = getattr(body, col)
        if val is not None:
            if col == "role" and val not in ROLES:
                raise HTTPException(status_code=400, detail="Invalid role")
            if col == "mfa_enabled":
                val = int(val)
            fields.append(f"{col}=?")
            values.append(val)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(user_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE users SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        changed = ",".join(f.split("=")[0] for f in fields)
        audit(conn, actor["email"], "user.update", user_id, f"fields={changed}")
        conn.commit()
        row = conn.execute(f"SELECT {_PUBLIC} FROM users WHERE id=?", (user_id,)).fetchone()
    return row_to_dict(row)


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: str, actor: dict = Depends(require_role("admin"))):
    if user_id == actor["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        audit(conn, actor["email"], "user.delete", user_id)
        conn.commit()
    return None
