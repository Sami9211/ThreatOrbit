"""Authentication routes: login, current user, password change."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import create_token, current_user, hash_password, verify_password
from dashboard_api.db import get_conn, row_to_dict

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
def login(body: LoginRequest):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (body.email.lower(),)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        user = row_to_dict(row)
        if not verify_password(body.password, user["password_hash"], user["password_salt"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if user["status"] == "disabled":
            raise HTTPException(status_code=403, detail="Account disabled")
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (now, user["id"]))
        conn.commit()
    token = create_token(user)
    for k in ("password_hash", "password_salt"):
        user.pop(k, None)
    user["last_login"] = now
    return {"token": token, "user": user}


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return user


@router.post("/change-password")
def change_password(body: PasswordChange, user: dict = Depends(current_user)):
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash, password_salt FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(body.current_password, row["password_hash"], row["password_salt"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if len(body.new_password) < 8:
            raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
        ph, salt = hash_password(body.new_password)
        conn.execute("UPDATE users SET password_hash=?, password_salt=? WHERE id=?", (ph, salt, user["id"]))
        conn.commit()
    return {"ok": True}
