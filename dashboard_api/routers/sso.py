"""SSO (OIDC) endpoints - status, login redirect, and callback.

All public (the user isn't authenticated yet). The callback issues the normal
dashboard session token and hands it to the frontend in the URL fragment, so it
never appears in a server log. Degrades to 404/"not configured" with no IdP set.
"""
import secrets
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from dashboard_api import oidc, tenancy
from dashboard_api.auth import create_token, hash_password, record_session
from dashboard_api.config import OIDC_POST_LOGIN_URL, OIDC_ROLE_MAP
from dashboard_api.db import audit, get_conn, row_to_dict

router = APIRouter(prefix="/auth/sso", tags=["sso"])


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@router.get("/status")
def status():
    """Lets the login page show/hide the SSO button."""
    return {"configured": oidc.configured(), "loginPath": "/auth/sso/login"}


@router.get("/login")
def login(return_to: str | None = Query(default=None)):
    if not oidc.configured():
        raise HTTPException(status_code=404, detail="SSO is not configured on this deployment.")
    state, nonce = oidc.make_state(return_to)
    try:
        url = oidc.authorization_url(state, nonce)
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach the identity provider.")
    return RedirectResponse(url=url, status_code=302)


def _provision(conn, u: dict) -> dict:
    """Find-or-create the SSO user. The IdP owns the role only when a role map is
    configured; otherwise a created user gets the default role and later manual
    changes are preserved."""
    manage_roles = bool(OIDC_ROLE_MAP)
    now = _now()
    row = conn.execute("SELECT * FROM users WHERE email=?", (u["email"],)).fetchone()
    if row:
        user = row_to_dict(row)
        role = u["role"] if manage_roles else user["role"]
        conn.execute("UPDATE users SET name=?, role=?, status='active', last_login=? WHERE id=?",
                     (u["name"], role, now, user["id"]))
        user.update(name=u["name"], role=role, status="active")
        return user
    uid = str(uuid.uuid4())
    # SSO users authenticate at the IdP; store an unguessable random password so
    # the local password path is effectively disabled for them.
    ph, salt = hash_password(secrets.token_urlsafe(24))
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,last_login,created_at,org_id) "
        "VALUES (?,?,?,?, 'active', ?,?, '#7A3CFF', 0, ?, ?, ?)",
        (uid, u["email"], u["name"], u["role"], ph, salt, now, now, tenancy.DEFAULT_ORG_ID),
    )
    return {"id": uid, "email": u["email"], "name": u["name"], "role": u["role"],
            "status": "active", "org_id": tenancy.DEFAULT_ORG_ID}


def _back(fragment: str) -> RedirectResponse:
    return RedirectResponse(url=f"{OIDC_POST_LOGIN_URL}#{fragment}", status_code=302)


@router.get("/callback")
def callback(request: Request, code: str | None = Query(default=None),
             state: str | None = Query(default=None), error: str | None = Query(default=None)):
    if not oidc.configured():
        raise HTTPException(status_code=404, detail="SSO is not configured on this deployment.")
    if error:
        return _back(f"sso_error={quote(error)}")
    if not code or not state:
        return _back("sso_error=missing_code")
    try:
        st = oidc.read_state(state)
        tokens = oidc.exchange_code(code, st.get("cv"))   # PKCE verifier (if any)
        claims = oidc.verify_id_token(tokens.get("id_token", ""), st["n"])
        u = oidc.claims_to_user(claims)
    except ValueError as e:
        return _back(f"sso_error={quote(str(e))}")
    except Exception:
        return _back("sso_error=sso_failed")

    with get_conn() as conn:
        user = _provision(conn, u)
        sid = record_session(conn, user["id"], request)   # listable/revocable per-device
        audit(conn, user["email"], "auth.sso_login", user["id"], f"role={user['role']}")
        conn.commit()
    token = create_token(user, sid=sid)
    return _back(f"sso_token={token}")
