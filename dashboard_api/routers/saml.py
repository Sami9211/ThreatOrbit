"""SAML 2.0 SP endpoints - status, login redirect, and the ACS.

Public (the user isn't authenticated yet). The ACS verifies the IdP's signed
assertion (dashboard_api/saml.py does the crypto + policy checks), JIT-provisions
the user, and hands the normal dashboard session token to the frontend in the
URL fragment so it never lands in a server log. Degrades to 404 when SAML isn't
configured; email+password and OIDC are unaffected.
"""
import secrets
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Query
from fastapi.responses import RedirectResponse

from dashboard_api import saml, tenancy
from dashboard_api.auth import create_token, hash_password
from dashboard_api.config import OIDC_POST_LOGIN_URL, SAML_ROLE_MAP
from dashboard_api.db import audit, get_conn, row_to_dict

router = APIRouter(prefix="/auth/saml", tags=["sso"])


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@router.get("/status")
def status():
    """Lets the login page show/hide the SAML button."""
    return {"configured": saml.configured(), "loginPath": "/auth/saml/login"}


@router.get("/login")
def login(return_to: str | None = Query(default=None)):
    if not saml.configured():
        raise HTTPException(status_code=404, detail="SAML is not configured on this deployment.")
    rid, url = saml.make_authn_request()
    relay = saml.make_relay_state(rid, return_to)
    sep = "&" if "?" in url else "?"
    return RedirectResponse(url=f"{url}{sep}RelayState={quote(relay)}", status_code=302)


def _provision(conn, u: dict) -> dict:
    """Find-or-create the SSO user. The IdP owns the role only when a SAML role
    map is configured; otherwise a created user gets the default role and later
    manual changes are preserved (mirrors the OIDC provisioning rule)."""
    manage_roles = bool(SAML_ROLE_MAP)
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
    ph, salt = hash_password(secrets.token_urlsafe(24))  # IdP-managed; local pw disabled
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,last_login,created_at,org_id) "
        "VALUES (?,?,?,?, 'active', ?,?, '#7A3CFF', 0, ?, ?, ?)",
        (uid, u["email"], u["name"], u["role"], ph, salt, now, now, tenancy.DEFAULT_ORG_ID))
    return {"id": uid, "email": u["email"], "name": u["name"], "role": u["role"],
            "status": "active", "org_id": tenancy.DEFAULT_ORG_ID}


def _back(fragment: str) -> RedirectResponse:
    return RedirectResponse(url=f"{OIDC_POST_LOGIN_URL}#{fragment}", status_code=302)


@router.post("/acs")
def acs(SAMLResponse: str = Form(...), RelayState: str = Form(default="")):
    if not saml.configured():
        raise HTTPException(status_code=404, detail="SAML is not configured on this deployment.")
    try:
        st = saml.read_relay_state(RelayState)
        u = saml.parse_response(SAMLResponse, st.get("r", ""))
    except ValueError as e:
        return _back(f"sso_error={quote(str(e))}")
    except Exception:
        return _back("sso_error=saml_failed")
    with get_conn() as conn:
        user = _provision(conn, u)
        audit(conn, user["email"], "auth.saml_login", user["id"], f"role={user['role']}")
        conn.commit()
    token = create_token(user)
    return _back(f"sso_token={token}")
