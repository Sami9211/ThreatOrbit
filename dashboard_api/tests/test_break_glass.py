"""Break-glass: time-boxed emergency RBAC elevation.

Proves the security-critical properties: only a base role holding
`break_glass.use` can activate (no self-elevation for viewer/analyst); while
active it grants any capability the base role lacks, and each elevated use is
audited; it expires; and it can be ended early. The default install is
unaffected (no session = ordinary RBAC).
"""
import uuid

import pytest
from fastapi import HTTPException

from dashboard_api import break_glass
from dashboard_api.auth import hash_password, require_perm
from dashboard_api.db import get_conn

PW = "Passw0rd!123"


def _mkuser(conn, email, role):
    ph, salt = hash_password(PW)
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,created_at,org_id) "
        "VALUES (?,?,?,?, 'active', ?,?, '#7A3CFF', 0, '2026-01-01T00:00:00+00:00', 'org-default')",
        (uid, email, "U", role, ph, salt))
    return uid


def _login(client, email):
    r = client.post("/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _email():
    return f"bg-{uuid.uuid4().hex[:8]}@example.com"


def test_break_glass_elevates_require_perm_and_audits():
    # A manager lacks license.manage; break-glass grants it, audited per use.
    with get_conn() as conn:
        uid = _mkuser(conn, _email(), "manager")
        conn.commit()
    muser = {"id": uid, "email": "mgr@x", "role": "manager"}
    gate = require_perm("license.manage")

    with pytest.raises(HTTPException) as ei:        # base manager → denied
        gate(muser)
    assert ei.value.status_code == 403

    with get_conn() as conn:
        break_glass.activate(conn, user_id=uid, reason="incident", minutes=30, activated_by="mgr@x")
        conn.commit()
    assert gate(muser) is muser                     # elevated → granted

    with get_conn() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM audit_log WHERE action='rbac.break_glass' "
                         "AND target='license.manage'").fetchone()["c"]
    assert n >= 1                                   # the elevated use was audited

    with get_conn() as conn:
        break_glass.deactivate(conn, uid)
        conn.commit()
    with pytest.raises(HTTPException):              # back to denied
        gate(muser)


def test_break_glass_expires():
    with get_conn() as conn:
        uid = _mkuser(conn, _email(), "manager")
        break_glass.activate(conn, user_id=uid, reason="x", minutes=30, activated_by="m")
        conn.commit()
    assert break_glass.is_active(uid) is True
    with get_conn() as conn:                        # backdate the expiry
        conn.execute("UPDATE break_glass SET expires_at='2000-01-01T00:00:00+00:00' WHERE user_id=?", (uid,))
        conn.commit()
    assert break_glass.is_active(uid) is False
    with pytest.raises(HTTPException):
        require_perm("license.manage")({"id": uid, "email": "m", "role": "manager"})


def test_viewer_cannot_self_elevate(client):
    with get_conn() as conn:
        email = _email(); _mkuser(conn, email, "viewer")
        conn.commit()
    h = _login(client, email)
    assert client.post("/auth/break-glass", json={"reason": "let me in"}, headers=h).status_code == 403


def test_break_glass_endpoint_lifecycle(client):
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "manager")
        conn.commit()
    h = _login(client, email)
    try:
        assert client.post("/auth/break-glass", json={"reason": "x"}, headers=h).status_code == 400  # too short
        r = client.post("/auth/break-glass", json={"reason": "prod incident", "minutes": 30}, headers=h)
        assert r.status_code == 200 and r.json()["active"] is True
        assert client.get("/auth/break-glass", headers=h).json()["active"] is True
        perms = client.get("/auth/permissions", headers=h).json()
        assert perms["breakGlass"] is True
        assert "license.manage" in perms["permissions"]          # elevated beyond manager
        assert client.post("/auth/break-glass/deactivate", headers=h).json()["active"] is False
        assert client.get("/auth/permissions", headers=h).json()["breakGlass"] is False
    finally:
        with get_conn() as conn:
            break_glass.deactivate(conn, uid)
            conn.commit()


def test_admin_lists_active_sessions(client, auth):
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "manager")
        break_glass.activate(conn, user_id=uid, reason="visible to admin", minutes=20, activated_by=email)
        conn.commit()
    try:
        r = client.get("/auth/break-glass/active", headers=auth)
        assert r.status_code == 200
        assert uid in [s["user_id"] for s in r.json()["sessions"]]
    finally:
        with get_conn() as conn:
            break_glass.deactivate(conn, uid)
            conn.commit()
