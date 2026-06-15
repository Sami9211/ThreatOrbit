"""Session-revocation tests (revocable stateless JWTs via a token-epoch counter).

Sign-out-everywhere, auto-revoke-on-password-change (current session continues
on the fresh token, others die), and admin revoke - all race-free (a monotonic
counter, not a timestamp). `GET /users` is the authed probe (needs only a valid
session).
"""
import uuid

from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn

PW = "Passw0rd!123"


def _mkuser(conn, email, role="analyst"):
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
    return r.json()["token"]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _email():
    return f"sess-{uuid.uuid4().hex[:8]}@example.com"


def test_revoke_all_kills_current_then_relogin_works(client):
    email = _email()
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    tok = _login(client, email)
    assert client.get("/users", headers=_h(tok)).status_code == 200
    assert client.post("/auth/sessions/revoke-all", headers=_h(tok)).status_code == 200
    assert client.get("/users", headers=_h(tok)).status_code == 401      # this session ended
    assert client.get("/users", headers=_h(_login(client, email))).status_code == 200  # re-login ok


def test_change_password_revokes_old_keeps_current(client):
    email = _email()
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    old = _login(client, email)
    r = client.post("/auth/change-password", headers=_h(old),
                    json={"current_password": PW, "new_password": "NewPassw0rd!"})
    assert r.status_code == 200, r.text
    fresh = r.json()["token"]
    assert fresh and fresh != old
    assert client.get("/users", headers=_h(old)).status_code == 401      # other sessions revoked
    assert client.get("/users", headers=_h(fresh)).status_code == 200    # this one continues


def test_admin_revoke_user_sessions(client, auth):
    email = _email()
    with get_conn() as conn:
        uid = _mkuser(conn, email)
        conn.commit()
    tok = _login(client, email)
    assert client.get("/users", headers=_h(tok)).status_code == 200
    assert client.post(f"/users/{uid}/revoke-sessions", headers=auth).status_code == 200
    assert client.get("/users", headers=_h(tok)).status_code == 401


def test_admin_revoke_requires_users_manage(client):
    actor, victim = _email(), _email()
    with get_conn() as conn:
        _mkuser(conn, actor, role="analyst")   # analyst lacks users.manage
        vid = _mkuser(conn, victim)
        conn.commit()
    tok = _login(client, actor)
    assert client.post(f"/users/{vid}/revoke-sessions", headers=_h(tok)).status_code == 403
