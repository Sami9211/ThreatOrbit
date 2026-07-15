"""Session-revocation tests (revocable stateless JWTs via a token-epoch counter).

Sign-out-everywhere, auto-revoke-on-password-change (current session continues
on the fresh token, others die), and admin revoke - all race-free (a monotonic
counter, not a timestamp). Plus the per-device session list: each login is a
listable row, individually revocable ("sign out this one device"), with the
list kept honest across change-password / revoke-all / admin revoke.
`GET /users` is the authed probe (needs only a valid session).
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


# -- Per-device session list + individual revoke ------------------------------

def test_sessions_list_and_individual_revoke(client):
    email = _email()
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    tok_a = _login(client, email)          # two devices = two logins = two rows
    tok_b = _login(client, email)
    sess = client.get("/auth/sessions", headers=_h(tok_a)).json()
    assert len(sess) == 2
    assert sum(1 for s in sess if s["current"]) == 1     # exactly one is "this device"
    mine = next(s for s in sess if s["current"])
    other = next(s for s in sess if not s["current"])

    # sign out the OTHER device from A; A itself keeps working
    assert client.post(f"/auth/sessions/{other['id']}/revoke", headers=_h(tok_a)).status_code == 200
    assert client.get("/users", headers=_h(tok_b)).status_code == 401
    assert client.get("/users", headers=_h(tok_a)).status_code == 200
    after = client.get("/auth/sessions", headers=_h(tok_a)).json()
    assert [s["id"] for s in after] == [mine["id"]]
    # revoking an already-gone session 404s (idempotent-safe)
    assert client.post(f"/auth/sessions/{other['id']}/revoke", headers=_h(tok_a)).status_code == 404


def test_cannot_revoke_another_users_session(client):
    e1, e2 = _email(), _email()
    with get_conn() as conn:
        _mkuser(conn, e1)
        _mkuser(conn, e2)
        conn.commit()
    tok1, tok2 = _login(client, e1), _login(client, e2)
    victim = client.get("/auth/sessions", headers=_h(tok2)).json()[0]["id"]
    assert client.post(f"/auth/sessions/{victim}/revoke", headers=_h(tok1)).status_code == 404
    assert client.get("/users", headers=_h(tok2)).status_code == 200      # untouched


def test_revoke_all_clears_session_list(client):
    email = _email()
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    tok = _login(client, email)
    assert len(client.get("/auth/sessions", headers=_h(tok)).json()) == 1
    assert client.post("/auth/sessions/revoke-all", headers=_h(tok)).status_code == 200
    lst = client.get("/auth/sessions", headers=_h(_login(client, email))).json()
    assert len(lst) == 1 and lst[0]["current"]            # only the fresh session


def test_change_password_keeps_current_session_listed(client):
    email = _email()
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    a = _login(client, email)
    b = _login(client, email)
    assert len(client.get("/auth/sessions", headers=_h(a)).json()) == 2
    r = client.post("/auth/change-password", headers=_h(a),
                    json={"current_password": PW, "new_password": "NewPassw0rd!"})
    assert r.status_code == 200, r.text
    fresh = r.json()["token"]
    assert client.get("/users", headers=_h(b)).status_code == 401         # other device dropped
    lst = client.get("/auth/sessions", headers=_h(fresh)).json()
    assert len(lst) == 1 and lst[0]["current"]            # this device continues, listed


def test_idle_timeout_signs_out_inactive_session(client):
    """A configured idle window signs out a session left inactive past it, even
    though the JWT hasn't hit its hard expiry."""
    import datetime as _dt
    email = _email()
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    tok = _login(client, email)
    with get_conn() as conn:
        sess_id = conn.execute(
            "SELECT id FROM sessions WHERE user_id=(SELECT id FROM users WHERE email=?)",
            (email,)).fetchone()["id"]
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('session_timeout_minutes','30')")
        stale = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=45)).replace(microsecond=0).isoformat()
        conn.execute("UPDATE sessions SET last_seen=? WHERE id=?", (stale, sess_id))
        conn.commit()
    try:
        assert client.get("/users", headers=_h(tok)).status_code == 401       # idle-timed-out
        assert client.get("/users", headers=_h(_login(client, email))).status_code == 200  # fresh login ok
    finally:
        with get_conn() as conn:                                              # restore default window
            conn.execute("DELETE FROM settings WHERE key='session_timeout_minutes'")
            conn.commit()
