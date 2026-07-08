"""Organization mode (simple|power) tests.

The mode is a UI-surfacing preference: GET is open to any authenticated user
(the frontend needs it to draw the nav), PUT is config.manage. It never
touches RBAC - which is exactly what the viewer/analyst tests pin down.
"""
import uuid

import pytest

from dashboard_api import modes
from dashboard_api.auth import hash_password
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


@pytest.fixture()
def _reset_mode():
    """Remove any persisted mode so each test observes the true default,
    and leave no residue for the rest of the suite."""
    def wipe():
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key=? OR key LIKE ?",
                         (modes.SETTING_KEY, modes.SETTING_KEY + ":%"))
            conn.commit()
    wipe()
    yield
    wipe()


def test_default_mode_is_power(client, auth, _reset_mode):
    r = client.get("/config/mode", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "power"
    assert body["features"] == sorted(modes.FEATURES)
    assert len(body["features"]) > 0


def test_put_simple_persists_and_get_reflects_it(client, auth, _reset_mode):
    r = client.put("/config/mode", headers=auth, json={"mode": "simple"})
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "simple"
    # persisted via the settings table (survives across requests)
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?",
                           (modes.SETTING_KEY,)).fetchone()
    assert row is not None and row["value"] == "simple"
    body = client.get("/config/mode", headers=auth).json()
    assert body["mode"] == "simple"
    assert body["features"] == sorted(modes.MODES["simple"])
    # and flipping back to power restores the full surface
    r = client.put("/config/mode", headers=auth, json={"mode": "power"})
    assert r.status_code == 200
    assert client.get("/config/mode", headers=auth).json()["mode"] == "power"


def test_invalid_mode_rejected(client, auth, _reset_mode):
    for bad in ("turbo", "", "SIMPLEST"):
        r = client.put("/config/mode", headers=auth, json={"mode": bad})
        assert r.status_code == 400, f"{bad!r} -> {r.status_code}"
    # nothing was persisted by the rejected writes
    assert client.get("/config/mode", headers=auth).json()["mode"] == "power"


def test_viewer_and_analyst_can_get_but_not_put(client, auth, _reset_mode):
    ve, ae = (f"u-{uuid.uuid4().hex[:8]}@example.com" for _ in range(2))
    with get_conn() as conn:
        _mkuser(conn, ve, "viewer")
        _mkuser(conn, ae, "analyst")
        conn.commit()
    for email in (ve, ae):
        hdrs = _login(client, email)
        r = client.get("/config/mode", headers=hdrs)
        assert r.status_code == 200, r.text
        assert r.json()["mode"] == "power"
        assert client.put("/config/mode", headers=hdrs,
                          json={"mode": "simple"}).status_code == 403
    # the denied PUTs changed nothing
    assert client.get("/config/mode", headers=auth).json()["mode"] == "power"


def test_get_requires_auth(client, _reset_mode):
    assert client.get("/config/mode").status_code in (401, 403)


def test_simple_is_nonempty_strict_subset_of_power():
    simple = set(modes.enabled_features("simple"))
    power = set(modes.enabled_features("power"))
    assert simple and power
    assert simple < power                       # strict subset
    assert power == set(modes.FEATURES)         # power is the full catalogue
    # every advertised feature id is documented in the catalogue
    assert simple <= set(modes.FEATURES)


def test_helpers_fail_open_to_power():
    # unrecognised persisted value or mode name never hides the full UI
    assert modes.enabled_features("garbage") == sorted(modes.FEATURES)
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
                     (modes.SETTING_KEY, "banana"))
        conn.commit()
        assert modes.effective_mode(conn, "org-default") == "power"
        conn.execute("DELETE FROM settings WHERE key=?", (modes.SETTING_KEY,))
        conn.commit()
