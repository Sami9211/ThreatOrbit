"""Password screening (NIST SP 800-63B): every set-password path (register,
admin-create, change-password) rejects common/breached and self-referential
passwords, while strong passphrases - even ones containing a common word - pass.
"""
import uuid

import pytest

from dashboard_api import password_policy as pp
from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn


def test_policy_helper_screens_weak_accepts_strong():
    with pytest.raises(ValueError):
        pp.validate_password("short")                       # below the length floor
    with pytest.raises(ValueError):
        pp.validate_password("password")                    # common (exact)
    with pytest.raises(ValueError):
        pp.validate_password("PASSWORD")                    # common (case-insensitive)
    with pytest.raises(ValueError):
        pp.validate_password("a" * 300)                     # above the length ceiling
    with pytest.raises(ValueError):
        pp.validate_password("johnsmith", email="johnsmith@acme.io")   # is the email local-part
    with pytest.raises(ValueError):
        pp.validate_password("john smith", name="John Smith")          # is the account name
    # Strong inputs pass - including a passphrase that merely *contains* a word.
    pp.validate_password("correct horse battery staple")
    pp.validate_password("Sup3rSecret!2026", email="x@y.com", name="X")


def _mkuser(email):
    ph, salt = hash_password("Passw0rd!123")
    uid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
            "avatar_color,mfa_enabled,created_at,org_id) "
            "VALUES (?,?,?,'analyst','active',?,?, '#7A3CFF', 0, '2026-01-01T00:00:00+00:00', 'org-default')",
            (uid, email, "C", ph, salt))
        conn.commit()
    return uid


def test_register_rejects_common_password(client):
    email = f"weak-{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/auth/register", json={"name": "Weak", "email": email, "password": "password"})
    assert r.status_code == 400 and "common" in r.json()["error"].lower()
    # the same address with a strong password is accepted (the weak attempt made no user)
    ok = client.post("/auth/register", json={"name": "Strong", "email": email, "password": "Sup3rSecret!2026"})
    assert ok.status_code == 201


def test_admin_create_user_rejects_common(client, auth):
    email = f"weak2-{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/users", json={"email": email, "name": "W", "role": "analyst", "password": "12345678"},
                    headers=auth)
    assert r.status_code == 400


def test_change_password_rejects_common(client):
    email = f"chg-{uuid.uuid4().hex[:8]}@example.com"
    _mkuser(email)
    tok = client.post("/auth/login", json={"email": email, "password": "Passw0rd!123"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    bad = client.post("/auth/change-password", headers=h,
                      json={"current_password": "Passw0rd!123", "new_password": "qwerty123"})
    assert bad.status_code == 400
    good = client.post("/auth/change-password", headers=h,
                       json={"current_password": "Passw0rd!123", "new_password": "An0ther!Strong1"})
    assert good.status_code == 200
