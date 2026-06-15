"""MFA recovery-code tests: a lost authenticator must not be a lockout.

Enrol → verify (codes issued once) → login with TOTP and with a one-time
recovery code (consumed) → regenerate invalidates the old set → disable clears
them. Plus the pure helpers.
"""
import uuid

from dashboard_api import mfa
from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn

PW = "Passw0rd!123"


def _mkuser(conn, email):
    ph, salt = hash_password(PW)
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,created_at,org_id) "
        "VALUES (?,?,?,'analyst','active',?,?, '#7A3CFF', 0, '2026-01-01T00:00:00+00:00', 'org-default')",
        (uid, email, "U", ph, salt))
    return uid


def _login(client, email, code=None):
    body = {"email": email, "password": PW}
    if code is not None:
        body["code"] = code
    return client.post("/auth/login", json=body)


def _enrol(client):
    email = f"mfa-{uuid.uuid4().hex[:8]}@example.com"
    with get_conn() as conn:
        _mkuser(conn, email)
        conn.commit()
    h = {"Authorization": f"Bearer {_login(client, email).json()['token']}"}
    secret = client.post("/auth/mfa/enroll", headers=h).json()["secret"]
    verify = client.post("/auth/mfa/verify", headers=h, json={"code": mfa.totp_code(secret)}).json()
    return email, h, secret, verify


def test_recovery_codes_issued_on_enrol_and_consumed_at_login(client):
    email, h, secret, verify = _enrol(client)
    codes = verify["recoveryCodes"]
    assert verify["enabled"] is True and len(codes) == 10
    assert client.get("/auth/mfa", headers=h).json()["recoveryCodesRemaining"] == 10

    assert _login(client, email).status_code == 401                       # MFA required
    assert _login(client, email, code=mfa.totp_code(secret)).status_code == 200   # TOTP works

    # a recovery code logs in AND is consumed (one-time)
    assert _login(client, email, code=codes[0]).status_code == 200
    assert client.get("/auth/mfa", headers=h).json()["recoveryCodesRemaining"] == 9
    assert _login(client, email, code=codes[0]).status_code == 401        # already used
    assert _login(client, email, code=codes[1]).status_code == 200        # a different one still works


def test_regenerate_invalidates_old_set(client):
    email, h, secret, verify = _enrol(client)
    old = verify["recoveryCodes"]
    new = client.post("/auth/mfa/recovery-codes", headers=h,
                      json={"code": mfa.totp_code(secret)}).json()["recoveryCodes"]
    assert len(new) == 10 and set(new).isdisjoint(old)
    assert _login(client, email, code=old[0]).status_code == 401          # old set dead
    assert _login(client, email, code=new[0]).status_code == 200          # new set live


def test_disable_clears_recovery_codes(client):
    email, h, secret, _ = _enrol(client)
    assert client.post("/auth/mfa/disable", headers=h,
                       json={"code": mfa.totp_code(secret)}).json()["enabled"] is False
    # MFA off → password alone logs in again
    assert _login(client, email).status_code == 200


def test_recovery_helpers():
    codes = mfa.new_recovery_codes(5)
    assert len(codes) == 5 and all("-" in c for c in codes)
    hashes = [mfa.hash_recovery_code(c) for c in codes]
    rem = mfa.consume_recovery_code(hashes, codes[0])
    assert rem is not None and len(rem) == 4
    assert mfa.consume_recovery_code(hashes, "nope-nope") is None
    # tolerant of formatting (no hyphen / uppercase / spaces)
    assert mfa.consume_recovery_code(hashes, f" {codes[1].replace('-', '').upper()} ") is not None
