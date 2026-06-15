"""GDPR data-subject tooling tests: export (self + admin) and the right to be
forgotten (anonymisation) - PII replaced, identity references rewritten, login
disabled, permission-gated, and self-erasure refused.
"""
import uuid
from datetime import datetime, timezone

from dashboard_api.auth import hash_password
from dashboard_api.db import audit, get_conn

PW = "Passw0rd!123"


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _make_user(conn, email, *, role="analyst", mfa=True):
    ph, salt = hash_password(PW)
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,mfa_secret,slack_webhook,created_at,org_id) "
        "VALUES (?,?,?,?, 'active', ?,?, '#7A3CFF', ?, ?, ?, ?, 'org-default')",
        (uid, email, "Test Subject", role, ph, salt, 1 if mfa else 0,
         "MFASECRET" if mfa else None, "https://hooks.slack/x", _now()))
    return uid


def test_export_self(client, auth):
    body = client.get("/privacy/me", headers=auth).json()
    assert body["subject"] == "admin@threatorbit.space"
    assert body["profile"]["email"] == "admin@threatorbit.space"
    assert "auditTrail" in body and "references" in body


def test_export_subject_as_admin(client, auth):
    email = f"dsar-{uuid.uuid4().hex[:8]}@example.com"
    with get_conn() as conn:
        uid = _make_user(conn, email)
        audit(conn, email, "test.activity", "x", "did a thing")
        conn.commit()
    body = client.get(f"/privacy/export/{uid}", headers=auth).json()
    assert body["subject"] == email
    assert body["profile"]["slack_webhook_configured"] is True   # secret not leaked, presence noted
    assert any(e["action"] == "test.activity" for e in body["auditTrail"])
    assert "audit_log.actor" in body["references"]


def test_erase_anonymises_and_disables_login(client, auth):
    email = f"forget-{uuid.uuid4().hex[:8]}@example.com"
    with get_conn() as conn:
        uid = _make_user(conn, email, mfa=True)
        audit(conn, email, "test.activity", "x", "trace")
        conn.commit()

    res = client.post(f"/privacy/erase/{uid}", headers=auth)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["subject"] == email and body["anonymizedTo"].endswith("@anonymized.invalid")
    assert body["rewritten"]["audit_log.actor"] >= 1

    with get_conn() as conn:
        row = conn.execute(
            "SELECT email,name,status,mfa_enabled,mfa_secret,slack_webhook FROM users WHERE id=?",
            (uid,)).fetchone()
        assert row["email"] != email and row["name"] == "Erased user"
        assert row["status"] == "disabled" and row["mfa_enabled"] == 0
        assert row["mfa_secret"] is None and row["slack_webhook"] is None
        # the subject's old email is gone from the audit trail (anonymised, not orphaned)
        assert conn.execute("SELECT COUNT(*) c FROM audit_log WHERE actor=?", (email,)).fetchone()["c"] == 0

    # the old identity can no longer authenticate
    login = client.post("/auth/login", json={"email": email, "password": PW})
    assert login.status_code == 401


def test_erase_requires_users_delete_permission(client):
    # an analyst (no users.delete) is forbidden
    email = f"analyst-{uuid.uuid4().hex[:8]}@example.com"
    with get_conn() as conn:
        _make_user(conn, email, role="analyst", mfa=False)
        victim = _make_user(conn, f"victim-{uuid.uuid4().hex[:8]}@example.com", mfa=False)
        conn.commit()
    tok = client.post("/auth/login", json={"email": email, "password": PW}).json()["token"]
    r = client.post(f"/privacy/erase/{victim}", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_cannot_self_erase(client, auth):
    me = client.get("/privacy/me", headers=auth).json()["profile"]["id"]
    assert client.post(f"/privacy/erase/{me}", headers=auth).status_code == 400
