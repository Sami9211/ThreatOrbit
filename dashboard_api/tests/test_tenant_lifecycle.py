"""Tenant lifecycle (MSSP/SaaS offboarding): suspend, export, delete-with-purge.

Suspending a workspace blocks its users from auth (under isolation); the default
workspace can't be suspended or deleted; export dumps a tenant's data (secrets
scrubbed); delete requires a prior suspend and then hard-purges every row.
"""
import uuid

from dashboard_api import tenancy
from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn
from dashboard_api.tenancy import new_org

PW = "Passw0rd!123"


def _mkuser(conn, email, role="analyst", org_id="org-default"):
    ph, salt = hash_password(PW)
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,created_at,org_id) "
        "VALUES (?,?,?,?, 'active', ?,?, '#7A3CFF', 0, '2026-01-01T00:00:00+00:00', ?)",
        (uid, email, "U", role, ph, salt, org_id))
    return uid


def _alert(conn, org_id, title):
    aid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
        "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
        "VALUES (?, '2026-01-01T00:00:00+00:00', ?, 'low','new','undetermined','',10,"
        "'R','r','', '',1,0,?)", (aid, title, org_id))
    return aid


def _login(client, email):
    return client.post("/auth/login", json={"email": email, "password": PW})


def _org(name):
    with get_conn() as conn:
        o = new_org(conn, name=name)
        conn.commit()
    return o["id"]


def test_suspend_blocks_auth(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Tenant A")
    with get_conn() as conn:
        email = f"t-{uuid.uuid4().hex[:8]}@x.com"; _mkuser(conn, email, org_id=org_b)
        conn.commit()
    # works before suspension; capture a live token too
    r = _login(client, email)
    assert r.status_code == 200
    token = r.json()["token"]
    # suspend the workspace
    assert client.patch(f"/orgs/{org_b}", json={"status": "suspended"}, headers=auth).status_code == 200
    # new logins blocked
    assert _login(client, email).status_code == 403
    # the already-issued token is blocked on the next request
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    # resume restores access
    assert client.patch(f"/orgs/{org_b}", json={"status": "active"}, headers=auth).status_code == 200
    assert _login(client, email).status_code == 200


def test_default_workspace_cannot_be_suspended(client, auth):
    assert client.patch("/orgs/org-default", json={"status": "suspended"}, headers=auth).status_code == 400


def test_export_workspace_dumps_data_without_secrets(client, auth):
    org_b = _org("Export Co")
    with get_conn() as conn:
        email = f"e-{uuid.uuid4().hex[:8]}@x.com"; _mkuser(conn, email, org_id=org_b)
        _alert(conn, org_b, "exported alert")
        conn.commit()
    data = client.get(f"/orgs/{org_b}/export", headers=auth).json()
    assert data["orgId"] == org_b
    assert any(a["title"] == "exported alert" for a in data["tables"]["alerts"])
    u = data["tables"]["users"][0]
    assert u["email"] == email and "password_hash" not in u and "mfa_secret" not in u


def test_delete_requires_suspend_then_purges(client, auth):
    org_b = _org("Doomed Co")
    with get_conn() as conn:
        email = f"d-{uuid.uuid4().hex[:8]}@x.com"; uid = _mkuser(conn, email, org_id=org_b)
        _alert(conn, org_b, "doomed alert")
        conn.commit()
    # can't delete while active
    assert client.delete(f"/orgs/{org_b}", headers=auth).status_code == 409
    # suspend, then delete purges everything
    client.patch(f"/orgs/{org_b}", json={"status": "suspended"}, headers=auth)
    r = client.delete(f"/orgs/{org_b}", headers=auth)
    assert r.status_code == 200 and r.json()["deleted"] is True
    with get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) c FROM alerts WHERE org_id=?", (org_b,)).fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) c FROM users WHERE id=?", (uid,)).fetchone()["c"] == 0
        assert conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_b,)).fetchone() is None


def test_default_workspace_cannot_be_deleted(client, auth):
    assert client.delete("/orgs/org-default", headers=auth).status_code == 400
