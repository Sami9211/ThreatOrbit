"""Per-workspace role assignment (scale-grade RBAC for MSSP/SaaS).

A user can be granted a distinct role *within* another workspace. Under
multi-tenancy, acting in that workspace via the `X-Org-Id` header takes the
granted role AND data scope there; requesting a workspace you're not a member of
is a 403. Single-tenant installs ignore the header entirely (unchanged).
"""
import uuid

from dashboard_api import permissions, tenancy
from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn
from dashboard_api.tenancy import new_org

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
    return f"ws-{uuid.uuid4().hex[:8]}@example.com"


def _org(name):
    with get_conn() as conn:
        o = new_org(conn, name=name)
        conn.commit()
    return o["id"]


def _grant(uid, org_id, role):
    with get_conn() as conn:
        conn.execute("INSERT INTO user_org_roles (user_id,org_id,role,granted_by,granted_at) "
                     "VALUES (?,?,?,?,?)", (uid, org_id, role, "admin", "2026-01-01T00:00:00+00:00"))
        conn.commit()


def test_grant_api_lists_and_resolves(client, auth):
    org_b = _org("Customer B")
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "viewer")
        conn.commit()
    r = client.put(f"/orgs/{org_b}/members/{uid}", json={"role": "analyst"}, headers=auth)
    assert r.status_code == 200 and r.json()["role"] == "analyst"
    assert permissions.workspace_role(uid, org_b) == "analyst"
    assert permissions.workspace_role(uid, "org-default") == "viewer"   # home → base
    members = client.get(f"/orgs/{org_b}/members", headers=auth).json()["members"]
    assert any(m["user_id"] == uid and m["role"] == "analyst" and m["source"] == "grant" for m in members)


def test_acting_org_switches_role_and_scope(client, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Acting Co")
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "viewer")
        conn.commit()
    _grant(uid, org_b, "manager")
    h = _login(client, email)
    me = client.get("/auth/me", headers=h).json()
    assert me["role"] == "viewer" and me["org_id"] == "org-default"
    me2 = client.get("/auth/me", headers={**h, "X-Org-Id": org_b}).json()
    assert me2["role"] == "manager" and me2["org_id"] == org_b


def test_acting_in_non_member_org_is_403(client, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_x = _org("Forbidden Co")
    with get_conn() as conn:
        email = _email(); _mkuser(conn, email, "analyst")
        conn.commit()
    h = _login(client, email)
    assert client.get("/auth/me", headers={**h, "X-Org-Id": org_x}).status_code == 403


def test_acting_org_enforced_in_require_perm(client, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Perm Co")
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "viewer")   # no siem.write at home
        conn.commit()
    _grant(uid, org_b, "analyst")                                # analyst → siem.write in org_b
    h = _login(client, email)
    payload = {"title": "ws-role alert", "severity": "low"}
    assert client.post("/siem/alerts", json=payload, headers=h).status_code == 403
    assert client.post("/siem/alerts", json=payload, headers={**h, "X-Org-Id": org_b}).status_code == 201


def test_no_privilege_escalation_on_grant(client):
    org_b = _org("Esc Co")
    with get_conn() as conn:
        memail = _email(); _mkuser(conn, memail, "manager")
        temail = _email(); tuid = _mkuser(conn, temail, "viewer")
        conn.commit()
    mh = _login(client, memail)
    # a manager lacks users.delete/license.manage → can't grant 'admin'
    assert client.put(f"/orgs/{org_b}/members/{tuid}", json={"role": "admin"}, headers=mh).status_code == 403
    # but can grant a role within their own privilege
    assert client.put(f"/orgs/{org_b}/members/{tuid}", json={"role": "analyst"}, headers=mh).status_code == 200


def test_remove_grant_revokes_access(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Revoke Co")
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "viewer")
        conn.commit()
    client.put(f"/orgs/{org_b}/members/{uid}", json={"role": "analyst"}, headers=auth)
    assert permissions.workspace_role(uid, org_b) == "analyst"
    assert client.delete(f"/orgs/{org_b}/members/{uid}", headers=auth).status_code == 200
    assert permissions.workspace_role(uid, org_b) is None
    h = _login(client, email)
    assert client.get("/auth/me", headers={**h, "X-Org-Id": org_b}).status_code == 403


def test_single_tenant_ignores_x_org_id(client, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
    org_b = _org("ST Co")
    with get_conn() as conn:
        email = _email(); uid = _mkuser(conn, email, "viewer")
        conn.commit()
    _grant(uid, org_b, "manager")
    h = _login(client, email)
    me = client.get("/auth/me", headers={**h, "X-Org-Id": org_b}).json()
    assert me["org_id"] == "org-default" and me["role"] == "viewer"     # header ignored off-MT
