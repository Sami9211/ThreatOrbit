"""Custom RBAC role tests.

Built-in roles stay code-authoritative (the other 230+ tests exercise them);
here we prove custom roles resolve their capabilities from the DB, that
require_perm honours them (grant AND deny) on the load-bearing path, that you
can't escalate by granting a capability you don't hold, that built-ins are
protected, and the delete-while-assigned guard.
"""
import uuid

from dashboard_api import permissions
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


def _email():
    return f"u-{uuid.uuid4().hex[:8]}@example.com"


def test_list_includes_builtins_and_catalogue(client, auth):
    body = client.get("/roles", headers=auth).json()
    ids = {r["id"] for r in body["roles"]}
    assert {"admin", "manager", "analyst", "viewer"} <= ids
    assert "siem.write" in body["capabilities"]
    assert all(r["builtIn"] for r in body["roles"] if r["id"] == "admin")


def test_create_custom_role_resolves_perms_from_db(client, auth):
    rid = f"soc-tier1-{uuid.uuid4().hex[:6]}"
    r = client.post("/roles", headers=auth, json={
        "id": rid, "name": "SOC Tier 1", "capabilities": ["siem.write", "soar.write"]})
    assert r.status_code == 201, r.text
    assert permissions.has_perm(rid, "siem.write") is True
    assert permissions.has_perm(rid, "config.manage") is False
    # built-ins unaffected
    assert permissions.has_perm("admin", "users.delete") is True
    assert permissions.has_perm("viewer", "siem.write") is False


def test_require_perm_honours_custom_role_grant_and_deny(client, auth):
    with_um = f"rolemgr-{uuid.uuid4().hex[:6]}"
    client.post("/roles", headers=auth, json={"id": with_um, "name": "RM", "capabilities": ["users.manage"]})
    without = f"readonly-{uuid.uuid4().hex[:6]}"
    client.post("/roles", headers=auth, json={"id": without, "name": "RO", "capabilities": ["cti.write"]})
    e1, e2 = _email(), _email()
    with get_conn() as conn:
        _mkuser(conn, e1, with_um)
        _mkuser(conn, e2, without)
        conn.commit()
    # /roles requires users.manage -> granted role can, the other is denied
    assert client.get("/roles", headers=_login(client, e1)).status_code == 200
    assert client.get("/roles", headers=_login(client, e2)).status_code == 403


def test_no_privilege_escalation(client, auth):
    # a manager lacks users.delete, so cannot mint a role granting it
    memail = _email()
    with get_conn() as conn:
        _mkuser(conn, memail, "manager")
        conn.commit()
    r = client.post("/roles", headers=_login(client, memail), json={
        "id": f"superx-{uuid.uuid4().hex[:6]}", "name": "Super", "capabilities": ["users.delete"]})
    assert r.status_code == 403


def test_builtins_are_protected(client, auth):
    assert client.patch("/roles/admin", headers=auth,
                        json={"name": "x", "capabilities": []}).status_code == 400
    assert client.delete("/roles/viewer", headers=auth).status_code == 400


def test_unknown_capability_rejected(client, auth):
    r = client.post("/roles", headers=auth, json={
        "id": f"bad-{uuid.uuid4().hex[:6]}", "name": "Bad", "capabilities": ["does.notexist"]})
    assert r.status_code == 400


def test_delete_refused_while_assigned_then_succeeds(client, auth):
    rid = f"temp-{uuid.uuid4().hex[:6]}"
    client.post("/roles", headers=auth, json={"id": rid, "name": "Temp", "capabilities": ["cti.write"]})
    email = _email()
    with get_conn() as conn:
        uid = _mkuser(conn, email, rid)
        conn.commit()
    assert client.delete(f"/roles/{rid}", headers=auth).status_code == 409
    client.patch(f"/users/{uid}", headers=auth, json={"role": "viewer"})
    assert client.delete(f"/roles/{rid}", headers=auth).status_code == 204
