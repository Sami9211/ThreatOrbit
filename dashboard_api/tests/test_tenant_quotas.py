"""Per-tenant quotas (MSSP/SaaS): a workspace can be capped on users and assets,
enforced at create time (HTTP 402). No-op when isolation is off, so single-tenant
installs are unaffected.
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


def _login(client, email):
    return {"Authorization": f"Bearer {client.post('/auth/login', json={'email': email, 'password': PW}).json()['token']}"}


def _email():
    return f"q-{uuid.uuid4().hex[:8]}@x.com"


def _org(name):
    with get_conn() as conn:
        o = new_org(conn, name=name)
        conn.commit()
    return o["id"]


def test_set_and_get_limits(client, auth):
    org_b = _org("Limits Co")
    r = client.put(f"/orgs/{org_b}/limits",
                   json={"maxUsers": 5, "maxAssets": 10, "retentionDays": 30}, headers=auth)
    assert r.status_code == 200
    got = client.get(f"/orgs/{org_b}/limits", headers=auth).json()
    assert got["users"]["limit"] == 5 and got["assets"]["limit"] == 10 and got["retentionDays"] == 30
    # 0 clears back to unlimited
    client.put(f"/orgs/{org_b}/limits", json={"maxUsers": 0}, headers=auth)
    assert client.get(f"/orgs/{org_b}/limits", headers=auth).json()["users"]["limit"] is None


def test_user_quota_enforced(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Seat Cap Co")
    with get_conn() as conn:
        admin_email = _email(); _mkuser(conn, admin_email, "admin", org_b)
        n = conn.execute("SELECT COUNT(*) c FROM users WHERE org_id=?", (org_b,)).fetchone()["c"]
        conn.commit()
    client.put(f"/orgs/{org_b}/limits", json={"maxUsers": n}, headers=auth)   # at cap
    ah = _login(client, admin_email)
    body = {"email": _email(), "name": "X", "role": "viewer", "password": PW}
    assert client.post("/users", json=body, headers=ah).status_code == 402
    client.put(f"/orgs/{org_b}/limits", json={"maxUsers": n + 1}, headers=auth)   # room for one
    assert client.post("/users", json={**body, "email": _email()}, headers=ah).status_code == 201


def test_asset_quota_enforced(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Asset Cap Co")
    with get_conn() as conn:
        uemail = _email(); _mkuser(conn, uemail, "analyst", org_b)
        conn.commit()
    client.put(f"/orgs/{org_b}/limits", json={"maxAssets": 1}, headers=auth)
    uh = _login(client, uemail)

    def asset():
        return {"name": f"a{uuid.uuid4().hex[:6]}", "type": "server",
                "value": f"10.0.0.{uuid.uuid4().int % 250}", "criticality": "low"}
    assert client.post("/assets", json=asset(), headers=uh).status_code == 201   # used 0 < 1
    assert client.post("/assets", json=asset(), headers=uh).status_code == 402   # used 1 >= 1


def _old_alert(conn, org_id, marker, days_old):
    import datetime as dt
    ts = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_old)).replace(microsecond=0).isoformat()
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
        "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
        "VALUES (?,?,?, 'low','new','undetermined','',10,'R','r','', '',1,0,?)",
        (f"{org_id}-{marker}", ts, marker, org_id))


def test_per_tenant_retention_window(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Short Retention Co")
    marker = "RET-" + uuid.uuid4().hex[:6]
    with get_conn() as conn:
        _old_alert(conn, org_b, marker, 20)            # 20 days old in org_b
        _old_alert(conn, "org-default", marker, 20)    # 20 days old in the default org
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('data_retention_days','90')")
        conn.commit()
    client.put(f"/orgs/{org_b}/limits", json={"retentionDays": 7}, headers=auth)
    out = client.post("/config/retention/enforce", headers=auth)
    assert out.status_code == 200
    with get_conn() as conn:
        b = conn.execute("SELECT COUNT(*) c FROM alerts WHERE id=?", (f"{org_b}-{marker}",)).fetchone()["c"]
        d = conn.execute("SELECT COUNT(*) c FROM alerts WHERE id=?", (f"org-default-{marker}",)).fetchone()["c"]
    assert b == 0    # purged under org_b's 7-day window
    assert d == 1    # kept under the default 90-day window


def test_quota_noop_when_single_tenant(monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('org_quota_users:org-default','1')")
        conn.commit()
        tenancy.enforce_quota(conn, "org-default", "users")     # must NOT raise (isolation off)
        conn.execute("DELETE FROM settings WHERE key='org_quota_users:org-default'")
        conn.commit()
