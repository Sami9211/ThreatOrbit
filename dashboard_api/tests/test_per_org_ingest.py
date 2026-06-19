"""Per-org ingest context (multi-tenancy GA): ingested events - and the alerts
they trigger - land in the *ingesting* principal's workspace, so a tenant only
sees detections from its own logs. The synthetic background engine and the
deployment-level log listeners stay in the default workspace (documented).
Single-tenant installs are unchanged (everything resolves to org-default).
"""
import datetime
import json
import uuid

from dashboard_api import tenancy
from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn
from dashboard_api.tenancy import new_org

PW = "Passw0rd!123"


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


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
    return f"ing-{uuid.uuid4().hex[:8]}@x.com"


def _org(name):
    with get_conn() as conn:
        o = new_org(conn, name=name)
        conn.commit()
    return o["id"]


def test_ingested_events_and_ti_alert_land_in_ingesting_org(client, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Ingest Co")
    tag = uuid.uuid4().hex[:8]
    bad_ip = f"203.0.113.{(uuid.uuid4().int % 250) + 1}"
    with get_conn() as conn:
        email = _email(); _mkuser(conn, email, "analyst", org_b)
        # a malicious IOC so the ingested event raises a deterministic TI-match alert
        conn.execute(
            "INSERT INTO iocs (id,type,value,severity,confidence,threat_type,actor,source,status,"
            "org_id,first_seen,last_seen) VALUES (?, 'ip', ?, 'critical', 90, 'c2','APTx','CTI',"
            "'active','org-default',?,?)", (f"ioc-{tag}", bad_ip, _now(), _now()))
        conn.commit()
    h = _login(client, email)
    line = json.dumps({"event_type": "failed_login", "src_ip": bad_ip, "user": f"u-{tag}"})
    assert client.post("/siem/ingest", json={"lines": [line], "format": "json"}, headers=h).status_code == 200
    with get_conn() as conn:
        ev = conn.execute("SELECT org_id FROM events WHERE username=?", (f"u-{tag}",)).fetchone()
        al = conn.execute("SELECT org_id FROM alerts WHERE src_ip=? AND rule_id='R-TIMATCH'", (bad_ip,)).fetchone()
    assert ev and ev["org_id"] == org_b          # ingested event stamped with the tenant
    assert al and al["org_id"] == org_b          # the TI-match alert lands in the same tenant


def test_insert_alert_stamps_org():
    from dashboard_api.detections import _insert_alert
    with get_conn() as conn:
        aid = _insert_alert(conn, title="t", severity="low", risk=10, rule_name="r", org_id="org-zzz")
        default_aid = _insert_alert(conn, title="t2", severity="low", risk=10, rule_name="r")
        conn.commit()
        a = conn.execute("SELECT org_id FROM alerts WHERE id=?", (aid,)).fetchone()
        d = conn.execute("SELECT org_id FROM alerts WHERE id=?", (default_aid,)).fetchone()
    assert a["org_id"] == "org-zzz"              # detection writer propagates the event's org
    assert d["org_id"] == "org-default"          # default keeps single-tenant behaviour


def test_single_tenant_ingest_uses_default_org(client, auth):
    tag = uuid.uuid4().hex[:8]
    line = json.dumps({"event_type": "login_success", "src_ip": "10.0.0.5", "user": f"st-{tag}"})
    assert client.post("/siem/ingest", json={"lines": [line], "format": "json"}, headers=auth).status_code == 200
    with get_conn() as conn:
        ev = conn.execute("SELECT org_id FROM events WHERE username=?", (f"st-{tag}",)).fetchone()
    assert ev["org_id"] == "org-default"
