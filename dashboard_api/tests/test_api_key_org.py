"""Org-scoped API keys (multi-tenancy): a key can be bound to a workspace, so a
non-interactive collector authenticating with it ingests into that tenant. Keys
default to the creator's workspace; single-tenant installs are unchanged
(everything is the default org).
"""
import json
import uuid

from dashboard_api import tenancy
from dashboard_api.db import get_conn
from dashboard_api.tenancy import new_org


def _org(name):
    with get_conn() as conn:
        o = new_org(conn, name=name)
        conn.commit()
    return o["id"]


def test_api_key_defaults_to_creator_org(client, auth):
    r = client.post("/config/api-keys", json={"name": "default-key", "scope": "read"}, headers=auth)
    assert r.status_code == 201 and r.json()["orgId"] == "org-default"


def test_api_key_org_must_exist(client, auth):
    r = client.post("/config/api-keys", json={"name": "bad", "scope": "read", "orgId": "org-nope"}, headers=auth)
    assert r.status_code == 404


def test_org_scoped_api_key_ingests_per_tenant(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b = _org("Collector Co")
    r = client.post("/config/api-keys",
                    json={"name": "collector", "scope": "write", "orgId": org_b}, headers=auth)
    assert r.status_code == 201 and r.json()["orgId"] == org_b
    key = r.json()["secret"]

    tag = uuid.uuid4().hex[:8]
    line = json.dumps({"event_type": "login_success", "src_ip": "10.0.0.9", "user": f"k-{tag}"})
    ri = client.post("/siem/ingest", json={"lines": [line], "format": "json"},
                     headers={"X-API-Key": key})
    assert ri.status_code == 200
    with get_conn() as conn:
        ev = conn.execute("SELECT org_id FROM events WHERE username=?", (f"k-{tag}",)).fetchone()
    assert ev and ev["org_id"] == org_b      # the collector's events land in its tenant
