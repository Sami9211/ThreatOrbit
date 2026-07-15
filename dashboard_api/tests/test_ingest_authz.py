"""RBAC on write endpoints: a read-only principal must NOT be able to mutate
shared SOC data. Regression guard for the finding that several write endpoints
(ingest, detection-rule edit, sources, hunts, asset create, feed manage,
integration test) were gated only by `current_user` - so a read-scoped API key
(viewer role, zero capabilities) could inject forged alerts or even disable
detections. Each must now return 403 for a viewer and succeed for an analyst.
"""
import uuid

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


def _viewer(client):
    email = f"viewer-{uuid.uuid4().hex[:8]}@example.com"
    with get_conn() as conn:
        _mkuser(conn, email, "viewer")
        conn.commit()
    return _login(client, email)


def _analyst(client):
    email = f"analyst-{uuid.uuid4().hex[:8]}@example.com"
    with get_conn() as conn:
        _mkuser(conn, email, "analyst")
        conn.commit()
    return _login(client, email)


# (method, path, json-body) for each newly-gated write endpoint.
_WRITE_ENDPOINTS = [
    ("post", "/siem/ingest", {"lines": ["evil log line"], "format": "auto", "source": "t"}),
    ("post", "/siem/ingest/raw", "raw log line"),
    ("post", "/siem/sources", {"name": "x", "type": "syslog"}),
    ("post", "/siem/hunts", {"name": "h", "query": "test"}),
    ("post", "/assets", {"name": "h1", "type": "server", "value": "h1.test", "criticality": "low"}),
    ("post", "/assets/recompute-risk", {}),
    ("post", "/cti/hunts", {"name": "h"}),
    ("post", "/feeds", {"name": "f", "type": "opensource", "url": "https://example.com/f"}),
]


def test_viewer_denied_on_write_endpoints(client):
    hdr = _viewer(client)
    for method, path, body in _WRITE_ENDPOINTS:
        fn = getattr(client, method)
        r = fn(path, headers=hdr, content=body) if isinstance(body, str) \
            else fn(path, headers=hdr, json=body)
        assert r.status_code == 403, f"{method.upper()} {path}: viewer got {r.status_code}, expected 403"


def test_viewer_cannot_edit_detection_rules(client, auth):
    """The load-bearing case: a read-only principal must not be able to disable
    a detection rule (which would blind the SIEM)."""
    # An analyst-authored rule to target.
    ha = _analyst(client)
    created = client.post("/siem/rules", headers=ha, json={
        "name": f"rule-{uuid.uuid4().hex[:6]}", "severity": "high",
        "definition": {"conditions": [{"field": "event_type", "op": "equals",
                                        "value": "failed_login"}], "logic": "and"}})
    assert created.status_code == 201, created.text
    rule_id = created.json()["id"]
    hv = _viewer(client)
    r = client.patch(f"/siem/rules/{rule_id}", headers=hv, json={"status": "disabled"})
    assert r.status_code == 403


def test_analyst_allowed_on_write_endpoints(client):
    """The same endpoints must still work for an analyst (has the capability),
    so the fix locks out only under-privileged callers."""
    hdr = _analyst(client)
    ok = client.post("/siem/ingest", headers=hdr,
                     json={"lines": ["sshd: Failed password for root from 203.0.113.9"],
                           "format": "auto", "source": "authz-test"})
    assert ok.status_code == 200, ok.text
    a = client.post("/assets", headers=hdr, json={
        "name": f"h-{uuid.uuid4().hex[:6]}", "type": "server",
        "value": f"{uuid.uuid4().hex[:6]}.test", "criticality": "low"})
    assert a.status_code == 201, a.text
