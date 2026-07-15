"""End-to-end multi-tenant validation - the gate before flipping
DASHBOARD_MULTI_TENANT on by default for MSSP builds.

Unlike the per-surface scope tests (search/stream/ingest/quotas/lifecycle),
this exercises the whole tenant journey through the REAL API: a second
workspace with its own admin creates data in every core domain
(SIEM alert, SOAR case, asset, CTI indicators), then we prove:

  * every creation stamps the creator's workspace (no row leaks into the
    deployment default),
  * list endpoints and the overview aggregates show only the caller's
    workspace,
  * id-addressed detail reads AND mutations 404 across workspaces,
  * bulk IOC import dedup is per-workspace - one tenant's indicators are
    neither an existence oracle nor a silent drop for another tenant's import.
"""
import uuid

from dashboard_api import tenancy
from dashboard_api.auth import hash_password
from dashboard_api.db import get_conn
from dashboard_api.tenancy import new_org

PW = "Passw0rd!123"


def _mkuser(conn, email, role="admin", org_id="org-default"):
    ph, salt = hash_password(PW)
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
        "avatar_color,mfa_enabled,created_at,org_id) "
        "VALUES (?,?,?,?, 'active', ?,?, '#7A3CFF', 0, '2026-01-01T00:00:00+00:00', ?)",
        (uid, email, "U", role, ph, salt, org_id))
    return uid


def _org(name):
    with get_conn() as conn:
        o = new_org(conn, name=name)
        conn.commit()
    return o["id"]


def _login(client, email):
    r = client.post("/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _second_workspace(client):
    org_b = _org(f"Beta-{uuid.uuid4().hex[:6]}")
    email = f"e2e-{uuid.uuid4().hex[:8]}@beta.test"
    with get_conn() as conn:
        _mkuser(conn, email, role="admin", org_id=org_b)
        conn.commit()
    return org_b, _login(client, email)


def _db_org_of(table, id_col, id_val):
    with get_conn() as conn:
        row = conn.execute(f"SELECT org_id FROM {table} WHERE {id_col}=?", (id_val,)).fetchone()
    assert row is not None, f"{table} row {id_val} missing"
    return row["org_id"]


def test_tenant_journey_create_stamp_list_detail_mutate(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b, hb = _second_workspace(client)
    mk = f"E2E-{uuid.uuid4().hex[:8]}"

    # -- Tenant B creates data in every core domain through the API ----------
    alert = client.post("/siem/alerts", headers=hb, json={
        "title": f"{mk} suspicious login", "severity": "high",
        "rule_name": "E2E manual"}).json()
    case = client.post("/soar/cases", headers=hb, json={
        "title": f"{mk} intrusion case", "severity": "high"}).json()
    asset = client.post("/assets", headers=hb, json={
        "name": f"{mk}-host", "type": "server", "value": f"{mk.lower()}.beta.test",
        "criticality": "high"}).json()
    imp = client.post("/cti/iocs/import", headers=hb, json={
        "indicators": [{"type": "domain", "value": f"{mk.lower()}.evil.test"}],
        "source": "e2e", "severity": "high", "threat_type": "c2",
        "confidence": 80}).json()
    assert imp["imported"] == 1

    # -- Every creation stamped the creator's workspace ----------------------
    assert _db_org_of("alerts", "id", alert["id"]) == org_b
    assert _db_org_of("cases", "id", case["id"]) == org_b
    assert _db_org_of("assets", "id", asset["id"]) == org_b
    with get_conn() as conn:
        row = conn.execute("SELECT org_id FROM iocs WHERE value=?",
                           (f"{mk.lower()}.evil.test",)).fetchone()
    assert row and row["org_id"] == org_b

    # -- Own workspace sees its data through every list endpoint -------------
    assert any(a["id"] == alert["id"] for a in
               client.get(f"/siem/alerts?q={mk}", headers=hb).json()["items"])
    assert any(c["id"] == case["id"] for c in
               client.get("/soar/cases", headers=hb).json())
    assert any(a["id"] == asset["id"] for a in
               client.get(f"/assets?q={mk.lower()}", headers=hb).json()["items"])
    assert any(i["value"] == f"{mk.lower()}.evil.test" for i in
               client.get(f"/cti/iocs?q={mk.lower()}", headers=hb).json()["items"])

    # -- The other workspace's lists never surface them ----------------------
    assert client.get(f"/siem/alerts?q={mk}", headers=auth).json()["items"] == []
    assert not any(c["id"] == case["id"] for c in
                   client.get("/soar/cases", headers=auth).json())
    assert client.get(f"/assets?q={mk.lower()}", headers=auth).json()["items"] == []
    assert client.get(f"/cti/iocs?q={mk.lower()}", headers=auth).json()["items"] == []

    # -- Id-addressed reads 404 across workspaces (no detail leak) -----------
    assert client.get(f"/siem/alerts/{alert['id']}", headers=auth).status_code == 404
    assert client.get(f"/soar/cases/{case['id']}", headers=auth).status_code == 404
    assert client.get(f"/assets/{asset['id']}", headers=auth).status_code == 404
    # …while the owning workspace still reads them fine.
    assert client.get(f"/siem/alerts/{alert['id']}", headers=hb).status_code == 200
    assert client.get(f"/soar/cases/{case['id']}", headers=hb).status_code == 200
    assert client.get(f"/assets/{asset['id']}", headers=hb).status_code == 200

    # -- Mutations across workspaces 404 and change nothing ------------------
    r = client.patch(f"/siem/alerts/{alert['id']}", headers=auth,
                     json={"status": "resolved"})
    assert r.status_code == 404
    assert client.get(f"/siem/alerts/{alert['id']}", headers=hb).json()["status"] == "new"
    assert client.patch(f"/soar/cases/{case['id']}", headers=auth,
                        json={"status": "investigating"}).status_code == 404
    assert client.delete(f"/assets/{asset['id']}", headers=auth).status_code == 404
    # …and the owner can still mutate.
    assert client.patch(f"/siem/alerts/{alert['id']}", headers=hb,
                        json={"status": "investigating"}).status_code == 200


def test_overview_aggregates_are_tenant_scoped(client, auth, monkeypatch):
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b, hb = _second_workspace(client)
    before = client.get("/overview/kpis", headers=auth).json()

    mk = uuid.uuid4().hex[:8]
    imp = client.post("/cti/iocs/import", headers=hb, json={
        "indicators": [{"type": "domain", "value": f"kpi-{mk}.evil.test"}],
        "source": "e2e", "severity": "high", "threat_type": "c2",
        "confidence": 80}).json()
    assert imp["imported"] == 1
    client.post("/siem/alerts", headers=hb, json={
        "title": f"kpi-{mk} beacon", "severity": "critical", "rule_name": "E2E"})

    # Tenant B's numbers move; the default workspace's numbers do not.
    b = client.get("/overview/kpis", headers=hb).json()
    assert b["iocs"] >= 1 and b["threats"] >= 1
    after = client.get("/overview/kpis", headers=auth).json()
    assert after["iocs"] == before["iocs"]
    assert after["threats"] == before["threats"]


def test_ueba_entities_are_tenant_scoped(client, auth, monkeypatch):
    """UEBA aggregated across ALL tenants before: one workspace could see
    another's usernames/hostnames (and probe alert titles via /entities/detail).
    Both endpoints now scope to the caller's workspace."""
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b, hb = _second_workspace(client)
    host = f"beta-host-{uuid.uuid4().hex[:8]}"
    r = client.post("/siem/alerts", headers=hb, json={
        "title": "beta ueba", "severity": "critical", "rule_name": "E2E",
        "hostname": host})
    assert r.status_code in (200, 201), r.text

    # B sees its entity; the default workspace does not.
    b_vals = [e["value"] for e in client.get(
        "/siem/entities?type=host&limit=100", headers=hb).json()["entities"]]
    assert host in b_vals
    a_vals = [e["value"] for e in client.get(
        "/siem/entities?type=host&limit=100", headers=auth).json()["entities"]]
    assert host not in a_vals

    # Probing B's hostname from the default workspace yields nothing.
    d = client.get(f"/siem/entities/detail?type=host&value={host}", headers=auth).json()
    assert d["alertCount"] == 0
    d_b = client.get(f"/siem/entities/detail?type=host&value={host}", headers=hb).json()
    assert d_b["alertCount"] == 1


def test_ioc_import_dedup_is_per_workspace(client, auth, monkeypatch):
    """One tenant's indicators must be neither an existence oracle nor a silent
    drop for another tenant's import of the same value."""
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    _, hb = _second_workspace(client)
    val = f"dedup-{uuid.uuid4().hex[:8]}.evil.test"
    body = {"indicators": [{"type": "domain", "value": val}],
            "source": "e2e", "severity": "medium", "threat_type": "phishing",
            "confidence": 60}

    first = client.post("/cti/iocs/import", headers=auth, json=body).json()
    assert first["imported"] == 1
    # Same value, different workspace → still imports (scoped dedup)…
    second = client.post("/cti/iocs/import", headers=hb, json=body).json()
    assert second["imported"] == 1 and second["duplicates"] == 0
    # …but a true duplicate within the same workspace is still caught.
    third = client.post("/cti/iocs/import", headers=hb, json=body).json()
    assert third["imported"] == 0 and third["duplicates"] == 1


def test_sub_resource_reads_are_cross_org_guarded(client, auth, monkeypatch):
    """Id-addressed sub-resource GETs (case/related, asset vulns/activity, report
    read/misp, case attribution, ioc enrichment) must 404 across workspaces -
    the MSSP gap where a guessable id leaked another tenant's linked data."""
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    org_b, hb = _second_workspace(client)
    mk = f"SUB-{uuid.uuid4().hex[:8]}"

    # Workspace B creates the parent records.
    case = client.post("/soar/cases", headers=hb, json={
        "title": f"{mk} case", "severity": "high"}).json()
    asset = client.post("/assets", headers=hb, json={
        "name": f"{mk}-host", "type": "server", "value": f"{mk.lower()}.beta.test",
        "criticality": "high"}).json()
    report = client.post("/cti/reports", headers=hb, json={
        "title": f"{mk} report", "summary": "s"}).json()
    client.post("/cti/iocs/import", headers=hb, json={
        "indicators": [{"type": "domain", "value": f"{mk.lower()}.evil.test"}],
        "source": "e2e", "severity": "high", "threat_type": "c2", "confidence": 80})
    with get_conn() as conn:
        ioc_id = conn.execute("SELECT id FROM iocs WHERE value=?",
                              (f"{mk.lower()}.evil.test",)).fetchone()["id"]

    # The other workspace (org-default admin) gets 404 on every sub-resource…
    denied = [
        ("get", f"/soar/cases/{case['id']}/related"),
        ("get", f"/assets/{asset['id']}/vulns"),
        ("get", f"/assets/{asset['id']}/activity"),
        ("get", f"/cti/reports/{report['id']}"),
        ("get", f"/cti/reports/{report['id']}/misp"),
        ("get", f"/cti/attribution/case/{case['id']}"),
        ("get", f"/cti/iocs/{ioc_id}/enrichment"),
    ]
    for method, path in denied:
        r = getattr(client, method)(path, headers=auth)
        assert r.status_code == 404, f"{path}: expected 404 cross-org, got {r.status_code}"
    # …and cross-org mutations on the report 404 without effect.
    assert client.patch(f"/cti/reports/{report['id']}", headers=auth,
                        json={"summary": "hijacked"}).status_code == 404
    assert client.delete(f"/cti/reports/{report['id']}", headers=auth).status_code == 404
    # The report list is scoped: the default workspace never sees B's report.
    assert not any(r["id"] == report["id"]
                   for r in client.get("/cti/reports", headers=auth).json())

    # …while the owning workspace reads them all fine (guard denies, doesn't break).
    for method, path in denied:
        r = getattr(client, method)(path, headers=hb)
        assert r.status_code == 200, f"{path}: owner expected 200, got {r.status_code}"
    assert any(r["id"] == report["id"]
               for r in client.get("/cti/reports", headers=hb).json())
