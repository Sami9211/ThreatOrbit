"""Smoke + behaviour tests across every domain router."""


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").json()["ready"] is True


def test_login_and_me(client, admin_token):
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json()["email"] == "admin@threatorbit.space"
    assert "password_hash" not in r.json()


def test_login_bad_password(client):
    r = client.post("/auth/login", json={"email": "admin@threatorbit.space", "password": "wrong"})
    assert r.status_code == 401


def test_auth_required(client):
    assert client.get("/siem/alerts").status_code == 401
    assert client.get("/overview/kpis").status_code == 401


def test_overview(client, auth):
    kpis = client.get("/overview/kpis", headers=auth).json()
    assert {"threats", "iocs", "sources", "score"} <= kpis.keys()
    assert len(client.get("/overview/hourly-volume", headers=auth).json()) == 24
    assert isinstance(client.get("/overview/threat-vectors", headers=auth).json(), list)


def test_siem(client, auth):
    data = client.get("/siem/alerts?limit=10", headers=auth).json()
    assert data["total"] > 0 and len(data["items"]) <= 10
    alert = data["items"][0]
    assert {"severity", "mitre_tactic", "risk_score"} <= alert.keys()
    # update flow
    r = client.patch(f"/siem/alerts/{alert['id']}", json={"status": "closed", "disposition": "benign"}, headers=auth)
    assert r.status_code == 200 and r.json()["status"] == "closed"
    kpis = client.get("/siem/kpis", headers=auth).json()
    assert kpis["totalAlerts"] > 0
    assert client.get("/siem/rules", headers=auth).json()
    assert client.get("/siem/sources", headers=auth).json()


def test_siem_metrics_are_computed(client, auth):
    """MTTD/MTTA/MTTR are derived from per-alert latency telemetry, in minutes."""
    kpis = client.get("/siem/kpis", headers=auth).json()
    # SOC-grade range: detection fastest, response slowest, all well under an hour.
    assert 0 < kpis["mttd"] < 60
    assert 0 < kpis["mtta"] < 90
    assert 0 < kpis["mttr"] < 120
    assert kpis["mttd"] < kpis["mttr"]  # detect before respond


def test_siem_correlations(client, auth):
    clusters = client.get("/siem/correlations?min_alerts=2", headers=auth).json()
    assert isinstance(clusters, list)
    for c in clusters:
        assert c["pivot"] in {"src_ip", "hostname", "username"}
        assert c["alertCount"] >= 2
        assert len(c["alerts"]) == c["alertCount"]
    # sorted by alertCount descending
    counts = [c["alertCount"] for c in clusters]
    assert counts == sorted(counts, reverse=True)


def test_siem_hunts_aliased(client, auth):
    hunts = client.get("/siem/hunts", headers=auth).json()
    assert hunts
    # frontend-facing field names are exposed, not the raw column names
    assert {"hypothesis", "analyst", "artifacts", "status", "progress"} <= hunts[0].keys()
    assert "description" not in hunts[0] and "author" not in hunts[0]


def test_cti_hunts_aliased(client, auth):
    hunts = client.get("/cti/hunts", headers=auth).json()
    assert hunts
    assert {"hypothesis", "analyst", "artifacts"} <= hunts[0].keys()


def test_soar(client, auth):
    cases = client.get("/soar/cases", headers=auth).json()
    assert cases and {"tasks", "war_room", "entities"} <= cases[0].keys()
    assert isinstance(cases[0]["tasks"], list)
    assert client.get("/soar/playbooks", headers=auth).json()
    assert client.get("/soar/integrations", headers=auth).json()
    m = client.get("/soar/metrics", headers=auth).json()
    assert "openCases" in m
    assert 0 <= m["automationRate"] <= 100  # a real ratio, not a saturating proxy


def test_soar_playbook_run(client, auth):
    pbs = client.get("/soar/playbooks", headers=auth).json()
    pb = next(p for p in pbs if p["enabled"])
    before = pb["runs"]
    r = client.post(f"/soar/playbooks/{pb['id']}/run", headers=auth)
    assert r.status_code == 200
    assert r.json()["runs"] == before + 1
    assert r.json()["last_run_status"] == "success"


def test_audit_log_records_mutations(client, auth):
    """A mutation writes an audit row visible via the audit-log endpoint."""
    feeds = client.get("/feeds", headers=auth).json()
    fid = feeds[0]["id"]
    client.patch(f"/feeds/{fid}", json={"enabled": False}, headers=auth)
    log = client.get("/config/audit-log?limit=20", headers=auth).json()
    assert any(r["action"] == "feed.toggle" and r["target"] == fid for r in log)
    assert all({"ts", "actor", "action"} <= r.keys() for r in log)


def test_cti(client, auth):
    actors = client.get("/cti/actors", headers=auth).json()
    assert actors and isinstance(actors[0]["aliases"], list)
    iocs = client.get("/cti/iocs?limit=5", headers=auth).json()
    assert iocs["total"] > 0
    graph = client.get("/cti/graph", headers=auth).json()
    assert "nodes" in graph and "links" in graph


def test_assets(client, auth):
    data = client.get("/assets", headers=auth).json()
    assert data["total"] > 0
    a = data["items"][0]
    assert isinstance(a["open_ports"], list) and isinstance(a["cves"], dict)
    assert "avgRiskScore" in client.get("/assets/summary", headers=auth).json()
    assert client.get("/assets/vulns", headers=auth).json()


def test_feeds(client, auth):
    feeds = client.get("/feeds", headers=auth).json()
    assert feeds
    summary = client.get("/feeds/summary", headers=auth).json()
    assert summary["totalFeeds"] == len(feeds)


def test_user_lifecycle(client, auth):
    r = client.post("/users", json={
        "email": "new.analyst@threatorbit.space", "name": "New Analyst",
        "role": "analyst", "password": "Password123!"}, headers=auth)
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    # duplicate email rejected
    assert client.post("/users", json={
        "email": "new.analyst@threatorbit.space", "name": "Dup",
        "role": "analyst", "password": "Password123!"}, headers=auth).status_code == 409
    # update role
    assert client.patch(f"/users/{uid}", json={"role": "manager"}, headers=auth).json()["role"] == "manager"
    # new user can log in
    assert client.post("/auth/login", json={
        "email": "new.analyst@threatorbit.space", "password": "Password123!"}).status_code == 200
    # delete
    assert client.delete(f"/users/{uid}", headers=auth).status_code == 204


def test_config_settings_and_keys(client, auth):
    s = client.get("/config/settings", headers=auth).json()
    assert "platform_name" in s
    updated = client.put("/config/settings", json={"values": {"timezone": "Europe/London"}}, headers=auth).json()
    assert updated["timezone"] == "Europe/London"
    key = client.post("/config/api-keys", json={"name": "CI", "scope": "read"}, headers=auth).json()
    assert key["secret"].startswith("to_rk_live_")
    assert any(k["name"] == "CI" for k in client.get("/config/api-keys", headers=auth).json())


def test_viewer_cannot_create_user(client):
    # log in as the seeded viewer
    tok = client.post("/auth/login", json={"email": "tom.okafor@threatorbit.space", "password": "Password123!"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/users", json={"email": "x@y.com", "name": "X", "role": "analyst", "password": "Password123!"}, headers=h)
    assert r.status_code == 403
