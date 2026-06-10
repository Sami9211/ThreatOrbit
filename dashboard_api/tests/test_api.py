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


def test_siem_alert_sorting_and_filters(client, auth):
    """Alerts support whitelisted sorts (severity by priority) and rejects bad sort."""
    # Sort by severity descending → first item is the highest-priority band present.
    items = client.get("/siem/alerts?sort=severity&order=desc&limit=20", headers=auth).json()["items"]
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    ranks = [rank[a["severity"]] for a in items]
    assert ranks == sorted(ranks, reverse=True)
    # risk_score ascending is monotonic non-decreasing.
    asc = client.get("/siem/alerts?sort=risk_score&order=asc&limit=20", headers=auth).json()["items"]
    scores = [a["risk_score"] for a in asc]
    assert scores == sorted(scores)
    # tactic filter only returns matching alerts.
    t = items[0]["mitre_tactic"]
    filtered = client.get(f"/siem/alerts?tactic={t}&limit=50", headers=auth).json()["items"]
    assert filtered and all(a["mitre_tactic"] == t for a in filtered)
    # an unknown sort column is rejected, not silently ignored.
    assert client.get("/siem/alerts?sort=DROP", headers=auth).status_code == 400


def test_ioc_sorting_and_confidence_filter(client, auth):
    """IOCs support a min_confidence filter and confidence sort."""
    hi = client.get("/cti/iocs?min_confidence=80&limit=100", headers=auth).json()["items"]
    assert all(i["confidence"] >= 80 for i in hi)
    desc = client.get("/cti/iocs?sort=confidence&order=desc&limit=20", headers=auth).json()["items"]
    conf = [i["confidence"] for i in desc]
    assert conf == sorted(conf, reverse=True)
    assert client.get("/cti/iocs?sort=bogus", headers=auth).status_code == 400


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


def test_cti_summary(client, auth):
    """CTI summary counts are internally consistent with the actor list."""
    s = client.get("/cti/summary", headers=auth).json()
    actors = client.get("/cti/actors", headers=auth).json()
    assert s["trackedActors"] == len(actors)
    # type buckets are populated (casing-normalised) and sum to the total
    assert s["nationState"] > 0
    assert s["nationState"] + s["cybercrime"] + s["hacktivist"] == s["trackedActors"]
    assert 0 <= s["activeActors"] <= s["trackedActors"]
    assert s["totalIocs"] == client.get("/cti/iocs?limit=1", headers=auth).json()["total"]


def test_ioc_lookup(client, auth):
    """A seeded IOC is found with enrichment; an unknown value is clean/not-found."""
    known = client.get("/cti/iocs?limit=1", headers=auth).json()["items"][0]
    hit = client.get(f"/cti/lookup?value={known['value']}", headers=auth).json()
    assert hit["found"] is True
    assert hit["verdict"] in {"malicious", "suspicious", "clean"}
    assert hit["confidence"] == known["confidence"]
    miss = client.get("/cti/lookup?value=definitely-not-a-real-indicator-xyz", headers=auth).json()
    assert miss["found"] is False and miss["verdict"] == "clean"


def test_ioc_import(client, auth):
    """Importing indicators inserts new ones, skips duplicates and bad types."""
    body = {
        "indicators": [
            {"type": "ip", "value": "203.0.113.250"},
            {"type": "domain", "value": "evil-import-test.example"},
            {"type": "ip", "value": "203.0.113.250"},   # duplicate within batch
            {"type": "bogus", "value": "x"},             # invalid type → skipped
        ],
        "confidence": 80, "severity": "high", "source": "import:TLP:AMBER", "tags": ["triage"],
    }
    r = client.post("/cti/iocs/import", json=body, headers=auth)
    assert r.status_code == 201
    res = r.json()
    assert res["imported"] == 2 and res["duplicates"] == 1 and res["skipped"] == 1
    # the imported indicator is now retrievable and looks up as a known hit
    hit = client.get("/cti/lookup?value=evil-import-test.example", headers=auth).json()
    assert hit["found"] is True and hit["confidence"] == 80
    # re-importing the same batch: every valid entry (ip twice + domain) is now a duplicate
    again = client.post("/cti/iocs/import", json=body, headers=auth).json()
    assert again["imported"] == 0 and again["duplicates"] == 3
    # empty batch rejected
    assert client.post("/cti/iocs/import", json={"indicators": []}, headers=auth).status_code == 400


def test_assets(client, auth):
    data = client.get("/assets", headers=auth).json()
    assert data["total"] > 0
    a = data["items"][0]
    assert isinstance(a["open_ports"], list) and isinstance(a["cves"], dict)
    assert "avgRiskScore" in client.get("/assets/summary", headers=auth).json()
    assert client.get("/assets/vulns", headers=auth).json()


def test_asset_risk_recompute_is_idempotent(client, auth):
    """Two recomputes over unchanged state produce identical scores (deterministic)."""
    r = client.post("/assets/recompute-risk", headers=auth)
    assert r.status_code == 200 and r.json()["updated"] > 0
    a1 = {a["id"]: a["risk_score"] for a in client.get("/assets?limit=500", headers=auth).json()["items"]}
    client.post("/assets/recompute-risk", headers=auth)
    a2 = {a["id"]: a["risk_score"] for a in client.get("/assets?limit=500", headers=auth).json()["items"]}
    assert a1 == a2  # no random drift between runs


def test_resolving_alerts_lowers_asset_risk(client, auth):
    """Triaging an asset's open alerts reduces its alert pressure and risk."""
    # Find an asset that currently carries open alerts.
    assets = client.get("/assets?limit=500", headers=auth).json()["items"]
    target = next((a for a in assets if a["alerts"] > 0), None)
    if target is None:
        return  # no alert-bearing asset in this seed; nothing to assert
    host = target["name"]
    before = target["risk_score"]
    # Close every unresolved alert on that host.
    alerts = client.get("/siem/alerts?limit=500", headers=auth).json()["items"]
    closed = 0
    for al in alerts:
        if al["hostname"] == host and al["status"] not in ("resolved", "closed"):
            client.patch(f"/siem/alerts/{al['id']}", json={"status": "closed"}, headers=auth)
            closed += 1
    if closed == 0:
        return
    client.post("/assets/recompute-risk", headers=auth)
    after = next(a for a in client.get("/assets?limit=500", headers=auth).json()["items"] if a["id"] == target["id"])
    assert after["alerts"] == 0
    assert after["risk_score"] <= before


def test_asset_detail_includes_risk_breakdown(client, auth):
    """The asset detail view explains its score per axis, summing to the total."""
    aid = client.get("/assets?limit=1", headers=auth).json()["items"][0]["id"]
    asset = client.get(f"/assets/{aid}", headers=auth).json()
    bd = asset["riskBreakdown"]
    assert {"vulnerability", "exposure", "patch", "alerts"} == {c["axis"] for c in bd["components"]}
    assert bd["score"] == asset["risk_score"]  # explanation matches the stored score
    # components are ordered by contribution, descending
    contribs = [c["contribution"] for c in bd["components"]]
    assert contribs == sorted(contribs, reverse=True)
    # the summed contributions reconstruct the score (within rounding)
    assert abs(sum(contribs) - bd["score"]) <= 1


def test_fleet_risk_distribution(client, auth):
    """Fleet distribution sums to the asset count and names a top driver."""
    d = client.get("/assets/risk-distribution", headers=auth).json()
    assert d["total"] > 0
    assert sum(d["bands"].values()) == d["total"]
    axes = {c["axis"] for c in d["axisContribution"]}
    assert axes == {"vulnerability", "exposure", "patch", "alerts"}
    # axisContribution is ordered, and topDriver is the leader
    contribs = [c["avgContribution"] for c in d["axisContribution"]]
    assert contribs == sorted(contribs, reverse=True)
    assert d["topDriver"] == d["axisContribution"][0]["axis"]
    assert 0 <= d["meanScore"] <= d["maxScore"] <= 100


def test_scoring_model_units():
    """The pure scoring model is bounded and ordered as documented."""
    from dashboard_api.scoring import asset_risk, risk_band, org_risk

    clean = asset_risk(cves={"critical": 0, "high": 0, "medium": 0, "low": 0},
                       criticality="low", patch_age=0, open_alerts=0)
    maxed = asset_risk(cves={"critical": 5, "high": 10, "medium": 20, "low": 40},
                       criticality="critical", patch_age=365, open_alerts=20,
                       open_ports=[3389, 445, 23], tags=["internet-facing"])
    assert 0 <= clean <= 100 and 0 <= maxed <= 100
    assert clean < maxed and maxed >= 90
    assert risk_band(80) == "critical" and risk_band(50) == "at-risk" and risk_band(10) == "clean"
    # Org risk weights critical assets above low ones.
    assert org_risk([{"risk_score": 90, "criticality": "critical"},
                     {"risk_score": 10, "criticality": "low"}]) > 50


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
    # the stored prefix is a non-sensitive display fragment: last 4 of the secret
    assert key["prefix"] == key["secret"][-4:]
    assert key["created_at"] and key["revoked"] == 0
    listed = client.get("/config/api-keys", headers=auth).json()
    assert any(k["name"] == "CI" and "secret_hash" not in k for k in listed)
    # revoke flow
    assert client.delete(f"/config/api-keys/{key['id']}", headers=auth).status_code == 204
    assert any(k["id"] == key["id"] and k["revoked"] == 1
               for k in client.get("/config/api-keys", headers=auth).json())


def test_viewer_cannot_create_user(client):
    # log in as the seeded viewer
    tok = client.post("/auth/login", json={"email": "tom.okafor@threatorbit.space", "password": "Password123!"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/users", json={"email": "x@y.com", "name": "X", "role": "analyst", "password": "Password123!"}, headers=h)
    assert r.status_code == 403


def test_register_creates_account_and_logs_in(client):
    r = client.post("/auth/register", json={
        "name": "Signup Smith", "email": "signup.smith@example.com",
        "password": "Sup3rSecret!", "company": "Example Corp"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["token"]
    assert body["user"]["email"] == "signup.smith@example.com"
    assert body["user"]["role"] == "analyst"  # seeded admin already exists
    assert "password_hash" not in body["user"]
    # the returned token works immediately
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {body['token']}"})
    assert me.status_code == 200 and me.json()["email"] == "signup.smith@example.com"
    # signup is audited
    tok = client.post("/auth/login", json={"email": "admin@threatorbit.space", "password": "ChangeMe123!"}).json()["token"]
    log = client.get("/config/audit-log?action=auth.register", headers={"Authorization": f"Bearer {tok}"}).json()
    assert any(e["actor"] == "signup.smith@example.com" for e in log)


def test_register_validation(client):
    dup = client.post("/auth/register", json={
        "name": "Dup", "email": "signup.smith@example.com", "password": "Sup3rSecret!"})
    assert dup.status_code == 409
    assert client.post("/auth/register", json={
        "name": "Short", "email": "short.pw@example.com", "password": "tiny"}).status_code == 400
    assert client.post("/auth/register", json={
        "name": "Bad", "email": "not-an-email", "password": "Sup3rSecret!"}).status_code == 400


def test_login_throttled_after_repeated_failures(client):
    from dashboard_api.config import AUTH_MAX_FAILURES
    email = "bruteforce.target@example.com"
    for _ in range(AUTH_MAX_FAILURES):
        assert client.post("/auth/login", json={"email": email, "password": "wrong"}).status_code == 401
    assert client.post("/auth/login", json={"email": email, "password": "wrong"}).status_code == 429


def test_patch_user_mfa(client, auth):
    r = client.post("/users", json={
        "email": "mfa.user@threatorbit.space", "name": "MFA User",
        "role": "viewer", "password": "Password123!"}, headers=auth)
    uid = r.json()["id"]
    assert r.json()["mfa_enabled"] == 0
    updated = client.patch(f"/users/{uid}", json={"mfa_enabled": True}, headers=auth).json()
    assert updated["mfa_enabled"] == 1
    client.delete(f"/users/{uid}", headers=auth)


def test_case_lifecycle(client, auth):
    r = client.post("/soar/cases", json={
        "title": "Suspicious lateral movement from jump host",
        "severity": "high", "type": "Intrusion",
        "description": "Created from correlated SMB alerts",
        "entities": [{"type": "host", "value": "JH-01"}]}, headers=auth)
    assert r.status_code == 201, r.text
    case = r.json()
    cid = case["id"]
    assert case["status"] == "new" and case["severity"] == "high"
    assert case["tasks"] and all(t["status"] == "pending" for t in case["tasks"])
    assert case["war_room"][0]["type"] == "system"

    # invalid severity rejected
    assert client.post("/soar/cases", json={"title": "x", "severity": "apocalyptic"},
                       headers=auth).status_code == 400

    # add a war-room note
    n = client.post(f"/soar/cases/{cid}/notes", json={"content": "Host isolated via EDR"}, headers=auth)
    assert n.status_code == 201
    assert any(e["content"] == "Host isolated via EDR" for e in n.json()["war_room"])

    # advance a task
    tid = case["tasks"][0]["id"]
    t = client.patch(f"/soar/cases/{cid}/tasks/{tid}", json={"status": "done"}, headers=auth)
    assert t.status_code == 200
    assert next(x for x in t.json()["tasks"] if x["id"] == tid)["status"] == "done"
    # unknown task 404, bad status 400
    assert client.patch(f"/soar/cases/{cid}/tasks/NOPE", json={"status": "done"}, headers=auth).status_code == 404
    assert client.patch(f"/soar/cases/{cid}/tasks/{tid}", json={"status": "skipped"}, headers=auth).status_code == 400


def test_hunt_query_engine(client, auth):
    """Ad-hoc hunt queries return real alerts matched on extracted tokens."""
    r = client.post("/siem/hunt-query", json={"query": "T1059 critical", "time_range": "7d"}, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scanned"] > 0
    assert "T1059" in body["tokens"]["techniques"] and "critical" in body["tokens"]["severities"]
    for row in body["results"]:
        assert row["technique"].startswith("T1059")
        assert row["severity"] == "critical"
        assert row["alert_id"]
    assert client.post("/siem/hunt-query", json={"query": "x", "time_range": "1y"}, headers=auth).status_code == 400


def test_saved_hunt_create_and_run(client, auth):
    created = client.post("/siem/hunts", json={
        "name": "PowerShell abuse sweep", "description": "Encoded PowerShell launches",
        "query": '"powershell" T1059', "technique": "T1059"}, headers=auth)
    assert created.status_code == 201, created.text
    hid = created.json()["id"]
    assert created.json()["status"] == "idle"

    run = client.post(f"/siem/hunts/{hid}/run", headers=auth)
    assert run.status_code == 200
    out = run.json()
    assert out["hunt"]["status"] == "complete" and out["hunt"]["progress"] == 100
    assert out["hunt"]["artifacts"] == out["run"]["hits"]
    assert client.post("/siem/hunts/missing/run", headers=auth).status_code == 404

    # CTI domain works against the IOC store
    cti = client.post("/cti/hunts", json={"name": "Cobalt Strike infra", "query": '"cobalt"'}, headers=auth)
    assert cti.status_code == 201
    cti_run = client.post(f"/cti/hunts/{cti.json()['id']}/run", headers=auth)
    assert cti_run.status_code == 200
    assert cti_run.json()["run"]["scanned"] > 0


def test_create_rule_feed_source(client, auth):
    rule = client.post("/siem/rules", json={
        "name": "Suspicious LSASS access", "severity": "high",
        "mitre_tactic": "Credential Access", "mitre_tech_id": "T1003",
        "kql": 'process where target.name == "lsass.exe"'}, headers=auth)
    assert rule.status_code == 201 and rule.json()["status"] == "enabled"
    assert rule.json()["id"].startswith("R-")
    assert client.post("/siem/rules", json={"name": "x", "severity": "huge"}, headers=auth).status_code == 400

    src = client.post("/siem/sources", json={"name": "K8s audit logs", "type": "JSON", "host": "k8s-audit"}, headers=auth)
    assert src.status_code == 201 and src.json()["status"] == "healthy"

    feed = client.post("/feeds", json={"name": "URLhaus", "type": "opensource",
                                       "url": "https://urlhaus.abuse.ch/downloads/csv/"}, headers=auth)
    assert feed.status_code == 201 and feed.json()["enabled"] == 1
    assert client.post("/feeds", json={"name": "x", "type": "imaginary"}, headers=auth).status_code == 400


def test_scan_history(client, auth):
    r = client.post("/cti/scans", json={
        "target": "45.95.147.236", "type": "ip", "verdict": "malicious",
        "score": 0.81, "engines": "41/90"}, headers=auth)
    assert r.status_code == 201, r.text
    assert r.json()["verdict"] == "malicious"
    listed = client.get("/cti/scans", headers=auth).json()
    assert listed["scansToday"] >= 1 and listed["malicious"] >= 1
    assert any(s["target"] == "45.95.147.236" for s in listed["items"])
    assert client.post("/cti/scans", json={"target": "x", "type": "carrier-pigeon",
                                           "verdict": "clean"}, headers=auth).status_code == 400


def test_webhook_lifecycle(client, auth):
    r = client.post("/config/webhooks", json={
        "url": "https://hooks.example.com/threatorbit",
        "events": ["alert.created", "incident.resolved"]}, headers=auth)
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    assert r.json()["status"] == "active" and "alert.created" in r.json()["events"]
    # invalid inputs rejected
    assert client.post("/config/webhooks", json={"url": "ftp://nope", "events": ["alert.created"]},
                       headers=auth).status_code == 400
    assert client.post("/config/webhooks", json={"url": "https://x.com", "events": ["bogus.event"]},
                       headers=auth).status_code == 400
    # pause it
    assert client.patch(f"/config/webhooks/{wid}", json={"status": "paused"},
                        headers=auth).json()["status"] == "paused"
    # delete it
    assert client.delete(f"/config/webhooks/{wid}", headers=auth).status_code == 204
    assert all(w["id"] != wid for w in client.get("/config/webhooks", headers=auth).json())


def test_create_asset(client, auth):
    r = client.post("/assets", json={
        "name": "staging-api-01", "type": "server", "value": "10.9.0.41",
        "criticality": "high"}, headers=auth)
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    assert r.json()["status"] == "unscanned" and r.json()["risk_score"] == 0
    # detail returns the transparent risk breakdown
    detail = client.get(f"/assets/{aid}", headers=auth).json()
    assert "riskBreakdown" in detail and "components" in detail["riskBreakdown"]
    assert client.post("/assets", json={"name": "x", "type": "spaceship", "value": "v"},
                       headers=auth).status_code == 400


def test_services_bridge_degrades_gracefully(client, auth, monkeypatch):
    """With no companion services running, reads degrade and actions 503."""
    status = client.get("/services/status", headers=auth).json()
    assert status["threatApi"]["available"] is False
    assert status["logApi"]["available"] is False
    health = client.get("/services/threat/source-health", headers=auth).json()
    assert health == {"available": False, "sources": []}
    assert client.post("/services/threat/fetch", headers=auth).status_code == 503
    assert client.post("/services/threat/sync-iocs", headers=auth).status_code == 503
    assert client.post("/services/logs/analyse",
                       files={"file": ("a.log", b"line\n")}, headers=auth).status_code == 503


def test_services_sync_iocs_imports_upstream(client, auth, monkeypatch):
    """sync-iocs maps Threat API indicators into the dashboard IOC store."""
    import dashboard_api.routers.services as services

    upstream = [
        {"ioc_type": "ip", "value": "203.0.113.99", "source": "otx",
         "threat_type": "c2", "confidence": 90, "tags": ["botnet"]},
        {"ioc_type": "sha256", "value": "f" * 64, "source": "abusech",
         "threat_type": "malware", "confidence": 60, "malware_family": "AgentTesla"},
        {"ioc_type": "carrier-pigeon", "value": "nope", "source": "x"},   # skipped
        {"ioc_type": "ip", "value": "203.0.113.99", "source": "otx"},      # duplicate
    ]
    monkeypatch.setattr(services, "_get", lambda base, path, admin=False, params=None: upstream)

    out = client.post("/services/threat/sync-iocs", headers=auth).json()
    assert out["imported"] == 2 and out["skipped"] == 1 and out["duplicates"] == 1

    hit = client.get("/cti/lookup?value=203.0.113.99", headers=auth).json()
    assert hit["found"] is True and hit["verdict"] == "malicious"
    assert hit["source"] == "threat-api:otx"
    # hash type was normalised
    items = client.get("/cti/iocs?q=" + "f" * 64, headers=auth).json()["items"]
    assert items and items[0]["type"] == "hash" and items[0]["actor"] == "AgentTesla"


def test_webhook_delivery_engine(client, auth, monkeypatch):
    """Platform events POST a JSON envelope to subscribed endpoints."""
    import http.server
    import threading
    import dashboard_api.webhooks as wh

    received: list = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            import json as _json
            length = int(self.headers.get("Content-Length", 0))
            received.append(_json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)

    try:
        hook = client.post("/config/webhooks", json={
            "url": f"http://127.0.0.1:{port}/sink",
            "events": ["case.created", "incident.resolved"]}, headers=auth).json()

        # case.created fires
        case = client.post("/soar/cases", json={"title": "Webhook test case", "severity": "low"},
                           headers=auth).json()
        assert any(m["event"] == "case.created" and m["data"]["id"] == case["id"] for m in received)

        # resolving the case fires incident.resolved (transition only)
        client.patch(f"/soar/cases/{case['id']}", json={"status": "resolved"}, headers=auth)
        assert any(m["event"] == "incident.resolved" and m["data"]["id"] == case["id"] for m in received)
        n = len(received)
        client.patch(f"/soar/cases/{case['id']}", json={"status": "closed"}, headers=auth)
        assert len(received) == n  # already resolved — no duplicate event

        # successful deliveries stamp last_delivery and stay active
        listed = client.get("/config/webhooks", headers=auth).json()
        mine = next(w for w in listed if w["id"] == hook["id"])
        assert mine["status"] == "active" and mine["last_delivery"]

        # the test endpoint reports reachability
        ok = client.post(f"/config/webhooks/{hook['id']}/test", headers=auth).json()
        assert ok["ok"] is True
        assert any(m["event"] == "webhook.test" for m in received)

        client.delete(f"/config/webhooks/{hook['id']}", headers=auth)
    finally:
        server.shutdown()


def test_webhook_failure_marks_failing(client, auth, monkeypatch):
    import dashboard_api.webhooks as wh
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    hook = client.post("/config/webhooks", json={
        "url": "http://127.0.0.1:1/unreachable", "events": ["ioc.confirmed"]}, headers=auth).json()
    client.post("/cti/iocs/import", json={
        "indicators": [{"type": "ip", "value": "198.51.100.77"}]}, headers=auth)
    listed = client.get("/config/webhooks", headers=auth).json()
    assert next(w for w in listed if w["id"] == hook["id"])["status"] == "failing"
    client.delete(f"/config/webhooks/{hook['id']}", headers=auth)


def test_background_jobs_recorded(client, auth):
    client.post("/assets/recompute-risk", headers=auth)
    jobs = client.get("/config/jobs", headers=auth).json()
    job = next(j for j in jobs if j["kind"] == "assets.recompute_risk")
    assert job["status"] == "completed" and job["progress"] == 100
    assert job["meta"]["updated"] >= 1


def test_create_alert(client, auth, monkeypatch):
    import dashboard_api.webhooks as wh
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    captured: list = []
    monkeypatch.setattr(wh, "_deliver", lambda event, payload, subs: captured.append(event))
    hook = client.post("/config/webhooks", json={
        "url": "https://example.com/sink", "events": ["alert.created"]}, headers=auth).json()

    r = client.post("/siem/alerts", json={
        "title": "Escalated: FortiOS SSL VPN exploitation", "severity": "critical",
        "src_ip": "91.92.251.103", "mitre_tech_id": "T1190",
        "rule_name": "Threat Intel Escalation", "ti_hits": 4}, headers=auth)
    assert r.status_code == 201, r.text
    alert = r.json()
    assert alert["status"] == "new" and alert["risk_score"] == 92
    # appears in the queue
    found = client.get("/siem/alerts?q=FortiOS&limit=5", headers=auth).json()["items"]
    assert any(a["id"] == alert["id"] for a in found)
    # alert.created webhook fired
    assert "alert.created" in captured
    assert client.post("/siem/alerts", json={"title": "x", "severity": "apocalyptic"},
                       headers=auth).status_code == 400
    client.delete(f"/config/webhooks/{hook['id']}", headers=auth)


def test_integration_lifecycle(client, auth):
    created = client.post("/soar/integrations", json={
        "name": "PagerDuty", "vendor": "PagerDuty", "category": "Notification",
        "actions": ["Trigger incident", "Resolve incident"]}, headers=auth)
    assert created.status_code == 201, created.text
    iid = created.json()["id"]
    assert created.json()["status"] == "pending"
    # test-connection marks it live
    tested = client.post(f"/soar/integrations/{iid}/test", headers=auth).json()
    assert tested["status"] == "connected" and tested["last_sync"]
    # running an action bumps the counter
    run = client.post(f"/soar/integrations/{iid}/actions/run",
                      json={"action": "Trigger incident"}, headers=auth).json()
    assert run["actions_run"] == 1
    assert client.post("/soar/integrations/missing/actions/run",
                       json={"action": "x"}, headers=auth).status_code == 404


def test_rule_delete(client, auth):
    rule = client.post("/siem/rules", json={"name": "Temp rule", "severity": "low"}, headers=auth).json()
    assert client.delete(f"/siem/rules/{rule['id']}", headers=auth).status_code == 204
    assert client.delete(f"/siem/rules/{rule['id']}", headers=auth).status_code == 404
