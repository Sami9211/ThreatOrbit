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


def test_connector_kinds_and_crud(client, auth):
    kinds = client.get("/connectors/kinds", headers=auth).json()
    assert any(k["kind"] == "threatorbit" for k in kinds)
    assert any(k["kind"] == "nvd" for k in kinds)
    # create a custom JSON connector
    c = client.post("/connectors", json={
        "name": "My Feed", "kind": "json", "url": "https://example.com/iocs.json",
        "field_map": {"value": "indicator", "type": "kind"}}, headers=auth)
    assert c.status_code == 201, c.text
    cid = c.json()["id"]
    assert "api_key" not in c.json()  # secret never returned
    # OTX without a key is rejected
    assert client.post("/connectors", json={"name": "OTX", "kind": "otx"}, headers=auth).status_code == 400
    # update + toggle
    assert client.patch(f"/connectors/{cid}", json={"enabled": False}, headers=auth).json()["enabled"] == 0
    assert client.delete(f"/connectors/{cid}", headers=auth).status_code == 204


def test_connector_json_csv_engine(client, auth, monkeypatch):
    """The generic JSON and CSV fetchers normalise + import real records."""
    import dashboard_api.connectors as conn_mod

    class FakeResp:
        def __init__(self, data=None, text=""):
            self._data = data
            self.text = text
        def json(self):
            return self._data

    json_payload = {"data": [
        {"indicator": "203.0.113.45", "kind": "ip", "threat": "c2"},
        {"indicator": "evil-domain.test", "kind": "domain"},
        {"indicator": "", "kind": "ip"},  # skipped
    ]}
    monkeypatch.setattr(conn_mod, "_http_get", lambda url, headers=None, params=None: FakeResp(data=json_payload))

    c = client.post("/connectors", json={
        "name": "JSON Feed", "kind": "json", "url": "https://x/iocs.json",
        "field_map": {"value": "indicator", "type": "kind", "threat_type": "threat"}}, headers=auth)
    cid = c.json()["id"]
    run = client.post(f"/connectors/{cid}/run", headers=auth).json()
    assert run["result"]["imported"] == 2 and run["result"]["skipped"] == 1
    assert run["connector"]["status"] == "ok"
    # the imported indicator is looked up live
    hit = client.get("/cti/lookup?value=203.0.113.45", headers=auth).json()
    assert hit["found"] and hit["source"] == "JSON Feed"

    # CSV variant
    csv_text = "url,type\nhttp://bad.test/x,url\nhttp://bad.test/y,url\n"
    monkeypatch.setattr(conn_mod, "_http_get", lambda url, headers=None, params=None: FakeResp(text=csv_text))
    cc = client.post("/connectors", json={
        "name": "CSV Feed", "kind": "csv", "url": "https://x/iocs.csv",
        "field_map": {"value": "url", "type": "type"}}, headers=auth)
    rr = client.post(f"/connectors/{cc.json()['id']}/run", headers=auth).json()
    assert rr["result"]["imported"] == 2


def test_connector_nvd_engine(client, auth, monkeypatch):
    import dashboard_api.connectors as conn_mod

    class FakeResp:
        def json(self):
            return {"vulnerabilities": [
                {"cve": {"id": "CVE-2024-99999",
                         "descriptions": [{"lang": "en", "value": "Critical RCE"}],
                         "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}}},
            ]}
    monkeypatch.setattr(conn_mod, "_http_get", lambda url, headers=None, params=None: FakeResp())
    c = client.post("/connectors", json={"name": "NVD", "kind": "nvd"}, headers=auth)
    run = client.post(f"/connectors/{c.json()['id']}/run", headers=auth).json()
    assert run["result"]["imported"] == 1
    items = client.get("/cti/iocs?q=CVE-2024-99999", headers=auth).json()["items"]
    assert items and items[0]["type"] == "cve" and items[0]["severity"] == "critical"


def test_connector_run_records_failure(client, auth, monkeypatch):
    """A network failure is recorded on the connector, never crashes the API."""
    import dashboard_api.connectors as conn_mod
    def boom(*a, **k):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(conn_mod, "_http_get", boom)
    c = client.post("/connectors", json={"name": "Broken", "kind": "json",
                                         "url": "https://nope.test/x"}, headers=auth)
    run = client.post(f"/connectors/{c.json()['id']}/run", headers=auth).json()
    assert "error" in run["result"] and run["connector"]["status"] == "error"


def test_log_analysis_creates_real_siem_alerts(client, auth, monkeypatch):
    """Uploading a log → the Log API's findings become real SIEM alerts."""
    import dashboard_api.routers.services as svc

    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"total_lines": 120, "parsed_lines": 118, "detectors_used": ["pattern", "ml"],
                    "findings": [
                        {"detector": "pattern", "finding_type": "brute_force",
                         "description": "SSH brute force from 45.9.1.2", "severity": "CRITICAL",
                         "severity_score": 95, "source_ip": "45.9.1.2", "username": "root",
                         "evidence": ["Failed password for root", "Failed password for root"],
                         "mitre_tags": [{"technique_id": "T1110", "name": "Brute Force"}], "count": 240},
                        {"detector": "statistical", "finding_type": "beaconing",
                         "description": "Periodic outbound to 185.2.3.4", "severity": "HIGH",
                         "severity_score": 78, "source_ip": "10.0.0.5",
                         "mitre_tags": [{"technique_id": "T1071", "name": "C2"}], "count": 60},
                    ]}
    monkeypatch.setattr(svc.httpx, "post", lambda *a, **k: FakeResp())

    before = client.get("/siem/alerts", headers=auth).json()["total"]
    r = client.post("/services/logs/analyse",
                    files={"file": ("auth.log", b"line1\nline2\n")},
                    data={"log_format": "syslog"}, headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["alertsCreated"] == 2
    after = client.get("/siem/alerts?sort=ts&order=desc&limit=10", headers=auth).json()
    assert after["total"] == before + 2
    bf = next(a for a in after["items"] if "brute force" in a["title"].lower())
    assert bf["severity"] == "critical" and bf["src_ip"] == "45.9.1.2"
    assert bf["mitre_tech_id"] == "T1110" and bf["mitre_tactic"] == "Credential Access"
    assert bf["rule_name"].startswith("LogEngine")


def test_connector_critical_ioc_raises_siem_alert(client, auth, monkeypatch):
    """A critical indicator ingested by a connector raises a SIEM intel alert."""
    import dashboard_api.connectors as conn_mod

    class FakeResp:
        def json(self):
            return [{"value": "198.51.100.66", "type": "ip", "confidence": 95,
                     "threat_type": "c2", "severity": "critical"}]
    monkeypatch.setattr(conn_mod, "_http_get", lambda url, headers=None, params=None: FakeResp())

    before = client.get("/siem/alerts", headers=auth).json()["total"]
    c = client.post("/connectors", json={"name": "CritFeed", "kind": "json",
                                         "url": "https://x/iocs.json",
                                         "field_map": {"value": "value", "type": "type",
                                                       "confidence": "confidence",
                                                       "severity": "severity"}}, headers=auth)
    run = client.post(f"/connectors/{c.json()['id']}/run", headers=auth).json()
    assert run["result"]["imported"] == 1 and run["result"]["alertsRaised"] == 1
    after = client.get("/siem/alerts?q=198.51.100.66", headers=auth).json()
    assert after["total"] == 1 and after["items"][0]["ti_hits"] == 1


def test_live_engine_produces_cross_section_data(client, auth):
    """The engine generates telemetry → SIEM alerts, CTI IOCs, dark-web findings,
    and auto-escalated SOAR cases — all queryable."""
    before = client.get("/siem/alerts", headers=auth).json()["total"]
    r = client.post("/config/engine", json={"generate": 10}, headers=auth)
    assert r.status_code == 200, r.text
    g = r.json()["generated"]
    assert g["alerts"] > 0 and g["iocs"] > 0
    # SIEM grew
    assert client.get("/siem/alerts", headers=auth).json()["total"] > before
    # engine alerts carry MITRE mapping
    items = client.get("/siem/alerts?sort=ts&order=desc&limit=20", headers=auth).json()["items"]
    assert any(a["mitre_tech_id"] and a["rule_name"] for a in items)
    # dark web findings exist
    dw = client.get("/darkweb/findings", headers=auth).json()
    assert dw["total"] >= 0
    summary = client.get("/darkweb/summary", headers=auth).json()
    assert "byCategory" in summary
    # engine status reflects live activity
    st = client.get("/config/engine", headers=auth).json()
    assert st["totalAlerts"] > 0


def test_darkweb_triage(client, auth):
    client.post("/config/engine", json={"generate": 8}, headers=auth)
    findings = client.get("/darkweb/findings?limit=5", headers=auth).json()["items"]
    if findings:
        fid = findings[0]["id"]
        updated = client.patch(f"/darkweb/findings/{fid}", json={"status": "investigating"}, headers=auth)
        assert updated.status_code == 200 and updated.json()["status"] == "investigating"
        assert client.patch(f"/darkweb/findings/{fid}", json={"status": "bogus"}, headers=auth).status_code == 400


def test_engine_pause_resume(client, auth):
    assert client.post("/config/engine", json={"enabled": False}, headers=auth).json()["enabled"] is False
    st = client.get("/config/engine", headers=auth).json()
    assert st["enabled"] is False
    client.post("/config/engine", json={"enabled": True}, headers=auth)


def test_reports_all_kinds(client, auth):
    kinds = [k["kind"] for k in client.get("/reports/kinds", headers=auth).json()]
    assert {"executive", "siem", "soar", "cti", "assets", "darkweb"} <= set(kinds)
    for kind in kinds:
        r = client.get(f"/reports/{kind}?period=weekly", headers=auth)
        assert r.status_code == 200, f"{kind}: {r.text}"
        rep = r.json()
        assert rep["meta"]["kind"] == kind
        assert "headline" in rep["summary"] and "narrative" in rep["summary"]
        assert isinstance(rep["findings"], list) and isinstance(rep["recommendations"], list)
        assert rep["meta"]["period"] and rep["meta"]["generatedAt"]
    # custom range requires a from date
    assert client.get("/reports/siem?period=custom", headers=auth).status_code == 400
    ok = client.get("/reports/siem?period=custom&from=2020-01-01T00:00:00", headers=auth)
    assert ok.status_code == 200
    # daily window works on a fresh demo DB
    assert client.get("/reports/executive?period=daily", headers=auth).status_code == 200


def test_rule_engine_matching():
    """Pure rule_engine: conditions, operators, and aggregation thresholds."""
    from dashboard_api.rule_engine import matches_event, evaluate
    from datetime import datetime, timezone
    e = {"event_type": "failed_login", "src_ip": "10.0.0.5", "bytes_out": 200, "username": "root"}
    assert matches_event(e, {"conditions": [{"field": "event_type", "op": "equals", "value": "failed_login"}], "logic": "and"})
    assert not matches_event(e, {"conditions": [{"field": "event_type", "op": "equals", "value": "beacon"}], "logic": "and"})
    assert matches_event(e, {"conditions": [{"field": "bytes_out", "op": "gt", "value": 100}], "logic": "and"})
    assert matches_event(e, {"conditions": [{"field": "src_ip", "op": "cidr", "value": "10.0.0.0/8"}], "logic": "and"})
    assert matches_event(e, {"conditions": [{"field": "username", "op": "in", "value": "root,admin"}], "logic": "and"})
    # aggregation: 3 same-ip events within window with threshold 3 → one match
    now = datetime.now(timezone.utc)
    evs = [{"event_type": "failed_login", "src_ip": "1.2.3.4", "ts": now.isoformat()} for _ in range(3)]
    rule = {"definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "failed_login"}],
                           "logic": "and", "aggregation": {"groupBy": "src_ip", "threshold": 3, "windowMinutes": 60}}}
    out = evaluate(rule, evs, now=now)
    assert len(out) == 1 and out[0]["entity"] == "1.2.3.4" and out[0]["count"] == 3
    # below threshold → no match
    assert evaluate({"definition": {**rule["definition"], "aggregation": {"groupBy": "src_ip", "threshold": 5, "windowMinutes": 60}}}, evs, now=now) == []


def test_detection_rule_crud_and_backtest(client, auth):
    # schema metadata
    sch = client.get("/siem/rule-schema", headers=auth).json()
    assert "event_type" in sch["fields"] and "equals" in sch["operators"]
    # create a rule with a real definition
    r = client.post("/siem/rules", json={
        "name": "Suspicious egress", "severity": "high", "mitre_tech_id": "T1041",
        "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "large_egress"}], "logic": "and"}},
        headers=auth)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert r.json()["definition"]["conditions"][0]["field"] == "event_type"
    # backtest endpoint runs without creating alerts
    bt = client.post("/siem/rules/test", json={
        "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "failed_login"}], "logic": "and"}},
        headers=auth)
    assert bt.status_code == 200 and "matched" in bt.json() and "scanned" in bt.json()
    # empty definition rejected
    assert client.post("/siem/rules/test", json={"definition": {}}, headers=auth).status_code == 400
    # update the definition
    upd = client.patch(f"/siem/rules/{rid}", json={"definition": {"conditions": [{"field": "bytes_out", "op": "gte", "value": 1000}], "logic": "and"}}, headers=auth)
    assert upd.json()["definition"]["conditions"][0]["op"] == "gte"


def test_engine_rule_driven_detection(client, auth):
    """The live engine now generates events and rules fire alerts over them."""
    # seed built-in rules (live-mode would do this at boot)
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    before = client.get("/siem/alerts", headers=auth).json()["total"]
    g = client.post("/config/engine", json={"generate": 12}, headers=auth).json()["generated"]
    assert g["alerts"] > 0  # rules matched generated events
    after = client.get("/siem/alerts?sort=ts&order=desc&limit=20", headers=auth).json()
    assert after["total"] > before
    # alerts carry the rule's name + MITRE (came from a matched rule)
    assert any(a["rule_name"] and a["mitre_tech_id"] for a in after["items"])


def test_log_ingestion_parses_and_detects(client, auth):
    """Native collector: raw log lines → events → rule-driven alerts."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    before = client.get("/siem/alerts", headers=auth).json()["total"]
    lines = [
        "Jan 10 03:22:01 web01 sshd[2451]: Failed password for root from 45.9.1.2 port 51110",
        '192.0.2.55 - admin [10/Jan/2025:03:22:05] "GET /index.php?id=1\' OR 1=1-- HTTP/1.1" 200',
        '{"event_type":"beacon","src_ip":"10.0.0.9","dest_ip":"185.2.3.4","dest_port":443}',
        "src=10.0.0.5 dst=8.8.8.8 user=svc-backup msg=normal traffic",
    ]
    r = client.post("/siem/ingest", json={"lines": lines, "format": "auto"}, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["parsed"] == 4 and body["alerts"] >= 2  # failed_login, web sqli, beacon fire rules
    assert client.get("/siem/alerts", headers=auth).json()["total"] > before
    bf = client.get("/siem/alerts?q=45.9.1.2", headers=auth).json()
    assert bf["total"] >= 1 and any(a["src_ip"] == "45.9.1.2" for a in bf["items"])
    # guard rails
    assert client.post("/siem/ingest", json={"lines": []}, headers=auth).status_code == 400
    assert client.post("/siem/ingest", json={"lines": ["x"], "format": "bogus"}, headers=auth).status_code == 400


def test_attack_coverage(client, auth):
    cov = client.get("/siem/attack-coverage", headers=auth).json()
    assert "tactics" in cov and "summary" in cov
    assert cov["summary"]["techniques"] > 0
    assert "coveragePct" in cov["summary"]
    # each technique entry has the coverage fields
    techs = [t for tac in cov["tactics"] for t in tac["techniques"]]
    assert all("covered" in t and "rules" in t and "alerts" in t for t in techs)


def test_global_search(client, auth):
    # seed some data via the engine, then search across stores
    client.post("/config/engine", json={"generate": 6}, headers=auth)
    r = client.get("/search?q=a", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert "results" in body and isinstance(body["results"], list)
    assert all({"kind", "label", "link"} <= set(x) for x in body["results"])
    assert client.get("/search?q=", headers=auth).status_code == 422  # min_length


def test_notifications_centre(client, auth):
    client.post("/config/engine", json={"generate": 8}, headers=auth)
    n = client.get("/notifications", headers=auth).json()
    assert "items" in n and "unread" in n
    if n["items"]:
        nid = n["items"][0]["id"]
        assert client.post("/notifications/read", json={"id": nid}, headers=auth).json()["ok"]
    # mark all read
    client.post("/notifications/read", json={}, headers=auth)
    assert client.get("/notifications", headers=auth).json()["unread"] == 0


def test_report_schedules(client, auth):
    s = client.post("/report-schedules", json={"kind": "executive", "cadence": "weekly",
                                               "webhook_url": "https://example.com/hook"}, headers=auth)
    assert s.status_code == 201, s.text
    sid = s.json()["id"]
    assert client.post("/report-schedules", json={"kind": "bogus"}, headers=auth).status_code == 400
    run = client.post(f"/report-schedules/{sid}/run", headers=auth).json()
    assert run["generated"] is True and "title" in run
    assert any(x["id"] == sid for x in client.get("/report-schedules", headers=auth).json())
    assert client.delete(f"/report-schedules/{sid}", headers=auth).status_code == 204


def test_saved_views(client, auth):
    v = client.post("/saved-views", json={"section": "siem", "name": "Critical only",
                                          "filters": {"severity": "critical"}}, headers=auth)
    assert v.status_code == 201
    vid = v.json()["id"]
    views = client.get("/saved-views?section=siem", headers=auth).json()
    assert any(x["id"] == vid and x["filters"]["severity"] == "critical" for x in views)
    assert client.delete(f"/saved-views/{vid}", headers=auth).status_code == 204


def test_audit_export_and_retention(client, auth):
    # generate some auditable activity
    client.post("/config/engine", json={"generate": 4}, headers=auth)
    exp = client.get("/config/audit-export", headers=auth)
    assert exp.status_code == 200 and "text/csv" in exp.headers["content-type"]
    assert "ts,actor,action" in exp.text
    ret = client.post("/config/retention/enforce", headers=auth).json()
    assert "retentionDays" in ret and "purged" in ret


def test_playbook_real_execution(client, auth):
    """A playbook's steps act on the real stores: block IP → IOC blocklist,
    case opened, triggering alert resolved, notification raised, run recorded."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "198.51.100.201"
    line = f"Jan 10 08:00:00 web01 sshd[3]: Failed password for admin from {ip} port 4022"
    client.post("/siem/ingest", json={"lines": [line]}, headers=auth)
    alert = client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]
    assert alert["severity"] == "high"

    pb = client.post("/soar/playbooks", json={
        "name": "PyTest Containment", "category": "Network",
        "steps": [
            {"kind": "enrich", "name": "Enrich"},
            {"kind": "condition", "name": "High?",
             "params": {"field": "severity", "op": "in", "value": "critical,high"}},
            {"kind": "block_ip", "name": "Block"},
            {"kind": "create_case", "name": "Case"},
            {"kind": "close_alerts", "name": "Close"},
            {"kind": "notify", "name": "Notify"},
        ]}, headers=auth)
    assert pb.status_code == 201, pb.text
    pid = pb.json()["id"]

    r = client.post(f"/soar/playbooks/{pid}/run", json={"alert_id": alert["id"]}, headers=auth)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["runs"] == 1 and out["last_run_status"] == "success"
    run = out["run"]
    assert run["status"] == "success" and run["trigger"] == "manual"
    assert all(s["status"] == "success" for s in run["steps"]), run["steps"]

    # the IP is now on the blocklist (critical IOC)
    hit = client.get(f"/cti/lookup?value={ip}", headers=auth).json()
    assert hit["found"] is True
    blocked = client.get(f"/cti/iocs?q={ip}", headers=auth).json()["items"][0]
    assert blocked["severity"] == "critical"
    # a case was opened by the playbook (drives the real automation rate)
    cases = client.get("/soar/cases", headers=auth).json()
    assert any(c["playbook"] == "PyTest Containment" for c in cases)
    # the triggering alert is resolved
    after = client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]
    assert after["status"] == "resolved" and after["disposition"] == "true-positive"
    # the run is in the history feeds
    assert any(x["id"] == run["id"] for x in client.get(f"/soar/playbooks/{pid}/runs", headers=auth).json())
    assert any(x["id"] == run["id"] for x in client.get("/soar/runs", headers=auth).json()["items"])
    # a playbook notification was raised
    notes = client.get("/notifications", headers=auth).json()["items"]
    assert any(n["type"] == "playbook" for n in notes)


def test_playbook_dry_run_no_side_effects(client, auth):
    """Dry-run previews every step without writing anything."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "198.51.100.202"
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 08:10:00 web01 sshd[4]: Failed password for root from {ip} port 4023"]},
        headers=auth)
    alert = client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]
    pb = client.post("/soar/playbooks", json={
        "name": "PyTest DryRun", "steps": [
            {"kind": "block_ip", "name": "Block"},
            {"kind": "create_case", "name": "Case"},
        ]}, headers=auth).json()

    cases_before = len(client.get("/soar/cases", headers=auth).json())
    dr = client.post(f"/soar/playbooks/{pb['id']}/run",
                     json={"dry_run": True, "alert_id": alert["id"]}, headers=auth).json()
    assert dr["dryRun"] is True
    assert all(s["status"] == "success" for s in dr["run"]["steps"])
    assert "Would push" in dr["run"]["steps"][0]["detail"]
    # nothing was written: no IOC, no case, no run counter, alert untouched
    assert client.get(f"/cti/lookup?value={ip}", headers=auth).json()["found"] is False
    assert len(client.get("/soar/cases", headers=auth).json()) == cases_before
    assert client.get(f"/soar/playbooks/{pb['id']}", headers=auth).json()["runs"] == 0
    assert client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]["status"] == "new"
    assert client.get(f"/soar/playbooks/{pb['id']}/runs", headers=auth).json() == []


def test_playbook_approval_flow(client, auth):
    """An approval step pauses the run; approve resumes it, reject cancels it."""
    pb = client.post("/soar/playbooks", json={
        "name": "PyTest Approval", "steps": [
            {"kind": "approval", "name": "Gate", "params": {"message": "Sign-off required"}},
            {"kind": "notify", "name": "After"},
        ]}, headers=auth).json()

    r1 = client.post(f"/soar/playbooks/{pb['id']}/run", headers=auth).json()
    run1 = r1["run"]
    assert run1["status"] == "awaiting-approval"
    assert run1["steps"][0]["status"] == "pending-approval"
    listed = client.get("/soar/runs?status=awaiting-approval", headers=auth).json()
    assert listed["awaitingApproval"] >= 1 and any(x["id"] == run1["id"] for x in listed["items"])
    # an approval notification was raised
    notes = client.get("/notifications", headers=auth).json()["items"]
    assert any(n["type"] == "approval" for n in notes)

    approved = client.post(f"/soar/runs/{run1['id']}/approve", headers=auth).json()
    assert approved["status"] == "success"
    by_name = {s["name"]: s for s in approved["steps"]}
    assert "Approved by" in by_name["Gate"]["detail"] and by_name["After"]["status"] == "success"
    # approving a finished run is a conflict; unknown run 404
    assert client.post(f"/soar/runs/{run1['id']}/approve", headers=auth).status_code == 409
    assert client.post("/soar/runs/nope/approve", headers=auth).status_code == 404

    # reject path
    run2 = client.post(f"/soar/playbooks/{pb['id']}/run", headers=auth).json()["run"]
    rejected = client.post(f"/soar/runs/{run2['id']}/reject", headers=auth).json()
    assert rejected["status"] == "rejected"
    steps = {s["name"]: s["status"] for s in rejected["steps"]}
    assert steps["Gate"] == "failed" and steps["After"] == "skipped"


def test_playbook_condition_gates_run(client, auth):
    """A failed condition gates the run: later steps skip, run still succeeds."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "198.51.100.203"
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 08:20:00 web01 sshd[5]: Failed password for root from {ip} port 4024"]},
        headers=auth)
    alert = client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]  # high
    pb = client.post("/soar/playbooks", json={
        "name": "PyTest Gate", "steps": [
            {"kind": "condition", "name": "Critical only",
             "params": {"field": "severity", "op": "in", "value": "critical"}},
            {"kind": "block_ip", "name": "Block"},
        ]}, headers=auth).json()
    run = client.post(f"/soar/playbooks/{pb['id']}/run",
                      json={"alert_id": alert["id"]}, headers=auth).json()["run"]
    assert run["status"] == "success"
    assert "not met" in run["steps"][0]["detail"]
    assert run["steps"][1]["status"] == "skipped"
    # the gated block never happened
    assert client.get(f"/cti/lookup?value={ip}", headers=auth).json()["found"] is False


def test_playbook_auto_trigger(client, auth):
    """The automation engine runs matching auto playbooks on fresh alerts, once per alert."""
    from dashboard_api.engine import seed_builtin_rules
    from dashboard_api.playbook_engine import auto_trigger_playbooks
    from dashboard_api.db import get_conn
    seed_builtin_rules()
    ip = "198.51.100.204"
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 08:30:00 web01 sshd[6]: Failed password for root from {ip} port 4025"]},
        headers=auth)
    pb = client.post("/soar/playbooks", json={
        "name": "PyTest AutoResponder", "trigger_type": "auto",
        "trigger_match": {"techniques": ["T1110"], "severities": ["high"]},
        "steps": [{"kind": "notify", "name": "Ping"}]}, headers=auth).json()

    with get_conn() as conn:
        started, _ = auto_trigger_playbooks(conn, max_runs=10)
        conn.commit()
    assert started >= 1
    runs = client.get(f"/soar/playbooks/{pb['id']}/runs", headers=auth).json()
    assert runs and runs[0]["trigger"] == "auto" and runs[0]["alert_id"]
    assert runs[0]["actor"] == "automation-engine"
    # per-alert idempotency: across many passes (the engine throttles to one
    # matching alert per playbook per pass), no alert ever gets two runs from
    # the same playbook
    for _ in range(8):
        with get_conn() as conn:
            auto_trigger_playbooks(conn, max_runs=10)
            conn.commit()
    runs = client.get(f"/soar/playbooks/{pb['id']}/runs?limit=100", headers=auth).json()
    pairs = [(r["playbook_id"], r["alert_id"]) for r in runs]
    assert len(pairs) == len(set(pairs))


def test_playbook_crud_validation(client, auth):
    """Step kinds are validated; steps are editable via PATCH."""
    bad = client.post("/soar/playbooks", json={
        "name": "Bad", "steps": [{"kind": "format_disk", "name": "x"}]}, headers=auth)
    assert bad.status_code == 400
    assert client.post("/soar/playbooks", json={
        "name": "Bad2", "trigger_type": "sometimes", "steps": []}, headers=auth).status_code == 400
    assert client.post("/soar/playbooks", json={
        "name": "Bad3", "steps": [{"kind": "notify"}]}, headers=auth).status_code == 400

    pb = client.post("/soar/playbooks", json={
        "name": "PyTest Editable", "steps": [{"kind": "notify", "name": "A"}]}, headers=auth).json()
    upd = client.patch(f"/soar/playbooks/{pb['id']}", json={
        "steps": [{"kind": "enrich", "name": "B"}, {"kind": "notify", "name": "C"}],
        "trigger_type": "auto", "trigger_match": {"severities": ["critical"]}}, headers=auth)
    assert upd.status_code == 200
    body = upd.json()
    assert [s["kind"] for s in body["steps"]] == ["enrich", "notify"]
    assert body["trigger_match"] == {"severities": ["critical"]}
    assert client.patch(f"/soar/playbooks/{pb['id']}", json={
        "steps": [{"kind": "bogus", "name": "x"}]}, headers=auth).status_code == 400
    assert client.patch("/soar/playbooks/missing", json={"enabled": False}, headers=auth).status_code == 404


SIGMA_SAMPLE = """
title: Suspicious brute force from scanner range
status: experimental
description: Multiple failed logins from a known scanner subnet
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  category: authentication
detection:
  selection:
    event_type: failed_login
    src_ip|cidr: 203.0.113.0/24
  condition: selection
level: high
"""


def test_sigma_import_export(client, auth):
    """Sigma YAML imports as a live, evaluable rule (and actually detects);
    export round-trips the original and generates Sigma for native rules."""
    r = client.post("/siem/rules/import-sigma", json={"yaml": SIGMA_SAMPLE}, headers=auth)
    assert r.status_code == 201, r.text
    rule = r.json()
    assert rule["severity"] == "high" and rule["source"] == "sigma"
    assert rule["mitre_tech_id"] == "T1110" and rule["mitre_tactic"] == "Credential Access"
    ops = {(c["field"], c["op"]) for c in rule["definition"]["conditions"]}
    assert ("event_type", "equals") in ops and ("src_ip", "cidr") in ops

    # the imported rule detects on live ingestion
    client.post("/siem/ingest", json={
        "lines": ["Jan 10 10:00:00 web01 sshd[9]: Failed password for root from 203.0.113.55 port 5050"]},
        headers=auth)
    hits = client.get("/siem/alerts?q=Suspicious brute force from scanner", headers=auth).json()
    assert hits["total"] >= 1

    # export: original YAML comes back for sigma-imported rules
    exp = client.get(f"/siem/rules/{rule['id']}/sigma", headers=auth).json()
    assert exp["source"] == "original" and "attack.t1110" in exp["yaml"]

    # native rules export as generated Sigma that parses back
    import yaml as _yaml
    native = client.post("/siem/rules", json={
        "name": "Native egress watch", "severity": "medium", "mitre_tech_id": "T1041",
        "definition": {"conditions": [{"field": "bytes_out", "op": "gte", "value": 1000000}],
                       "logic": "and",
                       "aggregation": {"groupBy": "src_ip", "threshold": 3, "windowMinutes": 5}}},
        headers=auth).json()
    gen = client.get(f"/siem/rules/{native['id']}/sigma", headers=auth).json()
    assert gen["source"] == "generated"
    doc = _yaml.safe_load(gen["yaml"])
    assert doc["title"] == "Native egress watch" and "count() by" in doc["detection"]["condition"]

    # guard rails
    assert client.post("/siem/rules/import-sigma", json={"yaml": "just a string"},
                       headers=auth).status_code == 400
    bad = SIGMA_SAMPLE.replace("condition: selection", "condition: selection and not filter")
    assert client.post("/siem/rules/import-sigma", json={"yaml": bad}, headers=auth).status_code == 400
    assert client.get("/siem/rules/NOPE/sigma", headers=auth).status_code == 404


def test_case_sla_and_related_evidence(client, auth):
    """Cases carry computed SLA tracking; /related links alerts, IOCs, playbook
    runs and a MITRE-mapped timeline through the case's entities."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "198.51.100.210"
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 09:00:00 web01 sshd[7]: Failed password for root from {ip} port 4030"]},
        headers=auth)
    case = client.post("/soar/cases", json={
        "title": "SLA + evidence test case", "severity": "high", "sla_hours": 8,
        "entities": [{"type": "ip", "value": ip}]}, headers=auth).json()
    # SLA fields computed on every case read
    got = client.get(f"/soar/cases/{case['id']}", headers=auth).json()
    assert got["slaStatus"] == "within" and got["slaDeadline"] and got["slaElapsedPct"] >= 0
    assert all("slaStatus" in c for c in client.get("/soar/cases", headers=auth).json())
    assert "slaBreached" in client.get("/soar/metrics", headers=auth).json()

    rel = client.get(f"/soar/cases/{case['id']}/related", headers=auth).json()
    assert any(a["src_ip"] == ip for a in rel["alerts"])  # linked through the entity
    assert any(t["type"] == "alert" and t["technique"] == "T1110" for t in rel["timeline"])
    assert any(t["type"] == "system" for t in rel["timeline"])  # war-room entries merged
    assert {"technique": "T1110", "count": 1} in rel["techniques"] or \
        any(t["technique"] == "T1110" for t in rel["techniques"])
    assert client.get("/soar/cases/NOPE/related", headers=auth).status_code == 404
    # resolved fast → SLA met
    client.patch(f"/soar/cases/{case['id']}", json={"status": "resolved"}, headers=auth)
    assert client.get(f"/soar/cases/{case['id']}", headers=auth).json()["slaStatus"] == "met"


def test_post_incident_report(client, auth):
    """The incident report assembles timeline, response actions, SLA verdict
    and a lessons-learned scaffold for one case."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "198.51.100.211"
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 09:10:00 web01 sshd[8]: Failed password for root from {ip} port 4031"]},
        headers=auth)
    alert = client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]
    # respond via a playbook so the report has real response actions
    pb = client.post("/soar/playbooks", json={
        "name": "PyTest IR", "steps": [
            {"kind": "create_case", "name": "Case"},
            {"kind": "close_alerts", "name": "Close"},
        ]}, headers=auth).json()
    client.post(f"/soar/playbooks/{pb['id']}/run", json={"alert_id": alert["id"]}, headers=auth)
    case = next(c for c in client.get("/soar/cases", headers=auth).json()
                if c["playbook"] == "PyTest IR")

    r = client.get(f"/reports/incident?case_id={case['id']}", headers=auth)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["meta"]["kind"] == "incident" and case["id"] in rep["meta"]["title"]
    labels = {h["label"]: h["value"] for h in rep["summary"]["headline"]}
    assert labels["Linked alerts"] >= 1 and labels["Response actions"] >= 1
    assert "SLA" in labels
    assert any("playbook" in t["title"].lower() or t["status"] == "playbook"
               for t in rep["findings"])
    assert any("post-incident review" in x.lower() for x in rep["recommendations"])
    assert client.get("/reports/incident?case_id=NOPE", headers=auth).status_code == 404
    # the generic kinds endpoint still works (route ordering)
    assert client.get("/reports/siem?period=daily", headers=auth).status_code == 200


def test_ioc_lifecycle_units():
    """Pure decay model: half-life per type, expiry floor, status bands."""
    from datetime import datetime, timedelta, timezone
    from dashboard_api.ioc_lifecycle import effective_confidence, lifecycle_of
    now = datetime.now(timezone.utc)
    iso = lambda d: (now - timedelta(days=d)).isoformat()
    # fresh IP keeps ~full confidence
    assert effective_confidence(90, now.isoformat(), "ip", now) >= 88
    # one IP half-life (14d) ≈ half
    assert 40 <= effective_confidence(90, iso(14), "ip", now) <= 50
    # hashes decay far slower than IPs over the same span
    assert effective_confidence(90, iso(14), "sha256", now) > effective_confidence(90, iso(14), "ip", now)
    assert effective_confidence(90, iso(14), "sha256", now) >= 80
    # a long-stale IP falls under the expiry floor → expired
    aged = {"confidence": 90, "last_seen": iso(90), "type": "ip", "status": "active"}
    assert lifecycle_of(aged, now)["status"] == "expired"
    fresh = {"confidence": 90, "last_seen": now.isoformat(), "type": "ip", "status": "active"}
    assert lifecycle_of(fresh, now)["status"] == "active"
    # known-good is never auto-expired
    kg = {**aged, "status": "known-good"}
    assert lifecycle_of(kg, now)["status"] == "known-good"


def test_ioc_lifecycle_api(client, auth):
    """Sightings refresh + reactivate; known-good whitelists (stops TI matching
    and reads benign); decay maintenance runs; status filter + summary counts."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "192.0.2.77"
    imp = client.post("/cti/iocs/import", json={
        "indicators": [{"type": "ip", "value": ip}],
        "confidence": 90, "severity": "critical", "source": "test"}, headers=auth)
    assert imp.json()["imported"] == 1
    iid = client.get(f"/cti/iocs?q={ip}", headers=auth).json()["items"][0]["id"]

    # detail carries lifecycle + empty sightings history
    detail = client.get(f"/cti/iocs/{iid}", headers=auth).json()
    assert detail["lifecycle"]["status"] == "active" and detail["lifecycle"]["sightings"] == 1
    assert detail["sightingsHistory"] == []
    assert detail["lifecycle"]["effectiveConfidence"] >= 85

    # a manual sighting bumps the count, confidence, and history
    s = client.post(f"/cti/iocs/{iid}/sighting", json={"source": "analyst", "context": "seen in IR"}, headers=auth)
    assert s.status_code == 200 and s.json()["sightings"] == 2 and s.json()["confidence"] >= 95
    assert len(client.get(f"/cti/iocs/{iid}", headers=auth).json()["sightingsHistory"]) == 1

    # whitelist → known-good: lookup reads benign, list filter works
    assert client.post(f"/cti/iocs/{iid}/known-good", headers=auth).json()["status"] == "known-good"
    look = client.get(f"/cti/lookup?value={ip}", headers=auth).json()
    assert look["verdict"] == "benign" and look["knownGood"] is True
    assert any(x["id"] == iid for x in client.get("/cti/iocs?status=known-good", headers=auth).json()["items"])

    # known-good no longer raises a threat-intel alert on a matching event
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 11:00:00 fw01 traffic from {ip} allowed"]}, headers=auth)
    assert client.get(f"/siem/alerts?q={ip}", headers=auth).json()["total"] == 0

    # un-whitelist reactivates; now a matching event DOES raise R-TIMATCH + a sighting
    assert client.delete(f"/cti/iocs/{iid}/known-good", headers=auth).json()["status"] == "active"
    client.post("/siem/ingest", json={
        "lines": [f"Jan 10 11:05:00 fw01 traffic from {ip} allowed"]}, headers=auth)
    assert client.get(f"/siem/alerts?q={ip}", headers=auth).json()["total"] >= 1
    after = client.get(f"/cti/iocs/{iid}", headers=auth).json()
    assert after["sightings"] >= 3
    assert any(h["source"] == "siem:event" for h in after["sightingsHistory"])

    # decay maintenance runs and the summary exposes lifecycle bands
    dec = client.post("/cti/iocs/decay", headers=auth).json()
    assert {"scanned", "expired", "reactivated"} <= dec.keys()
    summ = client.get("/cti/summary", headers=auth).json()
    assert {"activeIocs", "expiredIocs", "knownGoodIocs"} <= summ.keys()

    # guard rails
    assert client.get("/cti/iocs/NOPE", headers=auth).status_code == 404
    assert client.post("/cti/iocs/NOPE/sighting", json={}, headers=auth).status_code == 404
    assert client.get("/cti/iocs?status=bogus", headers=auth).status_code == 400


def test_event_stream_broker_units():
    """The pub/sub broker fans messages to every subscriber and drops dead ones."""
    import queue
    from dashboard_api import events_stream as es
    a = es.subscribe()
    b = es.subscribe()
    try:
        n = es.publish("alert", {"id": "x"})
        assert n == 2 and es.subscriber_count() == 2
        ma = a.get_nowait(); mb = b.get_nowait()
        assert ma["type"] == "alert" and ma["data"] == {"id": "x"} and "ts" in ma
        assert mb["type"] == "alert"
    finally:
        es.unsubscribe(a); es.unsubscribe(b)
    # after unsubscribe nobody receives
    assert es.publish("alert", {"id": "y"}) == 0
    # a full queue is dropped, never raises
    c = es.subscribe()
    try:
        for _ in range(es._MAX_QUEUED + 5):
            es.publish("noise", {})
        assert c.qsize() <= es._MAX_QUEUED  # bounded, no exception
    finally:
        es.unsubscribe(c)


def test_stream_auth_and_live_publish(client, auth, admin_token):
    """The SSE endpoint requires a valid token; notify()/dispatch() push to the
    broker so live clients update without polling."""
    from dashboard_api import events_stream as es
    # auth guard: no token / bad token rejected (don't open the stream itself —
    # it would block; the guard runs before streaming begins)
    assert client.get("/stream").status_code == 401
    assert client.get("/stream?token=not-a-jwt").status_code == 401
    assert client.get("/stream/health", headers=auth).json()["subscribers"] >= 0

    # a notification (engine path) publishes a 'notification' event to subscribers
    sub = es.subscribe()
    try:
        client.post("/config/engine", json={"generate": 8}, headers=auth)
        kinds = []
        import queue as _q
        try:
            while True:
                kinds.append(sub.get_nowait()["type"])
        except _q.Empty:
            pass
        assert any(k in ("notification", "tick", "alert.created", "case.created") for k in kinds), kinds
    finally:
        es.unsubscribe(sub)


def test_stix_serialization_units():
    """STIX 2.1: correct patterns per indicator type, SDOs, deterministic ids."""
    from dashboard_api import stix
    ip = stix.ioc_to_stix({"type": "ip", "value": "203.0.113.9", "confidence": 80,
                           "first_seen": "2025-01-01T00:00:00", "threat_type": "c2"})
    assert ip["type"] == "indicator" and ip["pattern"] == "[ipv4-addr:value = '203.0.113.9']"
    assert ip["pattern_type"] == "stix" and ip["spec_version"] == "2.1"
    assert "command-and-control" in ip["indicator_types"]
    assert stix.stix_pattern("domain", "evil.com") == "[domain-name:value = 'evil.com']"
    assert stix.stix_pattern("hash", "a" * 64) == "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"
    assert stix.stix_pattern("hash", "b" * 32) == "[file:hashes.'MD5' = '" + "b" * 32 + "']"
    assert stix.stix_pattern("url", "http://x/y") == "[url:value = 'http://x/y']"
    # CVE → vulnerability SDO, not an indicator
    cve = stix.ioc_to_stix({"type": "cve", "value": "CVE-2024-1234", "first_seen": "2025-01-01T00:00:00"})
    assert cve["type"] == "vulnerability" and cve["external_references"][0]["external_id"] == "CVE-2024-1234"
    # deterministic ids — re-serializing the same value is stable
    assert ip["id"] == stix.ioc_to_stix({"type": "ip", "value": "203.0.113.9"})["id"]
    # actor + relationship wiring
    objs = stix.build_objects(
        [{"type": "ip", "value": "203.0.113.9", "actor": "APT-Test", "confidence": 90}],
        [{"name": "APT-Test", "type": "nation-state", "aliases": ["AT"], "sophistication": 4}])
    types = [o["type"] for o in objs]
    assert "threat-actor" in types and "indicator" in types and "relationship" in types
    rel = next(o for o in objs if o["type"] == "relationship")
    assert rel["relationship_type"] == "indicates"
    b = stix.bundle(objs)
    assert b["type"] == "bundle" and b["id"].startswith("bundle--") and b["objects"] == objs


def test_taxii_server(client, auth):
    """TAXII 2.1 read API: discovery → collections → STIX objects, with auth
    by JWT or API key, type filtering, and a downloadable bundle."""
    # discovery + api root
    disc = client.get("/taxii2/", headers=auth)
    assert disc.status_code == 200 and "taxii+json" in disc.headers["content-type"]
    assert disc.json()["api_roots"] and disc.json()["api_roots"][0].endswith("/taxii2/api/")
    assert TAXII_VERSIONS(client, auth)

    # collections list has both served collections
    cols = client.get("/taxii2/api/collections/", headers=auth).json()["collections"]
    ids = {c["id"] for c in cols}
    assert {"indicators", "threat-actors"} <= ids and all(c["can_read"] for c in cols)

    # indicator objects are real STIX 2.1
    objs = client.get("/taxii2/api/collections/indicators/objects/", headers=auth).json()
    assert "objects" in objs and "more" in objs
    kinds = {o["type"] for o in objs["objects"]}
    assert kinds <= {"indicator", "vulnerability", "relationship"}
    assert all(o.get("spec_version") == "2.1" for o in objs["objects"])
    # type filter
    only_ind = client.get("/taxii2/api/collections/indicators/objects/?type=indicator&limit=5",
                          headers=auth).json()["objects"]
    assert all(o["type"] == "indicator" for o in only_ind) and len(only_ind) <= 5
    # actors collection
    actors = client.get("/taxii2/api/collections/threat-actors/objects/", headers=auth).json()["objects"]
    assert actors and all(o["type"] == "threat-actor" for o in actors)
    # unknown collection
    assert client.get("/taxii2/api/collections/nope/", headers=auth).status_code == 404

    # auth is enforced; a platform API key also works as a bearer credential
    assert client.get("/taxii2/api/").status_code == 401
    key = client.post("/config/api-keys", json={"name": "TAXII puller", "scope": "read"},
                      headers=auth).json()["secret"]
    keyed = client.get("/taxii2/api/", headers={"Authorization": f"Bearer {key}"})
    assert keyed.status_code == 200

    # downloadable STIX bundle (same content the TAXII server publishes)
    bundle = client.get("/cti/stix/bundle", headers=auth).json()
    assert bundle["type"] == "bundle" and isinstance(bundle["objects"], list) and bundle["objects"]
    ta = client.get("/cti/stix/bundle?type=threat-actor", headers=auth).json()
    assert all(o["type"] == "threat-actor" for o in ta["objects"])


def TAXII_VERSIONS(client, auth) -> bool:
    root = client.get("/taxii2/api/", headers=auth).json()
    return "application/taxii+json;version=2.1" in root["versions"]


def test_ueba_entity_risk(client, auth):
    """UEBA: entities ranked by alert-derived risk, with drill-down timeline."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    client.post("/config/engine", json={"generate": 12}, headers=auth)
    ent = client.get("/siem/entities?type=ip&limit=10", headers=auth).json()
    assert "entities" in ent and "summary" in ent
    if ent["entities"]:
        e = ent["entities"][0]
        assert {"value", "type", "risk", "alerts", "band", "techniqueCount"} <= set(e)
        assert 0 <= e["risk"] <= 100
        # risk is sorted descending
        risks = [x["risk"] for x in ent["entities"]]
        assert risks == sorted(risks, reverse=True)
        # drill-down
        d = client.get(f"/siem/entities/detail?type=ip&value={e['value']}", headers=auth).json()
        assert d["value"] == e["value"] and "timeline" in d and "alerts" in d
        assert "topTechniques" in d
    # all-types ranking works
    assert client.get("/siem/entities?type=all", headers=auth).status_code == 200
    assert client.get("/siem/entities?type=bogus", headers=auth).status_code == 422


def test_alert_suppression_lifecycle(client, auth):
    """Alert tuning: a suppression retro-closes open alerts for an entity and
    drops future matching detections (with a hit counter), then can be removed."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "203.0.113.201"
    bf = f"Jan 10 04:00:00 web01 sshd[111]: Failed password for root from {ip} port 51110"

    # 1) Baseline: a brute-force line produces an open alert for this IP.
    client.post("/siem/ingest", json={"lines": [bf], "format": "auto"}, headers=auth)
    got = client.get(f"/siem/alerts?q={ip}", headers=auth).json()
    assert got["total"] >= 1 and any(a["status"] not in ("resolved", "closed") for a in got["items"])

    # 2) Suppress the IP → retro-closes the open alert(s) as false-positive.
    s = client.post("/siem/suppressions",
                    json={"value": ip, "field": "src_ip", "reason": "known scanner"}, headers=auth)
    assert s.status_code == 201, s.text
    sid = s.json()["id"]
    assert s.json()["rule_id"] == "*" and s.json()["mode"] == "suppress"
    closed = client.get(f"/siem/alerts?q={ip}", headers=auth).json()
    assert all(a["status"] == "closed" and a["disposition"] == "false-positive" for a in closed["items"])
    base = closed["total"]

    # 3) Re-ingest the same line → the suppression drops it (no new alert) and
    #    its hit counter increments.
    client.post("/siem/ingest", json={"lines": [bf], "format": "auto"}, headers=auth)
    again = client.get(f"/siem/alerts?q={ip}", headers=auth).json()
    assert again["total"] == base  # nothing new fired
    supp = next(x for x in client.get("/siem/suppressions", headers=auth).json() if x["id"] == sid)
    assert supp["hits"] >= 1

    # validation guards
    assert client.post("/siem/suppressions", json={"value": ip, "field": "x"}, headers=auth).status_code == 400
    assert client.post("/siem/suppressions", json={"value": ip, "mode": "x"}, headers=auth).status_code == 400
    assert client.post("/siem/suppressions", json={"value": "   "}, headers=auth).status_code == 400

    # 4) Remove the suppression → detection fires again for the entity.
    assert client.delete(f"/siem/suppressions/{sid}", headers=auth).status_code == 204
    assert client.delete(f"/siem/suppressions/{sid}", headers=auth).status_code == 404
    client.post("/siem/ingest", json={"lines": [bf], "format": "auto"}, headers=auth)
    revived = client.get(f"/siem/alerts?q={ip}", headers=auth).json()
    assert revived["total"] > base and any(a["status"] not in ("resolved", "closed") for a in revived["items"])


def test_event_search_language(client, auth):
    """Real field-operator search over the raw event stream + stats aggregation."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    lines = [
        "Jan 10 06:00:00 web01 sshd[1]: Failed password for root from 203.0.113.41 port 5000",
        "Jan 10 06:00:01 web01 sshd[2]: Failed password for admin from 203.0.113.41 port 5001",
        '{"event_type":"beacon","src_ip":"10.0.0.7","dest_ip":"185.9.9.9","dest_port":443}',
    ]
    client.post("/siem/ingest", json={"lines": lines, "format": "auto"}, headers=auth)

    # field equality
    r = client.post("/siem/search", json={"query": "event_type=failed_login", "time_range": "24h"}, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hits"] >= 2 and all(x["event_type"] == "failed_login" for x in body["results"])
    assert body["scanned"] >= body["hits"]

    # a specific value isolates the two ingested rows for this src
    bysrc = client.post("/siem/search", json={"query": "src_ip=203.0.113.41"}, headers=auth).json()
    assert bysrc["hits"] >= 2 and all(x["src_ip"] == "203.0.113.41" for x in bysrc["results"])

    # numeric operator + AND of conditions
    num = client.post("/siem/search", json={"query": "event_type=beacon dest_port>=443"}, headers=auth).json()
    assert num["hits"] >= 1 and all(x["event_type"] == "beacon" for x in num["results"])

    # bare token → full-text over the raw line
    ft = client.post("/siem/search", json={"query": "beacon"}, headers=auth).json()
    assert ft["hits"] >= 1

    # membership operator
    mem = client.post("/siem/search", json={"query": "event_type in failed_login,beacon"}, headers=auth).json()
    assert mem["hits"] >= 3

    # stats aggregation groups by a field
    agg = client.post("/siem/search",
                      json={"query": "event_type=failed_login | stats count by src_ip"}, headers=auth).json()
    assert agg["stats"]["by"] == "src_ip" and agg["results"] == []
    grp = next((g for g in agg["stats"]["groups"] if g["value"] == "203.0.113.41"), None)
    assert grp and grp["count"] >= 2
    # the parser surfaces how it interpreted the query
    assert any(c["field"] == "event_type" and c["op"] == "equals" for c in agg["interpreted"]["conditions"])

    # bad time range rejected
    assert client.post("/siem/search", json={"query": "x", "time_range": "1y"}, headers=auth).status_code == 400


def test_ecs_field_normalization():
    """ECS aliases resolve to native fields so rules/searches are vendor-neutral."""
    from dashboard_api.rule_engine import matches_event, canonical_field
    from dashboard_api.hunting import parse_query
    assert canonical_field("source.ip") == "src_ip"
    assert canonical_field("user.name") == "username"
    assert canonical_field("src_ip") == "src_ip"  # native passes through
    e = {"src_ip": "10.0.0.5", "username": "root", "event_type": "failed_login", "dest_port": 443}
    # an ECS-authored condition matches the native event field
    assert matches_event(e, {"conditions": [{"field": "source.ip", "op": "equals", "value": "10.0.0.5"}], "logic": "and"})
    assert matches_event(e, {"conditions": [{"field": "user.name", "op": "equals", "value": "root"}], "logic": "and"})
    assert matches_event(e, {"conditions": [{"field": "destination.port", "op": "gte", "value": 443}], "logic": "and"})
    assert not matches_event(e, {"conditions": [{"field": "source.ip", "op": "equals", "value": "1.1.1.1"}], "logic": "and"})
    # the search parser recognises ECS names (and the stats clause groups native)
    p = parse_query("source.ip=10.0.0.5 event.action=block | stats count by user.name")
    fields = {(c["field"], c["op"]) for c in p["conditions"]}
    assert ("source.ip", "equals") in fields and ("event.action", "equals") in fields
    assert p["stats"] == {"by": "username"}  # canonicalised for grouping


def test_ecs_search_endpoint(client, auth):
    """An ECS-authored event search resolves to native fields and returns hits."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    client.post("/siem/ingest", json={"lines": [
        "Jan 10 07:00:00 web01 sshd[9]: Failed password for root from 203.0.113.77 port 9000",
    ], "format": "auto"}, headers=auth)
    r = client.post("/siem/search", json={"query": "source.ip=203.0.113.77"}, headers=auth).json()
    assert r["hits"] >= 1 and all(x["src_ip"] == "203.0.113.77" for x in r["results"])
    # rule-schema advertises the ECS alias map
    sch = client.get("/siem/rule-schema", headers=auth).json()
    assert sch["ecsAliases"]["source.ip"] == "src_ip"


def test_event_search_parser_units():
    """Pure parser: operators, membership, freetext, and the stats clause."""
    from dashboard_api.hunting import parse_query
    p = parse_query('src_ip=10.0.0.5 bytes_out>=100 raw~"OR 1=1" powershell | stats count by hostname')
    ops = {(c["field"], c["op"], c["value"]) for c in p["conditions"]}
    assert ("src_ip", "equals", "10.0.0.5") in ops
    assert ("bytes_out", "gte", "100") in ops
    assert ("raw", "regex", "OR 1=1") in ops           # quoted value with spaces survives
    assert p["freetext"] == ["powershell"]
    assert p["stats"] == {"by": "hostname"}
    # membership + an unknown field stays as free text
    p2 = parse_query("username in svc-backup,svc-deploy notafield=x")
    assert ({"field": "username", "op": "in", "value": "svc-backup,svc-deploy"} in p2["conditions"])
    assert "notafield=x" in p2["freetext"]


def test_fp_feedback_bumps_rule_fp_rate(client, auth):
    """Marking an alert false-positive raises its rule's FP rate (a tuning signal)."""
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    ip = "203.0.113.214"
    bf = f"Jan 10 05:00:00 web01 sshd[222]: Failed password for root from {ip} port 33000"
    client.post("/siem/ingest", json={"lines": [bf], "format": "auto"}, headers=auth)
    alert = client.get(f"/siem/alerts?q={ip}", headers=auth).json()["items"][0]
    before = next(r for r in client.get("/siem/rules", headers=auth).json() if r["id"] == "R-BRUTEFORCE")["fp_rate"]
    client.patch(f"/siem/alerts/{alert['id']}", json={"disposition": "false-positive"}, headers=auth)
    after = next(r for r in client.get("/siem/rules", headers=auth).json() if r["id"] == "R-BRUTEFORCE")["fp_rate"]
    assert after == min(100, before + 2)
