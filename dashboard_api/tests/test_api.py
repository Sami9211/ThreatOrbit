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
    assert any(k["name"] == "CI" for k in client.get("/config/api-keys", headers=auth).json())


def test_viewer_cannot_create_user(client):
    # log in as the seeded viewer
    tok = client.post("/auth/login", json={"email": "tom.okafor@threatorbit.space", "password": "Password123!"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/users", json={"email": "x@y.com", "name": "X", "role": "analyst", "password": "Password123!"}, headers=h)
    assert r.status_code == 403
