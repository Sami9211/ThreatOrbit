"""Evidence-based false-positive scoring (dashboard_api/fp_scoring.py).

Pins each signal's direction and rough magnitude, the neutral-midpoint /
banding behaviour, and the plan's explicit testing discipline: a real
multi-stage attack (correlated alerts + a known-bad IOC match) must still
land in the "likely-real" band even with one weak FP-leaning signal present
-- no single weak signal may outweigh several strong ones.
"""
import datetime as _dt
import uuid

from dashboard_api.db import get_conn
from dashboard_api.fp_scoring import score_alert, score_ioc


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _insert_alert(conn, tag, *, severity="high", status="new", rule_id=None, rule_name=None,
                   src_ip=None, username=None, hostname=None, dest_ip=None,
                   disposition="undetermined", ts=None):
    aid = f"FPT-{tag}-{uuid.uuid4().hex[:6]}"
    ts = ts or _now()
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
        "rule_id,rule_name,src_ip,username,hostname,dest_ip,description,raw_log,event_count,"
        "ti_hits,org_id) VALUES (?,?,?,?,?,?,'',50,?,?,?,?,?,?,?,'',1,0,'org-default')",
        (aid, ts, f"FPT-{tag}", severity, status, disposition, rule_id, rule_name,
         src_ip, username, hostname, dest_ip, tag))
    return aid


def _insert_ioc(conn, tag, *, value, ioc_type="ip", status="active", severity="high", sightings=1):
    iid = f"FPT-IOC-{tag}-{uuid.uuid4().hex[:6]}"
    conn.execute(
        "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
        "first_seen,last_seen,tags,status,sightings,org_id) VALUES "
        "(?,?,?,?,50,?,'test','',?,?,'[]',?,?,'org-default')",
        (iid, ioc_type, value, tag, severity, _now(), _now(), status, sightings))
    return iid


def _insert_asset(conn, tag, *, value, criticality="low"):
    aid = f"FPT-ASSET-{tag}"
    conn.execute(
        "INSERT INTO assets (id,name,type,value,criticality,status,risk_score,last_scan,"
        "alerts,cves,open_ports,os,owner,patch_age,tags,uptime,created_at,software,org_id) "
        "VALUES (?,?,?,?,?,'clean',0,NULL,0,'{}','[]',NULL,'',0,'[]',100.0,?,'[]','org-default')",
        (aid, tag, "server", value, criticality, _now()))
    return aid


def _insert_rule(conn, tag, *, fp_rate=0.0):
    rid = f"FPT-RULE-{tag}"
    conn.execute(
        "INSERT INTO detection_rules (id,name,category,severity,fp_rate,status,source,org_id) "
        "VALUES (?,?,?,?,?,'enabled','custom','org-default')",
        (rid, rid, "test", "high", fp_rate))
    return rid


def _insert_suppression(conn, tag, *, rule_id, field, value):
    sid = f"FPT-SUP-{tag}-{uuid.uuid4().hex[:6]}"
    conn.execute(
        "INSERT INTO suppressions (id,rule_id,field,value,mode,created_at,org_id) "
        "VALUES (?,?,?,?,'suppress',?,'org-default')",
        (sid, rule_id, field, value, _now()))
    return sid


def _insert_enrichment(tag, value, provider, verdict):
    with get_conn() as conn:
        eid = f"FPT-ENR-{tag}-{uuid.uuid4().hex[:6]}"
        conn.execute(
            "INSERT INTO ioc_enrichments (id,ioc_value,provider,verdict,summary,data,ts) "
            "VALUES (?,?,?,?,?,'{}',?)",
            (eid, value, provider, verdict, verdict, _now()))
        conn.commit()


def _cleanup(tag):
    with get_conn() as conn:
        conn.execute("DELETE FROM alerts WHERE id LIKE ?", (f"FPT-{tag}-%",))
        conn.execute("DELETE FROM iocs WHERE id LIKE ?", (f"FPT-IOC-{tag}-%",))
        conn.execute("DELETE FROM assets WHERE id LIKE ?", (f"FPT-ASSET-{tag}%",))
        conn.execute("DELETE FROM detection_rules WHERE id LIKE ?", (f"FPT-RULE-{tag}%",))
        conn.execute("DELETE FROM suppressions WHERE id LIKE ?", (f"FPT-SUP-{tag}-%",))
        conn.execute("DELETE FROM ioc_enrichments WHERE id LIKE ?", (f"FPT-ENR-{tag}-%",))
        conn.commit()


def test_no_evidence_is_neutral_uncertain():
    tag = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        aid = _insert_alert(conn, tag, severity="medium")
        conn.commit()
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        from dashboard_api.db import row_to_dict
        try:
            result = score_alert(conn, row_to_dict(row))
        finally:
            _cleanup(tag)
    assert result["score"] == 50
    assert result["band"] == "uncertain"
    assert result["evidence"] == []


def test_rule_fp_history_pushes_toward_fp():
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    try:
        with get_conn() as conn:
            rid = _insert_rule(conn, tag, fp_rate=80.0)
            aid = _insert_alert(conn, tag, severity="medium", rule_id=rid)
            conn.commit()
            row = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone())
            result = score_alert(conn, row)
    finally:
        _cleanup(tag)
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("rule_fp_history") == 16   # min(20, round(80/5))
    assert result["score"] == 66


def test_asset_criticality_both_directions():
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    host = f"host-{tag}"
    try:
        with get_conn() as conn:
            _insert_asset(conn, tag, value=host, criticality="critical")
            aid = _insert_alert(conn, tag, severity="medium", hostname=host)
            conn.commit()
            row = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone())
            result = score_alert(conn, row)
    finally:
        _cleanup(tag)
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("asset_criticality") == -15


def test_correlated_activity_outweighs_isolation():
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    src = f"10.77.{int(tag[:2], 16) % 250}.{int(tag[2:4], 16) % 250}"
    try:
        with get_conn() as conn:
            # two other high/critical alerts on the same src_ip, close in time
            _insert_alert(conn, tag, severity="critical", src_ip=src)
            _insert_alert(conn, tag, severity="high", src_ip=src)
            target = _insert_alert(conn, tag, severity="high", src_ip=src)
            conn.commit()
            row = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (target,)).fetchone())
            result = score_alert(conn, row)
    finally:
        _cleanup(tag)
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("correlated_activity") == -20
    assert "isolated_alert" not in signals


def test_isolated_alert_is_mild_fp_signal():
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    src = f"10.88.{int(tag[:2], 16) % 250}.{int(tag[2:4], 16) % 250}"
    try:
        with get_conn() as conn:
            aid = _insert_alert(conn, tag, severity="high", src_ip=src)
            conn.commit()
            row = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone())
            result = score_alert(conn, row)
    finally:
        _cleanup(tag)
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("isolated_alert") == 8


def test_ioc_cross_reference_both_directions():
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    good_ip = f"10.11.{int(tag[:2], 16) % 250}.1"
    bad_ip = f"10.12.{int(tag[:2], 16) % 250}.2"
    try:
        with get_conn() as conn:
            _insert_ioc(conn, tag, value=good_ip, status="known-good", severity="low")
            a1 = _insert_alert(conn, tag, severity="medium", src_ip=good_ip)
            conn.commit()
            r1 = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (a1,)).fetchone())
            good_result = score_alert(conn, r1)

            _insert_ioc(conn, tag, value=bad_ip, status="active", severity="critical")
            a2 = _insert_alert(conn, tag, severity="medium", src_ip=bad_ip)
            conn.commit()
            r2 = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (a2,)).fetchone())
            bad_result = score_alert(conn, r2)
    finally:
        _cleanup(tag)
    good_signals = {e["signal"]: e["weight"] for e in good_result["evidence"]}
    bad_signals = {e["signal"]: e["weight"] for e in bad_result["evidence"]}
    assert good_signals.get("known_good_ioc") == 25
    assert bad_signals.get("malicious_ioc_match") == -25


def test_entity_fp_history_signal():
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    host = f"host-{tag}"
    try:
        with get_conn() as conn:
            rid = _insert_rule(conn, tag, fp_rate=0.0)
            _insert_alert(conn, tag, severity="high", rule_id=rid, hostname=host,
                          disposition="false-positive")
            target = _insert_alert(conn, tag, severity="high", rule_id=rid, hostname=host)
            conn.commit()
            row = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (target,)).fetchone())
            result = score_alert(conn, row)
    finally:
        _cleanup(tag)
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("entity_fp_history") == 8


def test_real_multistage_attack_stays_likely_real_despite_weak_fp_signal():
    """The testing-discipline case from plan.md: correlated high/critical
    alerts sharing a pivot, plus a known-bad IOC match, must still score
    likely-real (<=30) even with a weak FP-leaning signal (a low-criticality
    asset match) also present -- no single weak signal may dominate several
    strong ones."""
    tag = uuid.uuid4().hex[:8]
    from dashboard_api.db import row_to_dict
    src = f"10.44.{int(tag[:2], 16) % 250}.{int(tag[2:4], 16) % 250}"
    host = f"host-{tag}"
    try:
        with get_conn() as conn:
            # weak FP-leaning signal: the touched asset is low-criticality
            _insert_asset(conn, tag, value=host, criticality="low")
            # a known-bad IOC on the pivot IP
            _insert_ioc(conn, tag, value=src, status="active", severity="critical")
            # two corroborating high/critical alerts on the same src_ip
            _insert_alert(conn, tag, severity="critical", src_ip=src, hostname=host)
            _insert_alert(conn, tag, severity="high", src_ip=src, hostname=host)
            target = _insert_alert(conn, tag, severity="high", src_ip=src, hostname=host)
            conn.commit()
            row = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (target,)).fetchone())
            result = score_alert(conn, row)
    finally:
        _cleanup(tag)
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("correlated_activity") == -20
    assert signals.get("malicious_ioc_match") == -25
    assert signals.get("asset_criticality") == 10
    assert result["band"] == "likely-real", (
        f"real multi-stage attack scored {result['score']} ({result['band']}) -- "
        f"a weak signal dominated strong ones: {result['evidence']}")
    assert result["score"] <= 30


def test_ioc_enrichment_signals():
    tag = uuid.uuid4().hex[:8]
    malicious_val = f"evil-{tag}.test"
    benign_val = f"benign-{tag}.test"
    try:
        _insert_enrichment(tag, malicious_val, "virustotal", "malicious")
        _insert_enrichment(tag, malicious_val, "otx", "malicious")
        _insert_enrichment(tag, benign_val, "virustotal", "benign")
        with get_conn() as conn:
            bad = score_ioc(conn, {"value": malicious_val, "type": "domain"})
            good = score_ioc(conn, {"value": benign_val, "type": "domain"})
    finally:
        _cleanup(tag)
    bad_signals = {e["signal"]: e["weight"] for e in bad["evidence"]}
    good_signals = {e["signal"]: e["weight"] for e in good["evidence"]}
    assert bad_signals.get("multi_source_malicious") == -25
    assert bad["band"] == "likely-real"
    assert good_signals.get("enrichment_benign") == 20


def test_ioc_cloud_cdn_range_signal():
    with get_conn() as conn:
        result = score_ioc(conn, {"value": "104.16.5.5", "type": "ip"})
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("cloud_cdn_range") == 15


def test_ioc_sighted_but_never_alerted_signal():
    tag = uuid.uuid4().hex[:8]
    ip = f"10.55.{int(tag[:2], 16) % 250}.9"
    with get_conn() as conn:
        result = score_ioc(conn, {"value": ip, "type": "ip", "severity": "high", "sightings": 5})
    signals = {e["signal"]: e["weight"] for e in result["evidence"]}
    assert signals.get("no_alert_correlation") == 15


def test_alert_fp_assessment_endpoint(client, auth):
    tag = uuid.uuid4().hex[:8]
    try:
        with get_conn() as conn:
            aid = _insert_alert(conn, tag, severity="medium")
            conn.commit()
        r = client.get(f"/siem/alerts/{aid}/fp-assessment", headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == {"score", "band", "evidence"}
        assert 0 <= body["score"] <= 100
        assert body["band"] in ("likely-fp", "uncertain", "likely-real")
    finally:
        _cleanup(tag)
    assert client.get("/siem/alerts/does-not-exist/fp-assessment", headers=auth).status_code == 404


def test_ioc_fp_assessment_endpoint(client, auth):
    tag = uuid.uuid4().hex[:8]
    try:
        with get_conn() as conn:
            iid = _insert_ioc(conn, tag, value=f"10.66.1.{int(tag[:2], 16) % 250}")
            conn.commit()
        r = client.get(f"/cti/iocs/{iid}/fp-assessment", headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == {"score", "band", "evidence"}
        assert 0 <= body["score"] <= 100
    finally:
        _cleanup(tag)
    assert client.get("/cti/iocs/does-not-exist/fp-assessment", headers=auth).status_code == 404


def test_alerts_fp_triage_scores_and_filters_by_band(client, auth):
    """Phase 3: the bulk-triage view scores a working set and can filter to
    just one band -- a strong known-good match should land in likely-fp, a
    strong malicious match in likely-real, and each other band excludes it.

    fp-triage only scores the most recent N open alerts (see
    _FP_TRIAGE_WORKING_SET_CAP), so this test's alerts are timestamped far in
    the future - guaranteeing they sort at the very top of that window
    regardless of how much other data the full suite has accumulated in the
    shared test database."""
    tag = uuid.uuid4().hex[:8]
    good_ip = f"10.21.{int(tag[:2], 16) % 250}.1"
    bad_ip = f"10.22.{int(tag[:2], 16) % 250}.2"
    future_ts = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=3650)).replace(microsecond=0).isoformat()
    try:
        with get_conn() as conn:
            _insert_ioc(conn, tag, value=good_ip, status="known-good", severity="low")
            fp_alert = _insert_alert(conn, tag, severity="medium", src_ip=good_ip, ts=future_ts)
            _insert_ioc(conn, tag, value=bad_ip, status="active", severity="critical")
            # correlated siblings push this firmly into likely-real - a lone
            # malicious-IOC match is offset by the isolated-alert mild bonus
            # (see test_real_multistage_attack_... for the full calibration).
            _insert_alert(conn, tag, severity="critical", src_ip=bad_ip, ts=future_ts)
            _insert_alert(conn, tag, severity="high", src_ip=bad_ip, ts=future_ts)
            real_alert = _insert_alert(conn, tag, severity="medium", src_ip=bad_ip, ts=future_ts)
            conn.commit()

        # The unfiltered view sorts the *whole* (up to 300-alert) working set
        # by score descending and pages it - a rock-bottom scorer like
        # real_alert is expected to rank near the very end of that, not on
        # an early page, so band filtering (which filters *before* paging)
        # is the only way to reliably find either alert regardless of how
        # much other data is loaded in the shared working set. limit=200 is
        # the endpoint's max, for the widest safety margin.
        only_fp = client.get("/siem/alerts/fp-triage?band=likely-fp&limit=200", headers=auth).json()
        assert "total" in only_fp and "workingSetSize" in only_fp and "items" in only_fp
        fp_ids = {i["id"]: i for i in only_fp["items"]}
        assert fp_alert in fp_ids, "fp_alert not found on the likely-fp page (unexpectedly outranked)"
        assert fp_ids[fp_alert]["fpBand"] == "likely-fp"
        assert fp_ids[fp_alert]["fpScore"] >= 70
        assert real_alert not in fp_ids

        only_real = client.get("/siem/alerts/fp-triage?band=likely-real&limit=200", headers=auth).json()
        real_ids = {i["id"]: i for i in only_real["items"]}
        assert real_alert in real_ids, "real_alert not found on the likely-real page (unexpectedly outranked)"
        assert real_ids[real_alert]["fpBand"] == "likely-real"
        assert real_ids[real_alert]["fpScore"] <= 30
        assert fp_alert not in real_ids
    finally:
        _cleanup(tag)


def test_bulk_dismiss_alerts(client, auth):
    tag = uuid.uuid4().hex[:8]
    try:
        with get_conn() as conn:
            rid = _insert_rule(conn, tag, fp_rate=0.0)
            a1 = _insert_alert(conn, tag, severity="high", status="new", rule_id=rid, rule_name=rid)
            a2 = _insert_alert(conn, tag, severity="medium", status="new", rule_id=rid, rule_name=rid)
            conn.commit()

        r = client.post("/siem/alerts/bulk-dismiss",
                         json={"ids": [a1, a2, "does-not-exist"]}, headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["dismissed"] == 2
        assert body["notFound"] == ["does-not-exist"]

        with get_conn() as conn:
            rows = {row["id"]: row for row in conn.execute(
                "SELECT id, status, disposition FROM alerts WHERE id IN (?,?)", (a1, a2)).fetchall()}
            rule_row = conn.execute("SELECT fp_rate FROM detection_rules WHERE id=?", (rid,)).fetchone()
        assert rows[a1]["status"] == "closed" and rows[a1]["disposition"] == "false-positive"
        assert rows[a2]["status"] == "closed" and rows[a2]["disposition"] == "false-positive"
        assert rule_row["fp_rate"] == 2.0  # bumped once, not once per dismissed alert
    finally:
        _cleanup(tag)

    assert client.post("/siem/alerts/bulk-dismiss", json={"ids": []}, headers=auth).status_code == 400
