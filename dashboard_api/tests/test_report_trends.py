"""Report narratives carry an honest prior-window trend sentence: a real
movement (or flat) when the preceding window has data, an explicit no-baseline
note when it doesn't - never an invented movement."""
import datetime as dt
import uuid

from dashboard_api.db import get_conn


def test_siem_report_trend_sentence_computed(client, auth):
    # Plant one alert 36h back so the daily report's preceding window (24-48h
    # ago) is guaranteed non-empty regardless of seed/suite state.
    prior_ts = (dt.datetime.now(dt.timezone.utc)
                - dt.timedelta(hours=36)).replace(microsecond=0).isoformat()
    aid = f"RPT-{uuid.uuid4().hex[:10]}"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
            "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
            "VALUES (?,?,?, 'low','new','undetermined','',10,'R-RPT','rpt','','',1,0,'org-default')",
            (aid, prior_ts, "report trend test"))
        conn.commit()
    try:
        r = client.get("/reports/siem?period=daily", headers=auth)
        assert r.status_code == 200, r.text
        narrative = r.json()["summary"]["narrative"]
        assert "against the preceding window" in narrative, narrative
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE id=?", (aid,))
            conn.commit()


def test_all_report_kinds_still_build(client, auth):
    for kind in ("siem", "soar", "cti", "assets", "darkweb", "executive"):
        r = client.get(f"/reports/{kind}?period=weekly", headers=auth)
        assert r.status_code == 200, f"{kind}: {r.text[:200]}"
        body = r.json()
        assert body["summary"]["narrative"], f"{kind} narrative empty"


def test_siem_report_series_and_geo(client, auth):
    """The SIEM report carries a real, zero-filled per-day time series and (when
    alerts carry a source country) a geographic breakdown; the HTML render draws
    the trend line and the geo bar."""
    ts = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    aid = f"RPTG-{uuid.uuid4().hex[:10]}"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
            "rule_id,rule_name,description,raw_log,event_count,ti_hits,src_country,org_id) "
            "VALUES (?,?,?, 'high','new','undetermined','',80,'R-RPTG','rpt','','',1,0,'Russia','org-default')",
            (aid, ts, "geo trend test"))
        conn.commit()
    try:
        body = client.get("/reports/siem?period=weekly", headers=auth).json()
        series = body.get("series")
        assert series and series["points"], "no time series on SIEM report"
        assert all("date" in p and "count" in p for p in series["points"])
        assert sum(p["count"] for p in series["points"]) >= 1, "planted alert not counted"
        assert "Alert sources by country" in [b["heading"] for b in body["breakdowns"]]

        html = client.get("/reports/siem?period=weekly&format=html", headers=auth).text
        assert "trend line" in html, "trend line SVG missing from HTML"
        assert "Alert sources by country" in html, "geo breakdown missing from HTML"
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE id=?", (aid,))
            conn.commit()


# -- The CTI report: counted in SQL, and about what the platform knows ---------


def test_the_cti_report_does_not_materialise_the_store():
    """It used to `SELECT *` every indicator in the window and count them in
    Python. On a 327,981-row store that was 3.6 seconds and 547 MB of resident
    memory for ONE weekly report - and report schedules run unattended, so
    nobody is watching when several fire at once.

    A static check, because the failure is a regression in SHAPE: a later edit
    that reintroduces a row-by-row scan would still return correct numbers, and
    no assertion about the output would notice."""
    import inspect

    from dashboard_api import reports

    src = inspect.getsource(reports._cti_report)
    assert "SELECT * FROM iocs" not in src, (
        "the CTI report must aggregate in SQL, not load the store into memory")
    # One pass, not one per statistic: a report window is usually most of the
    # store, so every extra `WHERE last_seen BETWEEN …` is another full scan.
    assert src.count("FROM iocs WHERE last_seen") <= 2, (
        "each separate scan of `iocs` costs a full table read; the grid query "
        "and the top-50 findings are the only two that earn one")


def test_the_cti_report_reports_corroboration_not_raw_confidence(client, auth):
    """It ranked by `confidence` - the number the FIRST feed to write the row
    claimed, which the composite score exists to replace - and counted "sources"
    as the distinct values of the denormalised `source` column, which holds
    exactly one feed per row. A report on a multi-feed platform that cannot
    report agreement between feeds is reporting the wrong thing."""
    from dashboard_api.db import get_conn
    from dashboard_api.reports import _cti_report, _window

    since, until, label = _window("weekly", None, None)
    with get_conn() as conn:
        rep = _cti_report(conn, since, until, label)
    labels = {h["label"] for h in rep["summary"]["headline"]}
    assert "Multi-source" in labels, labels
    assert "High-confidence" not in labels, (
        "the raw feed claim is not the headline number any more")
    # Findings are ranked by the composite score, so the top of the report is
    # what to act on rather than whichever feed asserted the biggest number.
    scores = [f["score"] for f in rep["findings"]]
    assert scores == sorted(scores, reverse=True), scores


def test_the_cti_report_recommendations_come_from_its_own_numbers(client, auth):
    """They were three fixed sentences, printed whatever the store looked like -
    which makes them decoration. An operator acts on a recommendation only if it
    could have said something else."""
    from dashboard_api.db import get_conn
    from dashboard_api.reports import _cti_report, _window

    since, until, label = _window("weekly", None, None)
    with get_conn() as conn:
        rep = _cti_report(conn, since, until, label)
        corroborated = conn.execute(
            "SELECT COUNT(*) AS n FROM (SELECT value FROM observable_sources "
            "GROUP BY value HAVING COUNT(*) > 1)").fetchone()["n"]
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM iocs WHERE last_seen >= ? AND last_seen <= ?",
            (since, until)).fetchone()["n"]
    text = " ".join(rep["recommendations"])
    if total and 100 * corroborated / total < 5:
        assert "multi-source" in text, (
            "a store that is almost entirely single-source must be told so")
    assert rep["recommendations"], "a report with no recommendation says nothing"
