"""GET /siem/analytics/trends - the per-day buckets behind the analytics
sparklines. These replaced hardcoded frontend demo trends, so the contract
matters: zero-filled days (a quiet day is an honest 0, not a gap), the range
ends today, and the latency/FP semantics match /siem/kpis."""
import datetime as dt
import uuid

from dashboard_api.db import get_conn


def _iso_day(days_back: int) -> str:
    return (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=days_back)).isoformat()


def _insert_alert(conn, ts: str, *, severity="low", disposition="undetermined",
                  detect=None, respond=None, title="trend test"):
    aid = f"TRND-{uuid.uuid4().hex[:10]}"
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
        "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id,"
        "detect_latency_sec,respond_latency_sec) "
        "VALUES (?,?,?,?, 'new',?, '',10,'R-TRND','trend-rule','','',1,0,'org-default',?,?)",
        (aid, ts, title, severity, disposition, detect, respond))
    return aid


def test_trends_shape_zero_fill_and_range(client, auth):
    r = client.get("/siem/analytics/trends", headers=auth)
    assert r.status_code == 200, r.text
    days = r.json()["days"]
    assert len(days) == 7
    assert days[-1]["day"] == _iso_day(0), "range must end today (UTC)"
    assert [d["day"] for d in days] == sorted(d["day"] for d in days)
    for d in days:
        # zero-filled buckets are complete records, not gaps
        assert set(d) == {"day", "alerts", "severe", "mttd", "mttr", "fpRate"}

    # bounds are enforced
    assert client.get("/siem/analytics/trends?days=0", headers=auth).status_code == 422
    assert client.get("/siem/analytics/trends?days=31", headers=auth).status_code == 422
    one = client.get("/siem/analytics/trends?days=1", headers=auth).json()["days"]
    assert len(one) == 1 and one[0]["day"] == _iso_day(0)


def test_trends_bucket_math_matches_kpi_semantics(client, auth):
    """Plant known telemetry on D-4 and pin the bucket's averages/rates.
    The bucket is NOT empty (the seeded demo data lands on past days), so the
    expectation is computed by merging the planted values with the bucket's
    pre-existing rows, read with the same day-prefix bucketing the endpoint
    uses. Only the arithmetic is mirrored - the endpoint's SQL cut, day
    bucketing, unit conversion, and NULL-latency exclusion are all exercised
    for real (planting shifts every value, so returning seconds instead of
    minutes, or counting NULL latencies as 0, would fail these pins)."""
    day = _iso_day(4)
    with get_conn() as conn:
        pre = conn.execute(
            "SELECT severity, disposition, detect_latency_sec, respond_latency_sec "
            "FROM alerts WHERE ts LIKE ?", (day + "%",)).fetchall()
    pre_d = [r["detect_latency_sec"] for r in pre if r["detect_latency_sec"] is not None]
    pre_r = [r["respond_latency_sec"] for r in pre if r["respond_latency_sec"] is not None]
    pre_fp = sum(1 for r in pre if r["disposition"] == "false-positive")

    ts = f"{day}T10:00:00+00:00"
    with get_conn() as conn:
        _insert_alert(conn, ts, detect=120, respond=600, severity="critical")
        _insert_alert(conn, ts, detect=240, respond=1200)
        # NULL latencies: must be excluded from the averages, not counted as 0
        _insert_alert(conn, ts, disposition="false-positive")
        conn.commit()
    try:
        after = client.get("/siem/analytics/trends", headers=auth).json()["days"]
        d4 = next(d for d in after if d["day"] == day)
        all_d = pre_d + [120, 240]
        all_r = pre_r + [600, 1200]
        n = len(pre) + 3
        pre_severe = sum(1 for r in pre if r["severity"] in ("critical", "high"))
        assert d4["alerts"] == n
        assert d4["severe"] == pre_severe + 1   # exactly one planted critical
        assert d4["mttd"] == round(sum(all_d) / len(all_d) / 60, 1)
        assert d4["mttr"] == round(sum(all_r) / len(all_r) / 60, 1)
        assert d4["fpRate"] == round((pre_fp + 1) / n * 100, 1)
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE rule_id='R-TRND'")
            conn.commit()


def test_trends_ignore_future_dated_alerts(client, auth):
    """Future-dated rows (some tests plant them deliberately) must not crash
    bucketing or leak into today's bucket."""
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        aid = _insert_alert(conn, future, title="future trend")
        conn.commit()
    try:
        r = client.get("/siem/analytics/trends", headers=auth)
        assert r.status_code == 200
        days = r.json()["days"]
        assert len(days) == 7
        assert days[-1]["day"] == _iso_day(0)
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE id=?", (aid,))
            conn.commit()
