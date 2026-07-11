"""Report narratives carry an honest prior-window trend sentence: a real
movement (or flat) when the preceding window has data, an explicit no-baseline
note when it doesn't — never an invented movement."""
import datetime as dt
import uuid

from dashboard_api.db import get_conn


def test_siem_report_trend_sentence_computed(client, auth):
    # Plant one alert 36h back so the daily report's preceding window (24–48h
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
