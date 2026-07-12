"""Overview time-bucketed rollups honour their claimed window instead of
piling everything older into the oldest cell. These endpoints also cut in
SQL now (idx_alerts_ts), so the assertions double as a windowing contract."""
import datetime as dt
import uuid

from dashboard_api.db import get_conn


def _insert(conn, ts, *, tactic="Initial Access", tag=""):
    aid = f"OVW-{tag}-{uuid.uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
        "rule_id,rule_name,mitre_tactic,description,raw_log,event_count,ti_hits,org_id) "
        "VALUES (?,?,?, 'high','new','undetermined','',50,'R-OVW','ovw',?, '','',1,0,'org-default')",
        (aid, ts, "ovw alert", tactic))
    return aid


def test_mitre_heatmap_excludes_alerts_older_than_a_week(client, auth):
    now = dt.datetime.now(dt.timezone.utc)
    recent = (now - dt.timedelta(hours=2)).replace(microsecond=0).isoformat()
    ancient = (now - dt.timedelta(days=90)).replace(microsecond=0).isoformat()
    tag = uuid.uuid4().hex[:6]
    tactic = f"OVW-Tactic-{tag}"   # unique tactic → isolated heatmap row
    with get_conn() as conn:
        _insert(conn, recent, tactic=tactic, tag=tag)
        _insert(conn, ancient, tactic=tactic, tag=tag)
        conn.commit()
    try:
        grid = client.get("/overview/mitre-heatmap", headers=auth).json()
        row = next((r for r in grid if r["label"] == tactic), None)
        assert row is not None, "recent alert should create a heatmap row"
        # exactly ONE alert counted (the recent one); the 90-day-old alert is
        # excluded, NOT clamped into the oldest bucket (the old bug)
        assert sum(row["vals"]) == 1, row["vals"]
        # and it lands in the most-recent bucket, not the oldest
        assert row["vals"][-1] == 1 and row["vals"][0] == 0, row["vals"]
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE rule_id='R-OVW'")
            conn.commit()


def test_hourly_volume_only_counts_last_24h(client, auth):
    now = dt.datetime.now(dt.timezone.utc)
    tag = uuid.uuid4().hex[:6]
    with get_conn() as conn:
        base = client.get("/overview/hourly-volume", headers=auth).json()
        _insert(conn, (now - dt.timedelta(hours=1)).replace(microsecond=0).isoformat(), tag=tag)
        _insert(conn, (now - dt.timedelta(days=5)).replace(microsecond=0).isoformat(), tag=tag)
        conn.commit()
    try:
        after = client.get("/overview/hourly-volume", headers=auth).json()
        assert len(after) == 24
        # exactly one new alert entered the 24h window (the 5-day-old one didn't)
        assert sum(after) - sum(base) == 1
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE rule_id='R-OVW'")
            conn.commit()
