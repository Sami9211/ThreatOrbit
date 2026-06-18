"""SOC triage snapshot (/siem/triage): the analyst console's operational feed.

Every count and age must come from the alerts table; only the SLA thresholds
are policy. These tests pin the open-queue rollup, unassigned load, status
breakdown, and ack-vs-resolve SLA breach classification using alerts aged well
beyond the seed window (so they deterministically top the worst-first breach
list) and a settings override (so the threshold path is exercised).
"""
import datetime as _dt
import uuid

from dashboard_api.db import get_conn


def _insert_alert(conn, *, marker, mins_old, severity, status, owner=""):
    ts = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=mins_old)).replace(microsecond=0).isoformat()
    aid = f"{marker}-{uuid.uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
        "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
        "VALUES (?,?,?,?,?,'undetermined',?,50,'R','r',?, '',1,0,'org-default')",
        (aid, ts, marker, severity, status, owner, marker))
    return aid


def _cleanup(marker):
    with get_conn() as conn:
        conn.execute("DELETE FROM alerts WHERE title=?", (marker,))
        conn.commit()


def test_triage_open_rollup_and_sla(client, auth):
    marker = "TRIAGE-" + uuid.uuid4().hex[:6]
    with get_conn() as conn:
        # critical, new, ~14 days old → ACK breach (default ack threshold 15);
        # older than any seed alert (seed caps at 7 days) so it tops the
        # worst-first list and survives the 25-row cap deterministically.
        crit_breach = _insert_alert(conn, marker=marker, mins_old=20000, severity="critical", status="new")
        # critical, assigned (acked), ~13 days old → RESOLVE breach (240), not ack
        crit_resolve = _insert_alert(conn, marker=marker, mins_old=19000, severity="critical",
                                     status="assigned", owner="ana@x")
        # high, new, 5 min old → within the 60-min high ack SLA, no breach
        young_high = _insert_alert(conn, marker=marker, mins_old=5, severity="high", status="new")
        conn.commit()
    try:
        out = client.get("/siem/triage", headers=auth).json()
        # counts are a superset of what we inserted (seed contributes too)
        assert out["open"]["total"] >= 3
        assert out["open"]["critical"] >= 2 and out["open"]["high"] >= 1
        assert out["byStatus"]["new"] >= 2 and out["byStatus"]["assigned"] >= 1
        assert out["oldestOpenMinutes"] >= 20000

        ids = {b["id"]: b for b in out["sla"]["breaches"]}
        assert crit_breach in ids and ids[crit_breach]["slaType"] == "ack"
        assert ids[crit_breach]["thresholdMinutes"] == 15
        assert crit_resolve in ids and ids[crit_resolve]["slaType"] == "resolve"
        assert young_high not in ids   # 5-min-old high is not breached
        # default thresholds are surfaced for the UI
        assert out["sla"]["ackThresholds"]["critical"] == 15
        assert out["sla"]["resolveThresholds"]["critical"] == 240
    finally:
        _cleanup(marker)


def test_triage_unassigned_and_threshold_override(client, auth):
    """An unowned alert counts as unassigned; raising the ack SLA via settings
    suppresses what would otherwise be a breach (order-independent: we assert
    the target's *absence* from breaches, not its rank)."""
    marker = "TRIAGE2-" + uuid.uuid4().hex[:6]
    with get_conn() as conn:
        _insert_alert(conn, marker=marker, mins_old=2, severity="medium", status="new", owner="")
        # medium, new, 600 min old → would breach the default 240-min ack SLA…
        target = _insert_alert(conn, marker=marker, mins_old=600, severity="medium", status="new", owner="x@y")
        # …but relax medium ack SLA past its age → no longer a breach
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('sla_ack_medium_mins','100000')")
        conn.commit()
    try:
        out = client.get("/siem/triage", headers=auth).json()
        assert out["open"]["unassigned"] >= 1
        assert out["sla"]["ackThresholds"]["medium"] == 100000
        assert all(b["id"] != target for b in out["sla"]["breaches"])  # suppressed
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key='sla_ack_medium_mins'")
            conn.commit()
        _cleanup(marker)
