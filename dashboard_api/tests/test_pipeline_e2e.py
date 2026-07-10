"""End-to-end SIEM pipeline: the core value proposition, guarded.

Proves the chain a real deployment depends on and that no unit test alone
covers: forwarded logs → detection rules fire → alerts carry the right rule +
MITRE mapping → correlated critical/high alerts on one pivot auto-escalate into
a SOAR case with an IR task list. Plus the ReDoS authoring guard, so a bad
detection-rule regex is rejected instead of hanging the engine.
"""
import json
import uuid

from dashboard_api.db import get_conn
from dashboard_api.engine import seed_builtin_rules, _maybe_escalate_case
from dashboard_api.detections import _insert_alert


def _ingest(client, auth, lines, fmt="json"):
    r = client.post("/siem/ingest", json={"lines": lines, "format": fmt}, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def test_forwarded_logs_become_alerts_with_mitre(client, auth):
    """A brute-force auth event, ingested as a real log line, fires the built-in
    detection rule and produces an alert mapped to T1110 / Credential Access."""
    seed_builtin_rules()   # guarantee the built-in rules exist + enabled
    tag = uuid.uuid4().hex[:8]
    # src_ip alone has only 250 possible values (TEST-NET-3) - across the full
    # suite's shared database that collides often enough for "ORDER BY ts DESC
    # LIMIT 1" to occasionally return a stale, unrelated alert with a tied or
    # later timestamp (SQLite happens to preserve insertion order for ties;
    # Postgres does not, so this was intermittently returning someone else's
    # alert there). username is unique per test run, so scope on both.
    username = f"victim-{tag}"
    src = f"203.0.113.{(uuid.uuid4().int % 250) + 1}"
    line = json.dumps({"event_type": "failed_login", "src_ip": src,
                       "user": username, "host": f"DC-{tag}"})
    out = _ingest(client, auth, [line])
    assert out["parsed"] == 1
    with get_conn() as conn:
        alert = conn.execute(
            "SELECT rule_name, mitre_tech_id, mitre_tactic, severity FROM alerts "
            "WHERE src_ip=? AND username=? ORDER BY ts DESC LIMIT 1", (src, username)).fetchone()
    assert alert is not None, "ingested brute-force log did not produce an alert"
    assert alert["mitre_tech_id"] == "T1110"
    assert alert["mitre_tactic"] == "Credential Access"
    assert alert["severity"] == "high"


def test_correlated_alerts_auto_escalate_to_a_case(client, auth):
    """Three unresolved critical/high alerts sharing a host pivot auto-open a
    SOAR case with the standard IR task list (Triage→Containment→…)."""
    host = f"WEB-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        for i in range(3):
            _insert_alert(conn, title=f"suspicious {i} on {host}", severity="critical",
                          risk=92, rule_name="R-TEST", hostname=host,
                          mitre_tech_id="T1071.001", mitre_tactic="Command and Control")
        conn.commit()
        created = _maybe_escalate_case(conn)
        conn.commit()
    assert created >= 1, "3 correlated critical alerts on one host should open a case"
    with get_conn() as conn:
        row = conn.execute(
            "SELECT tasks, entities, alert_count FROM cases "
            "WHERE entities LIKE ? AND status NOT IN ('resolved','closed') "
            "ORDER BY created DESC LIMIT 1", (f'%{host}%',)).fetchone()
    assert row is not None, "no case was opened for the correlated pivot"
    tasks = json.loads(row["tasks"]) if isinstance(row["tasks"], str) else row["tasks"]
    phases = [t["phase"] for t in tasks]
    assert phases[:4] == ["Triage", "Containment", "Eradication", "Recovery"]
    assert row["alert_count"] >= 3


def test_detection_rule_with_redos_regex_is_rejected(client, auth):
    """A catastrophic-backtracking regex in a detection rule is rejected at
    authoring (400), never stored — it would otherwise hang the engine."""
    body = {
        "name": f"redos-{uuid.uuid4().hex[:6]}", "severity": "high",
        "definition": {"conditions": [{"field": "raw", "op": "regex",
                                        "value": "(a+)+$"}], "logic": "and"},
    }
    r = client.post("/siem/rules", json=body, headers=auth)
    assert r.status_code == 400
    assert "regex" in r.json()["error"].lower()   # app wraps HTTPException detail as {"error": …}
    # The backtest endpoint must refuse it too (it would run the pattern).
    rt = client.post("/siem/rules/test", json={"definition": body["definition"]}, headers=auth)
    assert rt.status_code == 400
    # A safe regex rule is accepted.
    ok = client.post("/siem/rules", json={
        "name": f"safe-{uuid.uuid4().hex[:6]}", "severity": "low",
        "definition": {"conditions": [{"field": "raw", "op": "regex",
                                        "value": r"failed password for \w+"}], "logic": "and"}},
        headers=auth)
    assert ok.status_code == 201, ok.text


def test_correlation_survives_high_open_alert_volume(client, auth):
    """A busy SOC (hundreds of open critical/high alerts) must NOT hide a genuine
    3-alert pivot from escalation. The old engine scanned only the 200 most-recent
    alerts, so under volume a real incident could silently never open a case; the
    correlation now groups over a recency window, not a fixed row count.
    """
    host = f"CROWD-{uuid.uuid4().hex[:8]}"
    from datetime import datetime, timedelta, timezone
    older = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        # The real correlated incident: 3 alerts sharing one host, timestamped 2h
        # ago (well within the 48h correlation window, but OLDER than the noise).
        for i in range(3):
            aid = _insert_alert(conn, title=f"real {i} on {host}", severity="critical",
                                risk=95, rule_name="R-REAL", hostname=host,
                                mitre_tech_id="T1071.001")
            conn.execute("UPDATE alerts SET ts=? WHERE id=?", (older, aid))
        # Bury the signal: 250 unrelated open critical alerts at "now", each on
        # its own host so none of THEM correlate — pure recency noise. Under the
        # old `ORDER BY ts DESC LIMIT 200`, these 250 newer alerts would fill the
        # scan window and the 3 older real ones would be excluded → no case.
        for i in range(250):
            _insert_alert(conn, title=f"noise {i}", severity="critical", risk=90,
                          rule_name="R-NOISE", hostname=f"NOISE-{uuid.uuid4().hex[:8]}",
                          mitre_tech_id="T1059")
        conn.commit()
        created = _maybe_escalate_case(conn)
        conn.commit()
    assert created >= 1, "correlated pivot lost behind 250 noise alerts — window scan regressed"
    with get_conn() as conn:
        row = conn.execute(
            "SELECT alert_count FROM cases WHERE entities LIKE ? "
            "AND status NOT IN ('resolved','closed') ORDER BY created DESC LIMIT 1",
            (f'%{host}%',)).fetchone()
    assert row is not None, "no case opened for the buried correlated pivot"
    assert row["alert_count"] >= 3


def test_case_id_collision_does_not_crash_escalation(client, auth, monkeypatch):
    """One escalation call can open several cases (it scans the whole window), so
    the small 4-digit CASE-id space collides under load. Forcing every 4-digit
    draw to the SAME value must NOT crash — distinct cases still open via the
    wide-namespace fallback (the old single-retry code threw IntegrityError)."""
    import dashboard_api.engine as eng
    monkeypatch.setattr(eng.random, "randint", lambda a, b: 5000)  # every id collides
    h1 = f"COLL-A-{uuid.uuid4().hex[:8]}"
    h2 = f"COLL-B-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        for h in (h1, h2):
            for i in range(3):
                _insert_alert(conn, title=f"{h} {i}", severity="critical", risk=95,
                              rule_name="R-COLL", hostname=h, mitre_tech_id="T1071.001")
        conn.commit()
        created = _maybe_escalate_case(conn)   # must not raise on id collision
        conn.commit()
    assert created >= 2, "both correlated pivots should open cases despite id collision"
    with get_conn() as conn:
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE (entities LIKE ? OR entities LIKE ?) "
            "AND status NOT IN ('resolved','closed')", (f'%{h1}%', f'%{h2}%')).fetchone()["n"]
    assert n >= 2
