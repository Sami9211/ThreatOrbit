"""Detection-content tests.

Guards the built-in detection library: every rule is well-formed, the content
spans real ATT&CK breadth (and doesn't silently shrink), every telemetry
scenario the engine emits is actually matched by a rule whose technique agrees
with the event (no orphan events, no orphan rules), a benign event trips
nothing, and the new rules seed + evaluate through the live engine.
"""
import random
import re
import uuid
from datetime import datetime, timezone

from dashboard_api.engine import BUILTIN_RULES, _SCENARIOS, run_detection, seed_builtin_rules
from dashboard_api.rule_engine import matches_event
from dashboard_api.db import get_conn

_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_RNG = random.Random(20260615)


def test_builtin_rules_wellformed():
    seen = set()
    for r in BUILTIN_RULES:
        for k in ("id", "name", "category", "severity", "mitre_tactic", "mitre_tactic_id",
                  "mitre_tech_id", "mitre_tech", "title_tmpl", "definition"):
            assert r.get(k), f"{r.get('id')} missing {k}"
        assert r["id"] not in seen, f"duplicate rule id {r['id']}"
        seen.add(r["id"])
        assert _TECH.match(r["mitre_tech_id"]), f"{r['id']} bad technique {r['mitre_tech_id']}"
        assert _TACTIC.match(r["mitre_tactic_id"]), f"{r['id']} bad tactic {r['mitre_tactic_id']}"
        assert r["severity"] in _SEVERITIES, f"{r['id']} bad severity {r['severity']}"
        assert r["definition"].get("conditions"), f"{r['id']} has no conditions"


def test_content_breadth():
    # A SIEM's value is coverage. Regression guard: don't let the curated content
    # shrink, and keep it spanning multiple tactics including Impact (ransomware),
    # which was a gap before this unit.
    assert len(BUILTIN_RULES) >= 15
    tactics = {r["mitre_tactic_id"] for r in BUILTIN_RULES}
    assert len(tactics) >= 6, f"too few tactics: {sorted(tactics)}"
    assert "TA0040" in tactics, "Impact (ransomware/recovery) not covered"


def test_every_scenario_is_detected():
    """Each telemetry scenario the engine emits must be matched by at least one
    rule, and a matching rule's technique must agree with the event's MITRE hint
    - telemetry <-> detection alignment, so 'real data fires real detections'."""
    for scn, _weight in _SCENARIOS:
        event, _iocs = scn(_RNG)
        matched = [r for r in BUILTIN_RULES if matches_event(event, r["definition"])]
        assert matched, f"{scn.__name__}: event '{event.get('event_type')}' matched no rule"
        hint = event.get("mitre_tech_id")
        assert any(r["mitre_tech_id"] == hint for r in matched), (
            f"{scn.__name__}: no matching rule agrees with MITRE hint {hint} "
            f"(matched {[r['id'] for r in matched]})")


def test_scenario_weights_sum_to_one():
    total = sum(w for _fn, w in _SCENARIOS)
    assert abs(total - 1.0) < 1e-6, f"scenario weights sum to {total}, not 1.0"


def test_benign_event_matches_nothing():
    benign = {"category": "endpoint", "event_type": "heartbeat", "action": "ok",
              "hostname": "WEB-LB-01", "username": "msmith", "src_ip": "10.0.0.5",
              "dest_port": 443, "bytes_out": 1024, "country": "United States",
              "severity_hint": "info"}
    fired = [r["id"] for r in BUILTIN_RULES if matches_event(benign, r["definition"])]
    assert fired == [], f"benign event tripped rules: {fired}"


def test_new_rules_are_seeded(_db):
    seed_builtin_rules()  # idempotent
    with get_conn() as conn:
        ids = {row["id"] for row in conn.execute("SELECT id FROM detection_rules").fetchall()}
    for rid in ("R-RANSOMWARE", "R-SHADOWDEL", "R-KERBEROAST", "R-DNSTUNNEL",
                "R-PWSPRAY", "R-IMPOSSIBLE", "R-CLOUDKEY", "R-TOOLXFER"):
        assert rid in ids, f"{rid} not seeded into detection_rules"


def test_new_event_detected_through_engine(_db):
    """Full path (non-polluting): a ransomware telemetry event lands in the
    events table and run_detection's preview backtest matches the rule against
    it - proving the rule loads from the DB and evaluates on a real row."""
    seed_builtin_rules()
    ev, _iocs = _SCENARIOS[7][0](_RNG)  # _scn_ransomware
    assert ev["event_type"] == "file_encrypt"
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rule = next(r for r in BUILTIN_RULES if r["id"] == "R-RANSOMWARE")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,src_ip,dest_ip,dest_port,username,"
            "hostname,process_name,action,bytes_out,country,severity_hint,mitre_tech_id,raw,processed) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (str(uuid.uuid4()), now, ev["category"], ev["event_type"], None, None, None,
             ev.get("username"), ev.get("hostname"), ev.get("process_name"), ev.get("action"),
             0, None, ev.get("severity_hint"), ev.get("mitre_tech_id"), ev.get("raw")))
        conn.commit()
        res = run_detection(conn, preview_rule=rule)  # preview = no alerts written
    assert res["matched"] >= 1, res
