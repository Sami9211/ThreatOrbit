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


# -- Malformed-rule resilience: a broken rule must not blind the SIEM -----------

def test_evaluate_tolerates_non_numeric_aggregation():
    """A rule whose aggregation.threshold/window is non-numeric must NOT raise
    from evaluate() - an exception there propagates out of the per-batch
    detection loop and blinds detection for every rule/event in the tick."""
    from dashboard_api.rule_engine import evaluate
    events = [{"event_type": "failed_login", "src_ip": "10.0.0.1", "ts":
               datetime.now(timezone.utc).isoformat()}]
    for bad in ("high", "5m", None, "", "-3", 0):
        rule = {"definition": {"conditions": [{"field": "event_type", "op": "equals",
                                               "value": "failed_login"}], "logic": "and",
                               "aggregation": {"groupBy": "src_ip", "threshold": bad,
                                               "windowMinutes": "abc"}}}
        # Must return a list (possibly empty), never raise.
        assert isinstance(evaluate(rule, events), list)


def test_invalid_aggregation_detector():
    from dashboard_api.rule_engine import invalid_aggregation_in
    assert invalid_aggregation_in(
        {"aggregation": {"threshold": "high", "windowMinutes": 5}}) is not None
    assert invalid_aggregation_in(
        {"aggregation": {"threshold": 20, "windowMinutes": "5m"}}) is not None
    # Valid aggregation and no-aggregation both pass.
    assert invalid_aggregation_in({"aggregation": {"threshold": 20, "windowMinutes": 5}}) is None
    assert invalid_aggregation_in({"conditions": [{"field": "raw", "op": "contains", "value": "x"}]}) is None


def test_authoring_rejects_invalid_aggregation(client, auth):
    """Creating/updating a rule with a non-numeric aggregation threshold is
    rejected at authoring (400) with clear feedback, not silently stored."""
    bad = {"name": f"badagg-{uuid.uuid4().hex[:6]}", "severity": "high", "category": "test",
           "definition": {"conditions": [{"field": "event_type", "op": "equals",
                                          "value": "failed_login"}], "logic": "and",
                          "aggregation": {"groupBy": "src_ip", "threshold": "high",
                                          "windowMinutes": 5}}}
    r = client.post("/siem/rules", json=bad, headers=auth)
    assert r.status_code == 400
    assert "threshold" in r.json()["error"].lower()   # app wraps detail as {"error": …}
    # A valid aggregation is accepted.
    good = {**bad, "name": f"okagg-{uuid.uuid4().hex[:6]}"}
    good["definition"]["aggregation"]["threshold"] = 20
    assert client.post("/siem/rules", json=good, headers=auth).status_code == 201


def test_one_broken_rule_does_not_stop_detection(client, auth):
    """A stored rule that raises during evaluation is skipped, and OTHER rules in
    the same batch still fire - the engine isolates a bad rule per iteration."""
    import dashboard_api.rule_engine as re_mod
    seed_builtin_rules()
    tag = uuid.uuid4().hex[:8]
    src = f"203.0.113.{(uuid.uuid4().int % 250) + 1}"
    # Force evaluate() to blow up for a specific rule name, simulating any latent
    # per-rule crash (the belt-and-suspenders isolation, independent of the
    # aggregation coercion). All other rules must still run.
    real_evaluate = re_mod.evaluate

    def boom_on_marker(rule, events, now=None):
        if rule.get("name") == "BOOM-RULE":
            raise RuntimeError("simulated rule crash")
        return real_evaluate(rule, events, now)

    # run_detection does a function-local `from dashboard_api.rule_engine import
    # evaluate`, so patch the source module (rule_engine), not engine.
    orig = re_mod.evaluate
    re_mod.evaluate = boom_on_marker
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO detection_rules (id,name,category,severity,status,source,definition) "
                "VALUES (?,?,?,?, 'enabled','custom', ?)",
                (f"R-BOOM-{tag}", "BOOM-RULE", "test", "high",
                 '{"conditions": [{"field": "event_type", "op": "equals", "value": "failed_login"}], "logic": "and"}'))
            conn.commit()
        # Ingest a brute-force event that a BUILT-IN rule (not BOOM-RULE) detects.
        line = __import__("json").dumps({"event_type": "failed_login", "src_ip": src,
                                         "user": f"v-{tag}", "host": f"DC-{tag}"})
        r = client.post("/siem/ingest", json={"lines": [line], "format": "json"}, headers=auth)
        assert r.status_code == 200, r.text
    finally:
        re_mod.evaluate = orig
    with get_conn() as conn:
        alert = conn.execute("SELECT 1 FROM alerts WHERE src_ip=? LIMIT 1", (src,)).fetchone()
    assert alert is not None, "a crashing rule blinded the whole detection batch"
