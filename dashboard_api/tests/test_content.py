"""Detection-content update channel tests.

Proves the shipped pack loads + validates, a malformed pack is refused whole,
applying upserts the rules + records the version idempotently while preserving an
operator's enable/disable choice, an applied pack rule actually fires through
detection, and the status/apply endpoints behave (incl. permission).
"""
import json
import uuid
from datetime import datetime, timezone

import pytest

from dashboard_api import content
from dashboard_api.db import get_conn
from dashboard_api.rule_engine import matches_event

PACK = "threatorbit-windows-extras"


def test_shipped_pack_loads_and_validates():
    packs = {p["name"]: p for p in content.load_packs()}
    assert PACK in packs
    p = packs[PACK]
    assert p["version"] >= 1 and len(p["rules"]) == 4
    ids = {r["id"] for r in p["rules"]}
    assert {"R-SVCINSTALL", "R-AVTAMPER", "R-SCHTASK", "R-LOGCLEAR"} <= ids


def test_malformed_pack_is_refused(tmp_path):
    (tmp_path / "bad.json").write_text(json.dumps({
        "name": "bad", "version": 1,
        "rules": [{"id": "R-X", "name": "x", "category": "Endpoint", "severity": "high",
                   "mitre_tactic": "Persistence", "mitre_tactic_id": "TA0003",
                   "mitre_tech_id": "T1543", "mitre_tech": "svc",
                   "definition": {"conditions": []}}]}))  # no conditions
    with pytest.raises(ValueError, match="no conditions"):
        content.load_packs(tmp_path)


def test_apply_upserts_rules_and_records_version():
    with get_conn() as conn:
        res = content.apply(conn)
        conn.commit()
        assert res["rulesUpserted"] >= 4
        assert res["versions"][PACK] >= 1
        row = conn.execute(
            "SELECT source, status FROM detection_rules WHERE id='R-SVCINSTALL'").fetchone()
        assert row["source"] == "content-pack" and row["status"] == "enabled"
        st = content.status(conn)
    pack = next(p for p in st["packs"] if p["name"] == PACK)
    assert pack["appliedVersion"] == pack["version"] and pack["pending"] is False


def test_apply_is_idempotent_and_preserves_operator_status():
    with get_conn() as conn:
        content.apply(conn)
        conn.execute("UPDATE detection_rules SET status='disabled' WHERE id='R-SCHTASK'")
        conn.commit()
        content.apply(conn)  # re-apply must NOT re-enable the operator's choice
        conn.commit()
        status = conn.execute(
            "SELECT status FROM detection_rules WHERE id='R-SCHTASK'").fetchone()["status"]
        # exactly one row per id (no duplication)
        n = conn.execute("SELECT COUNT(*) c FROM detection_rules WHERE id='R-SCHTASK'").fetchone()["c"]
    assert status == "disabled" and n == 1


def test_applied_rule_fires_through_detection():
    from dashboard_api.engine import run_detection
    with get_conn() as conn:
        content.apply(conn)
        conn.execute("UPDATE detection_rules SET status='enabled' WHERE id='R-SVCINSTALL'")
        # a real ingested Windows "service installed" event
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,hostname,severity_hint,processed) "
            "VALUES (?,?,?,?,?,?,0)",
            (str(uuid.uuid4()), datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
             "endpoint", "service_install", "WEB-LB-01", "high"))
        conn.commit()
        run_detection(conn)
        conn.commit()
        hit = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE mitre_tech_id='T1543.003'").fetchone()["c"]
    assert hit >= 1


def test_pack_rule_is_evaluable():
    rule = next(r for p in content.load_packs() for r in p["rules"] if r["id"] == "R-LOGCLEAR")
    assert matches_event({"event_type": "log_cleared"}, rule["definition"])
    assert not matches_event({"event_type": "heartbeat"}, rule["definition"])


def test_endpoints_status_and_apply(client, auth):
    applied = client.post("/siem/content/apply", headers=auth)
    assert applied.status_code == 200, applied.text
    assert applied.json()["rulesUpserted"] >= 4
    st = client.get("/siem/content", headers=auth).json()
    pack = next(p for p in st["packs"] if p["name"] == PACK)
    assert pack["pending"] is False
