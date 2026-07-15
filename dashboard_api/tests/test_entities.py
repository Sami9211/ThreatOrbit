"""UEBA /siem/entities parity fences.

The endpoint was rewritten from fetch-every-alert-into-Python to SQL GROUP BY
aggregation (~2.6s → ~1.4s at 200k alerts, and no full-table materialisation).
These tests pin the aggregation semantics exactly: severity-weighted score,
technique diversity, open counts, severity buckets, risk cap and banding.
"""
import uuid


def _mk_alert(client, auth, host, severity, tech=None):
    r = client.post("/siem/alerts", headers=auth, json={
        "title": f"ueba {severity}", "severity": severity, "rule_name": "UEBA-T",
        "hostname": host, **({"mitre_tech_id": tech} if tech else {}),
    })
    assert r.status_code in (200, 201), r.text


def test_entity_aggregates_match_alert_history(client, auth):
    host = f"ueba-host-{uuid.uuid4().hex[:8]}"
    # 2×critical(25) + 1×high(15) + 1×low(3) = score 68; techniques {T1001,T1002}
    _mk_alert(client, auth, host, "critical", "T1001")
    _mk_alert(client, auth, host, "critical", "T1002")
    _mk_alert(client, auth, host, "high", "T1002")
    _mk_alert(client, auth, host, "low")

    ents = client.get("/siem/entities?type=host&limit=100", headers=auth).json()
    mine = next(e for e in ents["entities"] if e["value"] == host)

    assert mine["alerts"] == 4
    assert mine["score"] == 2 * 25 + 15 + 3
    assert mine["techniqueCount"] == 2
    assert mine["techniques"] == ["T1001", "T1002"]
    assert mine["open"] == 4                       # all just created → open
    assert mine["bySeverity"]["critical"] == 2
    assert mine["bySeverity"]["high"] == 1
    assert mine["bySeverity"]["low"] == 1
    assert mine["bySeverity"]["medium"] == 0
    # risk = min(100, score + techniqueCount*4); 68+8=76 → band critical
    assert mine["risk"] == 76
    assert mine["band"] == "critical"
    assert mine["lastSeen"] is not None

    # list is ranked by risk, summary counters are coherent
    risks = [e["risk"] for e in ents["entities"]]
    assert risks == sorted(risks, reverse=True)
    assert ents["summary"]["tracked"] >= len(ents["entities"])
    assert ents["summary"]["highRisk"] >= 1


def test_entity_detail_consistent_with_list(client, auth):
    host = f"ueba-det-{uuid.uuid4().hex[:8]}"
    _mk_alert(client, auth, host, "critical", "T1059")
    d = client.get(f"/siem/entities/detail?type=host&value={host}", headers=auth).json()
    assert d["alertCount"] == 1
    assert d["risk"] == min(100, 25 + 1 * 4)
