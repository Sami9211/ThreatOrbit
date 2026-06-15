"""Compliance control-mapping tests.

Guards the matrix's shape + honesty: every control is well-formed and cites
evidence, the status summary adds up, the self-assessment disclaimer is present
and does NOT overclaim certification, honest gaps stay visible, and the endpoint
serves it.
"""
import re

from dashboard_api import compliance

_STATUSES = {"implemented", "partial", "planned"}
_TSC = re.compile(r"^(CC\d\.\d|A\d\.\d|C\d\.\d|PI\d\.\d|P\d\.\d)$")  # SOC 2 TSC refs (incl. Privacy)
_ISO = re.compile(r"^A\.\d{1,2}\.\d{1,2}$")                          # ISO 27001:2022 Annex A


def test_every_control_is_wellformed_and_cites_evidence():
    seen = set()
    for c in compliance.CONTROLS:
        for k in ("id", "title", "soc2", "iso27001", "status", "evidence"):
            assert c.get(k), f"{c.get('id')} missing {k}"
        assert c["id"] not in seen, f"duplicate control id {c['id']}"
        seen.add(c["id"])
        assert c["status"] in _STATUSES, f"{c['id']} bad status {c['status']}"
        assert all(_TSC.match(x) for x in c["soc2"]), f"{c['id']} bad SOC2 ref {c['soc2']}"
        assert all(_ISO.match(x) for x in c["iso27001"]), f"{c['id']} bad ISO ref {c['iso27001']}"
        assert c["evidence"], f"{c['id']} cites no evidence"


def test_summary_adds_up():
    s = compliance.summary()
    assert s["total"] == len(compliance.CONTROLS)
    assert s["implemented"] + s["partial"] + s["planned"] == s["total"]
    # Real coverage exists, and so do honest gaps - neither should be empty.
    assert s["implemented"] >= 10
    assert s["planned"] >= 1


def test_disclaimer_is_honest_about_certification():
    d = compliance.DISCLAIMER.lower()
    assert "self-assessment" in d
    assert "not a soc 2 report" in d or "not a certification" in d


def test_known_gaps_stay_visible():
    by_id = {c["id"]: c for c in compliance.CONTROLS}
    # We must not silently claim a pen test or a formal audit we haven't done.
    assert by_id["RM-PENTEST"]["status"] == "planned"
    assert by_id["RM-AUDIT"]["status"] == "planned"


def test_endpoint_serves_matrix(client, auth):
    body = client.get("/compliance/controls", headers=auth).json()
    assert "disclaimer" in body and body["controls"]
    assert body["summary"]["total"] == len(compliance.CONTROLS)
    assert "ISO/IEC 27001:2022" in body["frameworks"]


def test_endpoint_requires_auth(client):
    assert client.get("/compliance/controls").status_code in (401, 403)
