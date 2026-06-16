"""Curated starter detection pack: real Sigma rules that parse onto evaluable
definitions, map to the platform's own event fields, and load idempotently.
"""
import json

from dashboard_api.detection_pack import STARTER_PACK
from dashboard_api.sigma import sigma_to_rule


def test_every_pack_rule_parses_and_is_evaluable():
    seen_names = set()
    for yaml_text in STARTER_PACK:
        r = sigma_to_rule(yaml_text)                       # raises if unparseable
        assert r["name"] and r["name"] not in seen_names   # unique titles
        seen_names.add(r["name"])
        conds = r["definition"]["conditions"]
        assert conds, f"{r['name']} has no conditions"
        # mapped to precise native fields, not a degraded raw-contains fallback
        assert all(c["field"] != "raw" for c in conds), r["name"]
        assert r["mitre_tech_id"] and r["mitre_tactic"]    # ATT&CK-tagged
    assert len(seen_names) == 10


def test_load_pack_creates_and_is_idempotent(client, auth):
    first = client.post("/siem/rules/load-pack", headers=auth).json()
    assert len(first["created"]) + len(first["skipped"]) == 10
    assert len(first["created"]) >= 1

    # a second load skips everything (idempotent by rule name)
    second = client.post("/siem/rules/load-pack", headers=auth).json()
    assert second["created"] == [] and len(second["skipped"]) == 10

    rules = client.get("/siem/rules", headers=auth).json()
    pack = [r for r in rules if r.get("source") == "pack"]
    assert len(pack) >= len(first["created"])
    # spot-check one is a real, evaluable, ATT&CK-tagged rule
    sample = next(r for r in pack if "Encryption" in r["name"])
    defn = sample["definition"]
    if isinstance(defn, str):
        defn = json.loads(defn)
    assert defn["conditions"] and sample["mitre_tech_id"] == "T1486"
    # every pack rule carries an authored noise rating (content metadata)
    assert sample["noise"] in ("low", "medium", "high")
    assert all(r.get("noise") in ("low", "medium", "high") for r in pack)
