"""Decay policy as records rather than constants.

How fast intel stops being actionable differs per deployment - a bank hunting
payment fraud and a hosting provider fighting abuse do not agree on how long a
phishing URL stays worth acting on. Until this, the curve lived in a Python dict,
so tuning it meant editing source, which in practice means nobody ever does.

The load-bearing test here is the FIRST one: seeding must reproduce the old
hardcoded behaviour exactly. An upgrade that silently re-dated 315,185
indicators would be a data change disguised as a refactor.
"""
import json

import pytest

from dashboard_api import decay as decay_mod
from dashboard_api.db import get_conn
from dashboard_api.ioc_lifecycle import (
    DECAY_HALFLIFE_DAYS, DEFAULT_HALFLIFE, EXPIRY_FLOOR, MAX_AGE_HALFLIVES,
    effective_confidence, half_life, lifecycle_of)


@pytest.fixture(autouse=True)
def fresh_cache():
    """The rule table is cached in-process for the hot decay path, so a test that
    writes a rule must not leak that policy into the next one."""
    decay_mod.invalidate_cache()
    yield
    decay_mod.invalidate_cache()


def test_seeded_rules_reproduce_the_previous_hardcoded_curves_exactly():
    """The whole point of landing this as a refactor. Every type that had a
    hardcoded half-life must still decay at exactly that rate, or the upgrade
    silently re-dates the entire store."""
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        for ioc_type, expected in DECAY_HALFLIFE_DAYS.items():
            rule = decay_mod.rule_for(conn, ioc_type)
            assert rule["halfLifeDays"] == expected, (
                f"{ioc_type}: rule says {rule['halfLifeDays']}d, constant said {expected}d")
        # ...and an unknown type still falls to the default.
        assert decay_mod.rule_for(conn, "something-new")["halfLifeDays"] == DEFAULT_HALFLIFE
        assert decay_mod.rule_for(conn, "ip")["revokeScore"] == EXPIRY_FLOOR
        assert decay_mod.rule_for(conn, "ip")["maxAgeHalfLives"] == MAX_AGE_HALFLIVES


def test_effective_confidence_is_identical_with_and_without_a_rule():
    """Callers in hot loops pass the rule; one-off callers do not. The number an
    analyst sees must not depend on which path produced it."""
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        for ioc_type in ("ip", "domain", "hash", "cve", "unknown-type"):
            rule = decay_mod.rule_for(conn, ioc_type)
            for last_seen in ("2026-07-01T00:00:00+00:00", "2026-06-01T00:00:00+00:00"):
                a = effective_confidence(80, last_seen, ioc_type)
                b = effective_confidence(80, last_seen, ioc_type, None, rule)
                assert a == b, f"{ioc_type}/{last_seen}: {a} != {b}"


def test_seeding_is_idempotent():
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        before = conn.execute("SELECT COUNT(*) AS n FROM decay_rules").fetchone()["n"]
        assert decay_mod.seed_builtin_rules(conn) == 0
        conn.commit()
        after = conn.execute("SELECT COUNT(*) AS n FROM decay_rules").fetchone()["n"]
    assert after == before


def test_every_seeded_type_is_covered_and_none_is_orphaned():
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        covered = set()
        for r in decay_mod.rules(conn):
            covered.update(r["appliesTo"])
    assert "*" in covered, "no catch-all rule: an unknown type would have no policy"
    assert set(DECAY_HALFLIFE_DAYS) <= covered


def test_a_tuned_rule_actually_changes_the_curve():
    """Otherwise the whole feature is decoration."""
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        original = decay_mod.rule_for(conn, "ip")["halfLifeDays"]
        conn.execute("UPDATE decay_rules SET half_life_days=? WHERE applies_to LIKE ?",
                     (1, '%"ip"%'))
        conn.commit()
        decay_mod.invalidate_cache()
        tuned = decay_mod.rule_for(conn, "ip")
        assert tuned["halfLifeDays"] == 1
        # One day old at a 1-day half-life = half the asserted confidence.
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        yesterday = (now - timedelta(days=1)).isoformat()
        assert effective_confidence(80, yesterday, "ip", now, tuned) == 40
        conn.execute("UPDATE decay_rules SET half_life_days=? WHERE applies_to LIKE ?",
                     (original, '%"ip"%'))
        conn.commit()
        decay_mod.invalidate_cache()


def test_the_cache_must_be_invalidated_or_it_serves_a_stale_policy():
    """The table is cached because the decay pass reads it 315k times. That makes
    a missed invalidation a silent correctness bug, so pin the contract."""
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        decay_mod.rule_for(conn, "ip")                      # populate
        conn.execute("UPDATE decay_rules SET half_life_days=999 WHERE applies_to LIKE ?",
                     ('%"ip"%',))
        conn.commit()
        assert decay_mod.rule_for(conn, "ip")["halfLifeDays"] != 999, (
            "cache is not caching - the decay pass would query per row")
        decay_mod.invalidate_cache()
        assert decay_mod.rule_for(conn, "ip")["halfLifeDays"] == 999
        conn.execute("UPDATE decay_rules SET half_life_days=14 WHERE applies_to LIKE ?",
                     ('%"ip"%',))
        conn.commit()
        decay_mod.invalidate_cache()


def test_valid_until_is_when_the_curve_reaches_the_revoke_score():
    rule = {"id": "t", "name": "t", "halfLifeDays": 10, "revokeScore": 25,
            "maxAgeHalfLives": 10, "reactionPoints": [], "appliesTo": ["*"],
            "builtin": False}
    # 100 -> 25 is exactly two half-lives.
    vu = decay_mod.valid_until(100, "2026-01-01T00:00:00+00:00", rule)
    assert vu.startswith("2026-01-21"), vu


def test_valid_until_is_capped_by_the_hard_age_ceiling():
    """A 100%-confidence indicator against a low revoke score would otherwise be
    dated years out and outlive any honest claim about it."""
    rule = {"id": "t", "name": "t", "halfLifeDays": 10, "revokeScore": 1,
            "maxAgeHalfLives": 2, "reactionPoints": [], "appliesTo": ["*"],
            "builtin": False}
    vu = decay_mod.valid_until(100, "2026-01-01T00:00:00+00:00", rule)
    # Ceiling is 10 * 2 = 20 days, well before the curve reaches 1.
    assert vu.startswith("2026-01-21"), vu


def test_valid_until_needs_a_last_seen_rather_than_inventing_one():
    rule = decay_mod._fallback()
    assert decay_mod.valid_until(80, None, rule) is None
    assert decay_mod.valid_until(80, "not-a-date", rule) is None


def test_reaction_points_report_the_next_threshold_and_when():
    """Decay with no reaction points is invisible: an indicator is actionable one
    day and silently gone the next."""
    rule = {"id": "t", "name": "t", "halfLifeDays": 10, "revokeScore": 10,
            "maxAgeHalfLives": 10, "reactionPoints": [80, 50, 20],
            "appliesTo": ["*"], "builtin": False}
    # Fresh at 100: the next crossing is 80.
    nxt = decay_mod.next_reaction(100, 0.0, rule)
    assert nxt["score"] == 80
    assert nxt["inDays"] > 0
    # Already decayed past 80 (one half-life -> 50): next is 20.
    nxt = decay_mod.next_reaction(100, 10.0, rule)
    assert nxt["score"] == 20


def test_no_next_reaction_once_every_point_is_passed():
    rule = {"id": "t", "name": "t", "halfLifeDays": 10, "revokeScore": 5,
            "maxAgeHalfLives": 20, "reactionPoints": [80], "appliesTo": ["*"],
            "builtin": False}
    assert decay_mod.next_reaction(100, 100.0, rule) is None


def test_lifecycle_names_the_rule_so_the_policy_is_arguable():
    """"Expires in 12 days" is a fact an analyst cannot argue with. "Expires in 12
    days under the 14-day IP rule" is one they can go and change."""
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        rule = decay_mod.rule_for(conn, "ip")
    lc = lifecycle_of({"confidence": 80, "type": "ip",
                       "last_seen": "2026-07-01T00:00:00+00:00"}, rule=rule)
    assert lc["rule"]["id"] and lc["rule"]["name"]
    assert lc["revokeScore"] == rule["revokeScore"]
    assert lc["validUntil"]
    # And without a rule the block is still complete, just unattributed.
    bare = lifecycle_of({"confidence": 80, "type": "ip",
                         "last_seen": "2026-07-01T00:00:00+00:00"})
    assert "rule" not in bare
    assert bare["effectiveConfidence"] == lc["effectiveConfidence"]


def test_a_disabled_rule_falls_through_to_the_catch_all():
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        conn.commit()
        conn.execute("UPDATE decay_rules SET enabled=0 WHERE applies_to LIKE ?", ('%"ip"%',))
        conn.commit()
        decay_mod.invalidate_cache()
        assert decay_mod.rule_for(conn, "ip")["halfLifeDays"] == DEFAULT_HALFLIFE
        conn.execute("UPDATE decay_rules SET enabled=1 WHERE applies_to LIKE ?", ('%"ip"%',))
        conn.commit()
        decay_mod.invalidate_cache()


def test_rule_lookup_survives_a_broken_table_without_changing_the_curve():
    """An indicator must never decay differently just because a lookup failed."""
    class Broken:
        def execute(self, *a, **k):
            raise RuntimeError("table is gone")

    rule = decay_mod.rule_for(Broken(), "ip")
    assert rule["halfLifeDays"] == DEFAULT_HALFLIFE
    assert rule["revokeScore"] == EXPIRY_FLOOR


def test_half_life_prefers_the_rule_over_the_constant():
    assert half_life("ip") == DECAY_HALFLIFE_DAYS["ip"]
    assert half_life("ip", {"halfLifeDays": 99}) == 99


def test_api_rejects_settings_that_would_empty_the_store(client, auth):
    """A zero half-life expires everything instantly and a revoke score of 100
    revokes on import. Both are one keystroke away and invisible until the store
    is empty."""
    rid = "builtin-default"
    for bad in ({"half_life_days": 0}, {"half_life_days": -5},
                {"revoke_score": 100}, {"revoke_score": 0},
                {"max_age_half_lives": 0}):
        r = client.patch(f"/cti/decay-rules/{rid}", json=bad, headers=auth)
        assert r.status_code == 400, f"{bad} was accepted: {r.status_code}"


def test_api_lists_and_updates_a_rule(client, auth):
    listed = client.get("/cti/decay-rules", headers=auth)
    assert listed.status_code == 200
    rules_ = listed.json()
    assert rules_ and any(r["appliesTo"] == ["*"] for r in rules_)

    rid = "builtin-default"
    original = next(r for r in rules_ if r["id"] == rid)["halfLifeDays"]
    try:
        r = client.patch(f"/cti/decay-rules/{rid}",
                         json={"half_life_days": 45, "reaction_points": [70, 30, 999, 0]},
                         headers=auth)
        assert r.status_code == 200, r.text
        got = r.json()
        assert got["halfLifeDays"] == 45
        # Out-of-range points are dropped rather than stored as nonsense.
        assert got["reactionPoints"] == [70, 30]
    finally:
        client.patch(f"/cti/decay-rules/{rid}", json={"half_life_days": original,
                     "reaction_points": decay_mod.DEFAULT_REACTION_POINTS}, headers=auth)


def test_unknown_rule_is_404(client, auth):
    r = client.patch("/cti/decay-rules/nope", json={"half_life_days": 20}, headers=auth)
    assert r.status_code == 404


def test_decay_pass_stores_valid_until():
    """Stored so "what expires this week?" is an indexed range scan rather than a
    decay computation over the whole store."""
    import uuid
    from dashboard_api.ioc_lifecycle import decay_iocs
    with get_conn() as conn:
        decay_mod.seed_builtin_rules(conn)
        iid = f"vu-{uuid.uuid4().hex[:8]}"
        conn.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,"
            "actor,first_seen,last_seen,tags,status,sightings,intel_score) "
            "VALUES (?,'ip',?,'c2',90,'critical','feed','', ?,?,'[]','active',1,0)",
            (iid, f"198.19.{uuid.uuid4().int % 200}.7",
             "2026-07-01T00:00:00+00:00", "2026-07-01T00:00:00+00:00"))
        conn.commit()
        try:
            res = decay_iocs(conn)
            conn.commit()
            assert res["dated"] >= 1
            row = conn.execute("SELECT valid_until FROM iocs WHERE id=?", (iid,)).fetchone()
            assert row["valid_until"], "decay pass did not store valid_until"
        finally:
            conn.execute("DELETE FROM iocs WHERE id=?", (iid,))
            conn.commit()
