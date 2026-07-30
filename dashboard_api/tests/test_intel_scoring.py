"""Composite intel score: ranking a 315k store by relevance rather than arrival.

The store ranked by `confidence` - a number copied verbatim from whichever feed
wrote the row first - so a value nine sources agree on sorted identically to one
stale list's guess. These pin the properties that make the score worth trusting.
"""
from datetime import datetime, timedelta, timezone

import pytest

from dashboard_api.intel_scoring import band_for, score_indicator


def _ioc(**kw):
    base = {"type": "domain", "confidence": 70, "last_seen": None,
            "report_id": None, "actor": ""}
    return {**base, **kw}


def test_corroboration_outranks_a_single_source_making_the_same_claim():
    """The core of the whole change. Two feeds independently asserting a value is
    a stronger claim than one feed asserting it, and the store could not
    previously express the difference at all."""
    alone = score_indicator(_ioc(), source_count=1)["score"]
    pair = score_indicator(_ioc(), source_count=2)["score"]
    many = score_indicator(_ioc(), source_count=5)["score"]
    assert alone < pair < many, f"{alone} !< {pair} !< {many}"


def test_corroboration_saturates_rather_than_running_away():
    """Twenty feeds copying one upstream list is not twenty confirmations. The
    step from 1->2 sources must be the informative one; 20->50 must be flat."""
    s2 = score_indicator(_ioc(), source_count=2)["score"]
    s5 = score_indicator(_ioc(), source_count=5)["score"]
    s50 = score_indicator(_ioc(), source_count=50)["score"]
    assert s5 - s2 < s2 - score_indicator(_ioc(), source_count=1)["score"]
    assert s50 == s5, "corroboration bonus is not capped"


def test_local_sighting_outweighs_any_amount_of_third_party_agreement():
    """A value seen in THIS deployment's telemetry is the only evidence that
    concerns this network. It must rank above a value many feeds merely list."""
    seen_here = score_indicator(_ioc(), source_count=1, local_sightings=1)["score"]
    listed_widely = score_indicator(_ioc(), source_count=50)["score"]
    assert seen_here > listed_widely, f"local {seen_here} should beat listed {listed_widely}"


def test_an_unreliable_source_asserting_high_confidence_loses_to_a_reliable_one():
    """Reliability is a multiplier, not a flat bonus: 90% from a source we cannot
    judge must not outrank 70% from one we can."""
    unreliable = score_indicator(_ioc(confidence=90), reliability="F")["score"]
    reliable = score_indicator(_ioc(confidence=70), reliability="A")["score"]
    assert reliable > unreliable, f"grade-A 70% ({reliable}) should beat grade-F 90% ({unreliable})"


def test_attribution_counts_for_something_but_not_much():
    """Arriving with a report attached is real context, but it is not evidence
    the value is more likely malicious - it must not dominate corroboration."""
    bare = score_indicator(_ioc())["score"]
    attributed = score_indicator(_ioc(report_id="r-1"))["score"]
    corroborated = score_indicator(_ioc(), source_count=3)["score"]
    assert bare < attributed < corroborated


def test_age_decays_the_score_by_indicator_type():
    """A phishing URL from six months ago is not the claim it was on day one; a
    file hash largely is. The existing per-type half-lives drive this."""
    # A moderate age, not an ancient one: past a few half-lives EVERY type
    # floors at zero and the comparison becomes vacuous (which is correct
    # behaviour, but proves nothing about per-type decay).
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    stale_url = score_indicator(_ioc(type="url", last_seen=old))["score"]
    stale_hash = score_indicator(_ioc(type="hash", last_seen=old))["score"]
    assert stale_url < stale_hash, "a stale URL should decay faster than a stale hash"
    assert stale_url < score_indicator(_ioc(type="url"))["score"]


def test_the_score_is_bounded():
    """Everything at once must not exceed 100, or the band thresholds lie."""
    maxed = score_indicator(_ioc(confidence=100, report_id="r", actor="APT"),
                            source_count=50, reliability="A", local_sightings=99)
    assert 0 <= maxed["score"] <= 100
    floor = score_indicator(_ioc(confidence=0), reliability="F")
    assert floor["score"] >= 0


def test_every_score_explains_itself():
    """A ranking an analyst cannot interrogate is one they are right not to
    trust. "Why is this 84?" has to be answerable in the UI."""
    out = score_indicator(_ioc(report_id="r-1"), source_count=4,
                          reliability="B", local_sightings=2)
    labels = [c["label"] for c in out["components"]]
    assert "Source claim, aged" in labels
    assert "Corroboration" in labels
    assert "Seen in your environment" in labels
    assert "Attributed" in labels
    # The parts must actually add up to the whole, or the explanation is decoration.
    assert sum(c["delta"] for c in out["components"]) == out["score"]
    for c in out["components"]:
        assert c["why"], f"component {c['label']} has no explanation"


@pytest.mark.parametrize("score,band", [
    (100, "high"), (75, "high"), (74, "moderate"), (50, "moderate"),
    (49, "low"), (25, "low"), (24, "weak"), (0, "weak"),
])
def test_bands_are_contiguous(score, band):
    assert band_for(score) == band


def test_live_mode_maintains_the_score_without_anyone_pressing_a_button():
    """The IOC list ranks by the PERSISTED `intel_score`, so something has to
    keep it current as corroboration and age accumulate.

    Lifecycle maintenance used to hang off the synthetic engine tick only. In
    live mode - where SYNTHETIC_ALLOWED is false and that generator is refused -
    it therefore never ran, so the default ranking silently froze at whatever
    each indicator scored at import, before any other source had corroborated
    it. This pins that the LIVE scheduler owns the job.
    """
    import inspect
    from dashboard_api import main

    src = inspect.getsource(main._connector_scheduler)
    assert "decay_iocs" in src, (
        "the live scheduler must run IOC lifecycle maintenance; without it the "
        "persisted intel_score never refreshes in the only mode that matters")
    assert "LIFECYCLE_TICK_SECONDS" in src, (
        "lifecycle maintenance must be on its own cadence, not the connector tick")


def test_the_persisted_score_agrees_with_a_freshly_computed_one(tmp_path, monkeypatch):
    """Sorting by a stored number while displaying a recomputed one is how a
    list ends up showing an 81 below a 75. After a maintenance pass the two must
    agree for every indicator."""
    from dashboard_api.db import get_conn
    from dashboard_api.ioc_lifecycle import decay_iocs
    from dashboard_api.intel_scoring import DEFAULT_RELIABILITY, score_indicator

    now = datetime.now(timezone.utc)
    vals = [("ip", "192.0.2.10", 80, 1), ("domain", "score-agree.test", 60, 3)]
    with get_conn() as conn:
        for itype, value, conf, nsrc in vals:
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,"
                "actor,first_seen,last_seen,tags,status,sightings,intel_score) "
                "VALUES (?,?,?,?,?,?,?,'',?,?,'[]','active',1,0)",
                (f"sc-{value}", itype, value, "malicious-activity", conf, "medium",
                 "feed-a", now.isoformat(), now.isoformat()))
            for n in range(nsrc):
                conn.execute(
                    "INSERT INTO observable_sources (value,source_id,first_seen,last_seen,"
                    "raw_label,confidence) VALUES (?,?,?,?,'',?) "
                    "ON CONFLICT(value,source_id) DO NOTHING",
                    (value, f"feed-{n}", now.isoformat(), now.isoformat(), conf))
        conn.commit()
        decay_iocs(conn, now=now)
        conn.commit()

        for itype, value, conf, nsrc in vals:
            row = conn.execute(
                "SELECT * FROM iocs WHERE value=?", (value,)).fetchone()
            srcs = [r["source_id"] for r in conn.execute(
                "SELECT source_id FROM observable_sources WHERE value=?", (value,)).fetchall()]
            fresh = score_indicator(dict(row), source_count=max(1, len(srcs)),
                                    reliability=DEFAULT_RELIABILITY,
                                    local_sightings=0, now=now)["score"]
            assert row["intel_score"] == fresh, (
                f"{value}: stored {row['intel_score']} != recomputed {fresh}")
        conn.execute("DELETE FROM iocs WHERE value IN (?,?)", (vals[0][1], vals[1][1]))
        conn.execute("DELETE FROM observable_sources WHERE value IN (?,?)",
                     (vals[0][1], vals[1][1]))
        conn.commit()


def test_store_summary_answers_what_is_actually_in_the_store(client, auth):
    """"315,185 indicators" says nothing about whether they are worth having.
    These are the numbers that do."""
    r = client.get("/cti/store-summary", headers=auth)
    assert r.status_code == 200, r.text
    s = r.json()
    assert set(s["bands"]) == {"high", "moderate", "low", "weak"}
    assert sum(s["bands"].values()) == s["total"], (
        "the band counts do not add up to the total")
    assert set(s["corroboration"]) == {"1", "2", "3+"}
    assert 0 <= s["corroboratedShare"] <= 100
    assert isinstance(s["activities"], list) and isinstance(s["sources"], list)
    assert isinstance(s["expiringWithin7Days"], int)


def test_store_summary_share_is_consistent_with_its_own_counts(client, auth):
    """The share is the honest figure - 4,000 corroborated out of 315,185 is a
    very different store from 4,000 out of 6,000 - so it must not drift from the
    counts it is derived from."""
    s = client.get("/cti/store-summary", headers=auth).json()
    corr = s["corroboration"]
    known = corr["1"] + corr["2"] + corr["3+"]
    if known and s["total"]:
        expected = round(100 * (corr["2"] + corr["3+"]) / s["total"], 1)
        assert abs(s["corroboratedShare"] - expected) < 0.05
