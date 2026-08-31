"""The score ignored the one per-indicator fact the engine had just learned.

Measured on the live 499,501-indicator store: the composite score produced **24
distinct values** across the whole library, with 101,755 indicators sharing a
single one. That is not a ranking of indicators, it is a ranking of FEEDS -
`confidence` is a per-feed constant, every row was imported within minutes of
the others so the age decay is near-identical, and three reliability grades are
in play. The two terms meant to separate indicators from one another were both
flat zero: nothing in the store had been seen locally, and nothing carried an
actor.

Meanwhile 178,873 of those indicators carried a malware family - a fact about
THAT value, published by the source - and were scored as though they were
anonymous rows on a blocklist.

With the term, on the same data: 27 distinct scores, the top moves from 77 to
82, and the high band goes from **10 indicators to 1,724** - the values that are
both corroborated by a second source AND named by one of them. That is the right
population to promote, and it is the population an analyst should open first.
"""
import uuid

import pytest

from dashboard_api.db import get_conn
from dashboard_api.intel_scoring import (ATTRIBUTION_BONUS, FAMILY_BONUS,
                                         score_indicator)

_BASE = {"type": "domain", "confidence": 72, "last_seen": "2026-08-30T00:00:00+00:00"}


def _score(**extra) -> int:
    return score_indicator({**_BASE, **extra}, source_count=1)["score"]


def test_a_named_indicator_outranks_an_anonymous_one():
    assert _score(malware_family="emotet") == _score() + FAMILY_BONUS


def test_the_family_is_worth_less_than_an_actor():
    """A family is a class; an actor is a specific adversary. Commodity malware
    is sold to whoever pays, so naming the family is a smaller claim."""
    assert 0 < FAMILY_BONUS < ATTRIBUTION_BONUS


def test_an_attributed_indicator_is_not_paid_twice():
    """A report or an actor already means the value arrived attached to
    something. Paying for the family on top would make a fully-attributed
    indicator look better than the evidence supports."""
    both = _score(malware_family="emotet", actor="TA542")
    assert both == _score() + ATTRIBUTION_BONUS
    assert both == _score(actor="TA542")
    assert _score(malware_family="emotet", report_id="rep-1") == _score() + ATTRIBUTION_BONUS


def test_the_term_explains_itself():
    """A ranking an analyst cannot interrogate is one they are right not to
    trust, so every term names what it is and why."""
    comps = score_indicator({**_BASE, "malware_family": "qakbot"},
                            source_count=1)["components"]
    term = next(c for c in comps if c["label"] == "Attributed")
    assert term["delta"] == FAMILY_BONUS
    assert "qakbot" in term["why"]
    assert "bare value" in term["why"]
    # And the parts still add up to the whole.
    total = score_indicator({**_BASE, "malware_family": "qakbot"}, source_count=1)
    assert sum(c["delta"] for c in total["components"]) == total["score"]


def test_an_indicator_ranks_on_arrival_not_only_after_a_pass():
    """`initial_score` runs at INSERT so a new indicator sorts correctly
    immediately. If it ignored the family, every named indicator would sit
    below where it belongs until the next maintenance sweep - up to
    LIFECYCLE_TICK_SECONDS away."""
    from dashboard_api.ioc_store import COLUMNS, ioc_row

    plain = dict(zip(COLUMNS, ioc_row(type="domain", value=f"a-{uuid.uuid4().hex[:8]}.test",
                                      confidence=72)))
    named = dict(zip(COLUMNS, ioc_row(type="domain", value=f"b-{uuid.uuid4().hex[:8]}.test",
                                      confidence=72, malware_family="emotet")))
    assert named["intel_score"] == plain["intel_score"] + FAMILY_BONUS


def test_the_maintenance_pass_reads_the_column_it_scores_on():
    """The structural guard, and the one that matters most.

    `decay_iocs` rescores every indicator from a SELECT of named columns. Leave
    `malware_family` out of that list and the pass silently rescores 178,873
    named indicators as anonymous on its next sweep - undoing the term without
    a single test failing, because every unit test here passes a dict built by
    hand. This store has been bitten by exactly that before: `reg_domain` was
    written by nothing but the boot backfill for as long as it was.
    """
    import inspect

    from dashboard_api import ioc_lifecycle

    src = inspect.getsource(ioc_lifecycle.decay_iocs)
    select = src[src.index("SELECT id, type, value"):src.index("WHERE status != 'known-good'")]
    assert "malware_family" in select, (
        "the rescore pass does not read the column it scores on")


def test_the_pass_keeps_a_named_indicator_above_an_anonymous_one():
    """The behaviour behind that guard, end to end through the real pass."""
    from dashboard_api.ioc_lifecycle import decay_iocs
    from dashboard_api.ioc_store import insert_ioc

    tag = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        insert_ioc(conn, type="domain", value=f"plain-{tag}.example.test",
                   confidence=72, source="osint:trails")
        insert_ioc(conn, type="domain", value=f"named-{tag}.example.test",
                   confidence=72, source="osint:trails", malware_family="emotet")
        conn.commit()
        decay_iocs(conn)
        conn.commit()
        scores = {r["value"]: r["intel_score"] for r in conn.execute(
            "SELECT value, intel_score FROM iocs WHERE value LIKE ?",
            (f"%-{tag}.example.test",)).fetchall()}
    try:
        assert scores[f"named-{tag}.example.test"] > scores[f"plain-{tag}.example.test"], scores
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM iocs WHERE value LIKE ?", (f"%-{tag}.example.test",))
            conn.commit()
