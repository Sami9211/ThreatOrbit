"""A CTI hunt was returning the whole store and reporting the page size.

Two bugs wearing each other as cover, found on a live 530,238-indicator store.

`extract_tokens` pulled keywords out of QUOTED strings only. Nobody types
quotes, so a hunt for `emotet` extracted nothing, built no WHERE clause, and
matched **every row in the store**. And `run_ioc_hunt` reported
`hits = len(rows)` AFTER the `LIMIT`, so it always said fifty. Fifty results for
`emotet`, ordered by confidence, looks exactly like a hunt that worked.

Measured before the fix - every one of these "found" all 530,238:

    cobaltstrike   reported 50     actually 11,253
    emotet         reported 50     actually  8,001
    phishing       reported 50     actually 149,747

The saved hunt then carried that 50 forward as its recorded result, which is
what the UI shows as the hunt's artefact count.
"""
import uuid

import pytest

from dashboard_api.db import get_conn
from dashboard_api.hunting import extract_tokens, run_ioc_hunt


@pytest.fixture()
def seeded():
    """Indicators with a term nothing else in the suite uses."""
    tag = f"hunttag{uuid.uuid4().hex[:8]}"
    values = [f"{tag}-{i}.example.test" for i in range(7)]
    with get_conn() as conn:
        for i, v in enumerate(values):
            conn.execute(
                "INSERT INTO iocs (id,type,value,severity,confidence,intel_score,source,"
                "threat_type,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), "domain", v, "high" if i < 4 else "low",
                 60 + i, 50 + i, "test-feed", f"{tag}-activity",
                 "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"))
        conn.commit()
    yield tag, values
    with get_conn() as conn:
        conn.executemany("DELETE FROM iocs WHERE value=?", [(v,) for v in values])
        conn.commit()


# -- a bare word is a search term ----------------------------------------------

def test_an_unquoted_word_is_a_keyword():
    """The defect. Nobody types quotes, and a query that extracts nothing
    matched everything."""
    assert extract_tokens("emotet")["keywords"] == ["emotet"]
    assert "cobaltstrike" in extract_tokens("cobaltstrike C2 infrastructure")["keywords"]


def test_quotes_still_mean_a_phrase():
    assert extract_tokens('"cobalt strike"')["keywords"] == ["cobalt strike"]


def test_a_severity_word_is_not_also_a_keyword():
    """`critical phishing` is a severity filter and one search term, not two
    search terms one of which matches every critical row by substring."""
    t = extract_tokens("critical phishing")
    assert t["severities"] == ["critical"]
    assert t["keywords"] == ["phishing"]


def test_techniques_and_addresses_are_not_duplicated_as_keywords():
    t = extract_tokens("T1071 beacon 198.51.100.4")
    assert t["techniques"] == ["T1071"] and t["ips"] == ["198.51.100.4"]
    assert t["keywords"] == ["beacon"]


def test_a_two_letter_domain_term_survives():
    """`c2` is shorter than the noise floor and means something here."""
    assert "c2" in extract_tokens("emotet c2")["keywords"]


# -- the count is the count -----------------------------------------------------

def test_the_hit_count_is_not_the_page_size(seeded):
    """`hits` was `len(rows)` after the LIMIT, so it could never exceed the
    page. A number that is the page size dressed up as a finding is worse than
    no number."""
    tag, values = seeded
    r = run_ioc_hunt(tag, limit=3)
    assert r["hits"] == len(values), f"reported {r['hits']} of {len(values)}"
    assert r["shown"] == 3, "the page should still be the page"
    assert len(r["results"]) == 3


def test_the_count_survives_a_limit_larger_than_the_matches(seeded):
    tag, values = seeded
    r = run_ioc_hunt(tag, limit=500)
    assert r["hits"] == len(values) == r["shown"]


def test_the_window_function_column_is_not_returned_as_a_field(seeded):
    """The count rides the same scan as the page; that plumbing must not leak
    into something that looks like an indicator attribute."""
    tag, _ = seeded
    r = run_ioc_hunt(tag)
    assert r["results"], "expected matches"
    assert "_total" not in r["results"][0]


# -- nothing searchable means nothing, not everything ---------------------------

def test_an_empty_query_returns_nothing_rather_than_the_whole_store():
    """The safety property behind the whole defect: no extractable term must
    never mean "match every row"."""
    r = run_ioc_hunt("")
    assert r["hits"] == 0 and r["results"] == []
    assert r["scanned"] > 0, "it should still say how much it looked at"


def test_a_query_of_only_stopwords_returns_nothing():
    assert run_ioc_hunt("where and by stats count")["hits"] == 0


# -- ranking --------------------------------------------------------------------

def test_results_lead_with_the_highest_intel_score(seeded):
    """A hunt is for the ones worth opening. A feed's own confidence says
    nothing about corroboration, local sightings or decay."""
    tag, _ = seeded
    r = run_ioc_hunt(tag, limit=3)
    scores = [x["intel_score"] for x in r["results"]]
    assert scores == sorted(scores, reverse=True), scores
