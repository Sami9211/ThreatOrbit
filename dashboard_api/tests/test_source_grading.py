"""Admiralty source grading: the multiplier that was applied to everything and
differentiated nothing.

The composite score multiplies each claim by its source's reliability grade -
the right shape, and completely inert while every source sat at the shipped
default C. Measured on the real store: 20 distinct scores across 327,981
indicators, 95% of them inside a 15-point band, and a list "sorted by relevance"
that opened on whichever phishing domain sorted first alphabetically.

A grade is a judgement, so these pin the properties that make it trustworthy
rather than the grades themselves: that it varies, that it moves the score, that
it is visible with a reason, and that an operator's judgement outranks ours.
"""
import uuid

from dashboard_api.connectors import feed_reliability_defaults
from dashboard_api.db import _apply_feed_reliability_defaults, get_conn
from dashboard_api.intel_scoring import RELIABILITY_WEIGHT, score_indicator


def _source(conn, sid, grade="C"):
    conn.execute(
        "INSERT INTO intel_sources (id,name,reliability,first_seen,last_seen) "
        "VALUES (?,?,?,'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00') "
        "ON CONFLICT(id) DO UPDATE SET reliability=?", (sid, sid, grade, grade))


# -- the grades themselves --------------------------------------------------


def test_the_shipped_grades_actually_differ():
    """The whole defect was uniformity. A grading where every source scores the
    same is arithmetically identical to no grading at all, and it is the reason
    the store's scores collapsed into a 15-point band."""
    grades = {g for g, _ in feed_reliability_defaults().values()}
    assert len(grades) >= 3, f"only {grades} in use - this differentiates nothing"


def test_no_public_feed_is_graded_completely_reliable():
    """Admiralty A is a claim about a long history with no known failures. It is
    not ours to award to a public blocklist, and handing it out would make the
    top of the scale meaningless."""
    top = [sid for sid, (g, _) in feed_reliability_defaults().items() if g == "A"]
    assert not top, f"graded A: {top}"


def test_every_shipped_grade_states_why():
    """A weighting nobody can interrogate is one an analyst is right to
    distrust - and this one silently multiplies every score the source
    contributes."""
    for sid, (grade, reason) in feed_reliability_defaults().items():
        assert grade in RELIABILITY_WEIGHT, f"{sid}: {grade} is not an Admiralty grade"
        assert reason and len(reason) > 30, f"{sid} has no usable reason"


def test_the_grade_actually_changes_the_score():
    """Otherwise this is bookkeeping. Same claim, same age, same corroboration -
    only the source differs."""
    ioc = {"type": "domain", "confidence": 80, "last_seen": None,
           "report_id": None, "actor": ""}
    b = score_indicator(ioc, reliability="B")["score"]
    c = score_indicator(ioc, reliability="C")["score"]
    d = score_indicator(ioc, reliability="D")["score"]
    assert b > c > d, f"B={b} C={c} D={d} - grading must separate them"


# -- whose judgement is in force -------------------------------------------


def test_an_operator_grading_is_never_overwritten_by_a_shipped_default():
    """Ours is a starting assessment. Theirs is knowledge of their own
    environment and of which feeds have burned them - so a later upgrade
    revising a default must not silently undo it."""
    sid = next(iter(feed_reliability_defaults()))
    with get_conn() as conn:
        # A store that has never synced holds no source rows, so the assertion
        # below would be vacuously true and the test would pass having proved
        # nothing. Create the row rather than skipping.
        before = conn.execute(
            "SELECT reliability, reliability_reason, reliability_set_by "
            "FROM intel_sources WHERE id=?", (sid,)).fetchone()
        preexisting = before is not None
        if not preexisting:
            _source(conn, sid)
        conn.execute(
            "UPDATE intel_sources SET reliability='F', reliability_reason=?, "
            "reliability_set_by='analyst@example.test' WHERE id=?",
            ("burned us twice", sid))
        conn.commit()
        # Scoped to THIS source rather than to a global count. A count of zero
        # assumed no other source row was ungraded, which stopped being true
        # once feeds began recording their fetch health BEFORE they had
        # contributed a value - a source that exists but has asserted nothing is
        # now a normal state, and it is the state a broken feed is in.
        _apply_feed_reliability_defaults(conn)
        after = conn.execute(
            "SELECT reliability FROM intel_sources WHERE id=?", (sid,)).fetchone()
        assert after["reliability"] == "F"
        # ...and once the operator's mark is cleared, the default applies again.
        # Every other row was just moved to its default by the pass above, so
        # this one is the only thing left that can change.
        conn.execute("UPDATE intel_sources SET reliability_set_by=NULL WHERE id=?", (sid,))
        conn.commit()
        assert _apply_feed_reliability_defaults(conn) == 1
        assert conn.execute("SELECT reliability FROM intel_sources WHERE id=?",
                            (sid,)).fetchone()["reliability"] == \
            feed_reliability_defaults()[sid][0]
        if preexisting:
            conn.execute(
                "UPDATE intel_sources SET reliability=?, reliability_reason=?, "
                "reliability_set_by=? WHERE id=?",
                (before["reliability"], before["reliability_reason"],
                 before["reliability_set_by"], sid))
        else:
            conn.execute("DELETE FROM intel_sources WHERE id=?", (sid,))
        conn.commit()


def test_the_defaults_pass_is_idempotent():
    """It runs on every boot so a revised default reaches existing installs.
    That is only safe if a second run is a no-op."""
    with get_conn() as conn:
        _apply_feed_reliability_defaults(conn)
        conn.commit()
        assert _apply_feed_reliability_defaults(conn) == 0


# -- the API ----------------------------------------------------------------


def test_sources_are_listed_with_their_grade_weight_and_reason(client, auth):
    sid = f"test-source-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        _source(conn, sid, "D")
        conn.commit()
    try:
        r = client.get("/cti/sources", headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        mine = next(s for s in body["items"] if s["id"] == sid)
        assert mine["reliability"] == "D"
        # The weight is what the grade DOES; without it the choice is abstract.
        assert mine["weight"] == RELIABILITY_WEIGHT["D"]
        assert mine["isDefault"] is True and mine["gradedBy"] == "shipped default"
        assert {s["grade"] for s in body["scale"]} == set(RELIABILITY_WEIGHT)
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM intel_sources WHERE id=?", (sid,))
            conn.commit()


def test_grading_a_source_records_who_decided_and_why(client, auth):
    sid = f"test-source-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        _source(conn, sid, "C")
        conn.commit()
    try:
        r = client.patch(f"/cti/sources/{sid}", headers=auth,
                         json={"reliability": "b", "reason": "verified C2 only"})
        assert r.status_code == 200, r.text
        assert r.json()["reliability"] == "B", "the grade is case-insensitive"
        assert r.json()["isDefault"] is False
        with get_conn() as conn:
            row = conn.execute(
                "SELECT reliability_set_by, reliability_reason FROM intel_sources "
                "WHERE id=?", (sid,)).fetchone()
            assert row["reliability_set_by"] == "admin@threatorbit.space"
            assert row["reliability_reason"] == "verified C2 only"
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM intel_sources WHERE id=?", (sid,))
            conn.commit()


def test_an_invalid_grade_is_refused_rather_than_stored(client, auth):
    """A grade outside A-F falls back to the default weight at scoring time, so
    storing one would silently un-grade the source."""
    sid = f"test-source-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        _source(conn, sid, "C")
        conn.commit()
    try:
        assert client.patch(f"/cti/sources/{sid}", headers=auth,
                            json={"reliability": "Z"}).status_code == 400
        assert client.patch("/cti/sources/no-such-source", headers=auth,
                            json={"reliability": "B"}).status_code == 404
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM intel_sources WHERE id=?", (sid,))
            conn.commit()


# -- what the ranking does with a tie --------------------------------------


def test_tied_scores_are_ordered_by_recency_not_by_a_random_uuid(client, auth):
    """A store of single-source blocklist entries has little to differentiate it:
    measured on the real store, 108,393 of 327,981 indicators share a five-point
    band. Breaking those ties on a random id makes "page one, sorted by
    relevance" a random sample of the tie."""
    # Scoped by a unique marker in the value rather than by taking the top of
    # the list: the suite seeds indicators of its own, so "the first three rows"
    # is a claim about other tests' data and fails depending on run order.
    marker = f"tiebreak{uuid.uuid4().hex[:10]}"
    made = []
    with get_conn() as conn:
        # Deliberately inserted out of date order, so passing cannot be an
        # accident of insertion order or of heap/rowid ordering.
        for i, ts in enumerate(["2026-03-01", "2026-05-01", "2026-04-01"]):
            iid = f"tie-{uuid.uuid4().hex[:10]}"
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,"
                "actor,first_seen,last_seen,tags,status,sightings,intel_score) "
                "VALUES (?,'domain',?,'malware-c2',70,'high','test-feed','',?,?,"
                "'[]','active',1,97)",
                (iid, f"{marker}-{i}.invalid", f"{ts}T00:00:00+00:00",
                 f"{ts}T00:00:00+00:00"))
            made.append(iid)
        conn.commit()
    try:
        items = client.get(f"/cti/iocs?sort=score&q={marker}", headers=auth).json()["items"]
        seen = [i["last_seen"] for i in items]
        assert len(seen) == 3, f"expected the seeded trio, got {len(seen)} rows"
        assert seen == sorted(seen, reverse=True), (
            f"tied scores came back in {seen} - newest must lead")
    finally:
        with get_conn() as conn:
            conn.executemany("DELETE FROM iocs WHERE id=?", [(i,) for i in made])
            conn.commit()
