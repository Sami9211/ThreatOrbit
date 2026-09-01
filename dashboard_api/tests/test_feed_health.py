"""A feed can die without anyone noticing. These make that impossible.

Found on the live store: all thirty-five malware-family trails had been
returning 404 for days, because the upstream project moved its detection content
into a separate repository. Every sync in that window reported success. Nothing
was wrong with the tally - a feed that fails logs a warning and contributes an
empty list, and an empty list is exactly what a feed with nothing new to say
contributes too. The store simply stopped learning family names, which is the
single most valuable thing this engine does, and said nothing.

The URL was a one-line fix. The silence was the defect, so these tests pin the
properties that end it: that a fetch outcome is recorded per source, that
partial loss is reported rather than rounded away, that "failing" carries the
date it started, and that a mirror never gets to look like a healthy origin.
"""
import uuid

import pytest

import dashboard_api.connectors as conn_mod
from dashboard_api.connectors import (
    FEED_FAILED, FEED_MIRRORED, FEED_OK, FEED_UNCHANGED, _bulk_source_id,
    _record_feed_health)
from dashboard_api.db import get_conn


class _Resp:
    def __init__(self, text="", not_modified=False, headers=None):
        self.text = text
        self.not_modified = not_modified
        self.headers = headers or {}


def _row(sid):
    with get_conn() as conn:
        return conn.execute(
            "SELECT last_status, last_status_detail, last_ok, served_via "
            "FROM intel_sources WHERE id=?", (sid,)).fetchone()


@pytest.fixture()
def feed():
    """A source name nothing else in the suite touches."""
    name = f"health-test-{uuid.uuid4().hex[:8]}"
    yield name
    with get_conn() as conn:
        conn.execute("DELETE FROM intel_sources WHERE id=?", (_bulk_source_id(name),))
        conn.commit()


# -- the outcome is recorded at all -------------------------------------------

def test_a_fetch_outcome_is_persisted(feed):
    """The whole point: after a sync, the store can say what happened to each
    source. Before this, the only record was a log line."""
    _record_feed_health({feed: {"status": FEED_OK}})
    r = _row(_bulk_source_id(feed))
    assert r is not None, "nothing was written - the outcome is invisible again"
    assert r["last_status"] == FEED_OK
    assert r["last_ok"], "a successful fetch must timestamp itself"


def test_a_source_that_has_never_been_fetched_still_gets_a_row(feed):
    """The write has to be an upsert. It used to be a bare UPDATE, which matched
    zero rows on the first ever sync of a feed - so the one case where an
    operator most needs to know whether a new feed works recorded nothing."""
    with get_conn() as conn:
        assert conn.execute("SELECT 1 FROM intel_sources WHERE id=?",
                            (_bulk_source_id(feed),)).fetchone() is None
    _record_feed_health({feed: {"status": FEED_FAILED, "detail": "404"}})
    assert _row(_bulk_source_id(feed))["last_status"] == FEED_FAILED


def test_the_error_is_kept_in_the_words_it_arrived_in(feed):
    """"failed" is not actionable; "404 Not Found" is. An operator has to be able
    to tell a moved file from a rate limit from a blocked egress."""
    _record_feed_health({feed: {"status": FEED_FAILED, "detail": "HTTP 404 Not Found"}})
    assert "404" in (_row(_bulk_source_id(feed))["last_status_detail"] or "")


# -- failing since when -------------------------------------------------------

def test_last_ok_only_moves_forward(feed):
    """A failing feed must KEEP the timestamp of its last success. Overwriting it
    would erase the only number that distinguishes a blip from an outage."""
    _record_feed_health({feed: {"status": FEED_OK}}, now="2026-01-01T00:00:00+00:00")
    _record_feed_health({feed: {"status": FEED_FAILED, "detail": "404"}},
                        now="2026-06-01T00:00:00+00:00")
    r = _row(_bulk_source_id(feed))
    assert r["last_status"] == FEED_FAILED
    assert r["last_ok"] == "2026-01-01T00:00:00+00:00", \
        "the failure erased the date it started failing"


def test_a_304_counts_as_the_feed_answering(feed):
    """Not-modified is a success. A feed that says "nothing new" every day for a
    month is healthy, and treating it as silence would raise a false alarm on
    exactly the feeds that are most stable."""
    _record_feed_health({feed: {"status": FEED_UNCHANGED}},
                        now="2026-03-01T00:00:00+00:00")
    assert _row(_bulk_source_id(feed))["last_ok"] == "2026-03-01T00:00:00+00:00"


# -- only a transition is news ------------------------------------------------

def test_a_feed_that_just_broke_is_announced(feed):
    _record_feed_health({feed: {"status": FEED_OK}})
    assert _record_feed_health({feed: {"status": FEED_FAILED}}) == [feed]


def test_a_feed_that_was_already_broken_is_not_announced_again(feed):
    """Otherwise every sync re-raises every outage, and the bell becomes a
    thing people turn off."""
    _record_feed_health({feed: {"status": FEED_OK}})
    _record_feed_health({feed: {"status": FEED_FAILED}})
    assert _record_feed_health({feed: {"status": FEED_FAILED}}) == []


def test_a_feed_that_has_never_worked_is_not_an_outage(feed):
    """A source that fails on its first ever fetch is a configuration question -
    somebody typed a URL wrong - not something that broke."""
    assert _record_feed_health({feed: {"status": FEED_FAILED}}) == []


def test_recovery_is_not_announced_as_a_break(feed):
    _record_feed_health({feed: {"status": FEED_FAILED}})
    assert _record_feed_health({feed: {"status": FEED_OK}}) == []


# -- a mirror is a host, not a source -----------------------------------------

def test_a_mirrored_feed_records_the_host_that_answered(feed):
    _record_feed_health({feed: {"status": FEED_MIRRORED,
                                "served_via": "https://mirror.example/list.txt"}})
    r = _row(_bulk_source_id(feed))
    assert r["served_via"] == "https://mirror.example/list.txt"
    assert r["last_ok"], "a mirrored fetch is still a fetch that worked"


def test_a_recovered_origin_stops_being_described_as_mirrored(feed):
    _record_feed_health({feed: {"status": FEED_MIRRORED,
                                "served_via": "https://mirror.example/list.txt"}})
    _record_feed_health({feed: {"status": FEED_OK}})
    assert _row(_bulk_source_id(feed))["served_via"] is None


def test_every_mirror_republishes_the_feed_it_claims_to():
    """A mirror keeps the ORIGINAL source_id, so if it pointed at a different
    list the store would attribute one source's opinion to another - and count
    it as corroboration.

    Each entry declares the upstream URL its mirror was built from. The rule is
    the HOST: a different path on the source's own host is the same publisher's
    list (the Tor Project publishes its exit nodes at two endpoints in two
    formats, and FireHOL mirrors the other one), while a different host is
    somebody else's opinion wearing this source's name.
    """
    from urllib.parse import urlsplit
    by_name = {f[0]: f[1] for f in conn_mod._BULK_FEEDS}
    for name, (mirror_url, upstream) in conn_mod.feed_mirrors().items():
        assert name in by_name, f"{name} has a mirror but is not a configured feed"
        configured = by_name[name]
        assert urlsplit(upstream).hostname == urlsplit(configured).hostname, (
            f"{name}'s mirror claims to republish {upstream}, which is not "
            f"published by {urlsplit(configured).hostname} - that is a different "
            f"source, and using it here would fabricate corroboration")
        assert mirror_url != configured, f"{name}'s mirror is its own origin"


def test_a_mirror_does_not_become_a_second_source(monkeypatch):
    """The error this whole mechanism is one step away from: fetching
    blocklist.de's list from a mirror does not make it two independent sources.
    Corroboration is the signal the platform exists to produce, and it is only
    worth anything if two sources means two opinions."""
    name = next(iter(conn_mod.feed_mirrors()))
    mirror_url = conn_mod.feed_mirrors()[name][0]

    def fake(url, headers=None, **kw):
        if url == mirror_url:
            return _Resp("203.0.113.77\n")
        raise OSError("origin refused the connection")

    monkeypatch.setattr(conn_mod, "_http_get", fake)
    out = conn_mod._fetch_bulk_osint({})
    hits = [o for o in out if o["value"] == "203.0.113.77"]
    assert hits, "the mirror fallback produced nothing"
    assert {h["source"] for h in hits} == {_bulk_source_id(name)}, \
        "the mirror was recorded as its own source"


# -- the family trails ---------------------------------------------------------

def test_a_catalogue_that_fetches_nothing_is_not_a_healthy_sync(monkeypatch):
    """The exact outage. Every family 404s; the sync still returns; the store
    must end up saying the family source FAILED rather than saying nothing."""
    monkeypatch.setattr(conn_mod, "_http_get",
                        lambda url, headers=None, **kw: (_ for _ in ()).throw(
                            OSError("HTTP 404 Not Found")))
    conn_mod._fetch_bulk_osint({})
    r = _row(_bulk_source_id(conn_mod._MALTRAIL_SOURCE))
    assert r is not None and r["last_status"] == FEED_FAILED, \
        "thirty-five dead trails reported as a healthy sync"


def test_partial_family_loss_is_reported_not_rounded_away(monkeypatch):
    """A catalogue that quietly stops covering some of its families still looks
    healthy at the tally. The detail has to name them, because "we no longer
    track redline" is a coverage decision somebody should get to make."""
    gone = "redline"

    def fake(url, headers=None, **kw):
        if f"/{gone}.txt" in url:
            raise OSError("HTTP 404 Not Found")
        if "/malware/" in url:
            return _Resp("198.51.100.9\n")
        raise OSError("not part of this test")

    monkeypatch.setattr(conn_mod, "_http_get", fake)
    conn_mod._fetch_bulk_osint({})
    r = _row(_bulk_source_id(conn_mod._MALTRAIL_SOURCE))
    assert r["last_status"] == FEED_OK, "one dead family must not condemn the rest"
    assert gone in (r["last_status_detail"] or ""), \
        f"the detail does not say {gone} is missing: {r['last_status_detail']!r}"


def test_the_family_trails_are_not_fetched_from_the_retired_path():
    """The content moved out of the engine repository into its own. Guarding the
    specific path because the failure it caused was silent for days."""
    url = conn_mod._MALTRAIL_FAMILY_URL
    assert "/maltrail/" not in url, \
        "still pointing at the engine repo, where every family trail is a 404"
    assert url.startswith("https://"), "trails must be fetched over TLS"
    assert "{}" in url, "the template has to interpolate the family"


def test_a_source_is_named_for_a_person_not_for_the_code(feed):
    """The panel headed "how much each source is trusted" listed
    `osint:abuse.ch URLhaus`. Every writer of a source row set name = id, so the
    slug the code joins on was also the label an analyst had to read."""
    _record_feed_health({feed: {"status": FEED_OK}})
    with get_conn() as conn:
        row = conn.execute("SELECT id, name FROM intel_sources WHERE id=?",
                           (_bulk_source_id(feed),)).fetchone()
    assert row["name"] == feed, f"named {row['name']!r} rather than {feed!r}"
    assert row["name"] != row["id"]


def test_a_name_already_set_is_never_overwritten(feed):
    """Same rule the Admiralty grade follows: ours is a default, and anything
    somebody else put there outranks it."""
    sid = _bulk_source_id(feed)
    _record_feed_health({feed: {"status": FEED_OK}})
    with get_conn() as conn:
        conn.execute("UPDATE intel_sources SET name=? WHERE id=?",
                     ("what the analyst calls it", sid))
        conn.commit()
    _record_feed_health({feed: {"status": FEED_OK}})
    with get_conn() as conn:
        assert conn.execute("SELECT name FROM intel_sources WHERE id=?",
                            (sid,)).fetchone()["name"] == "what the analyst calls it"
