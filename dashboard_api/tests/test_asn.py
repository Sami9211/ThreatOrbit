"""Network ownership lookup against the local BGP table.

An IP on its own is barely intelligence. "165.227.1.7, announced by AS14061
DigitalOcean, US" is - it says the infrastructure is cheap and rented, and it
makes every other indicator this deployment holds in the same AS reachable from
this one.

The table is loaded locally rather than proxied per query, so these cover the
parts that make that safe: the ordering trick the range lookup depends on, the
refusal to invent ownership for space nobody announces, and the honest
unavailable state before anything has been synced.

NOTE: the fixture is a verbatim-format slice of iptoasn's combined table. The
live download is not exercised here - the suite must not depend on a third-party
file being reachable.
"""
import ipaddress

import pytest

from dashboard_api import asn as asn_mod
from dashboard_api.db import get_conn

# `range_start \t range_end \t AS_number \t country_code \t AS_description`
#
# Real, routable ranges. Deliberately NOT the RFC 5737 documentation blocks
# (203.0.113.0/24 and friends): Python classes those as reserved, so lookup
# short-circuits on them before the table is ever consulted, and a fixture built
# from them would have tested the private-address branch while appearing to test
# the range query.
FIXTURE = "\n".join([
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed",          # AS0 -> dropped
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE",
    "165.227.0.0\t165.227.255.255\t14061\tUS\tDIGITALOCEAN-ASN",
    "2001:4860:4860::\t2001:4860:4860:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE",
    "malformed line with no tabs",
    "",
])
STALE = "2020-01-01T00:00:00+00:00"


@pytest.fixture
def loaded():
    with get_conn() as conn:
        conn.execute("DELETE FROM asn_ranges")
        n = asn_mod.load_rows(conn, asn_mod.parse_dataset(FIXTURE))
        asn_mod._record_sync(conn, n, "2026-07-29T00:00:00+00:00")
        conn.commit()
        yield conn
        conn.execute("DELETE FROM asn_ranges")
        conn.execute("DELETE FROM settings WHERE key IN ('asn_last_synced','asn_range_count')")
        conn.commit()


def test_hex_keys_sort_the_same_way_the_addresses_compare():
    """The whole range query rests on this. Storing addresses as integers would
    have worked for IPv4 and silently overflowed for IPv6, so they are stored as
    fixed-width hex - which is only correct if lexicographic order matches
    numeric order at every width."""
    v4 = ["0.0.0.0", "1.2.3.4", "9.0.0.0", "10.0.0.1", "192.168.0.1", "255.255.255.255"]
    keys = [asn_mod.hex_key(ipaddress.ip_address(a)) for a in v4]
    assert keys == sorted(keys), "IPv4 hex keys do not sort numerically"
    assert len({len(k) for k in keys}) == 1, "IPv4 keys must be fixed width"

    v6 = ["::", "::1", "2001:4860::", "2001:4860:4860::8888", "ffff::"]
    keys6 = [asn_mod.hex_key(ipaddress.ip_address(a)) for a in v6]
    assert keys6 == sorted(keys6), "IPv6 hex keys do not sort numerically"
    assert len({len(k) for k in keys6}) == 1


def test_malformed_and_unannounced_rows_are_dropped_not_stored():
    """AS0 is iptoasn's marker for allocated-but-not-announced space. Keeping
    those rows would turn "we know nothing about this IP" into a confident
    record owned by "Not routed"."""
    rows = list(asn_mod.parse_dataset(FIXTURE))
    assert len(rows) == 4, rows
    assert all(r[3] != 0 for r in rows), "AS0 rows must not be stored"


def test_lookup_finds_the_owning_network(loaded):
    hit = asn_mod.lookup(loaded, "165.227.1.7")
    assert hit is not None
    assert hit["asn"] == 14061
    assert hit["country"] == "US"
    assert "DIGITALOCEAN" in hit["description"]


def test_lookup_covers_range_boundaries(loaded):
    """Ranges are inclusive at both ends. An off-by-one here silently loses the
    first and last address of every network."""
    assert asn_mod.lookup(loaded, "1.0.0.0")["asn"] == 13335
    assert asn_mod.lookup(loaded, "1.0.0.255")["asn"] == 13335
    # Just outside, in the AS0 gap we deliberately dropped.
    assert asn_mod.lookup(loaded, "1.0.1.0") is None


def test_ipv6_is_looked_up_too(loaded):
    """IPv6 is the case an integer column would have broken, so it gets its own
    assertion rather than riding on the v4 path."""
    hit = asn_mod.lookup(loaded, "2001:4860:4860::8888")
    assert hit is not None and hit["asn"] == 15169


def test_families_do_not_bleed_into_each_other(loaded):
    """A v4 key is 8 hex chars and a v6 key is 32, so without the family filter
    every v4 address would compare below every v6 range and match the wrong
    row."""
    hit = asn_mod.lookup(loaded, "8.8.8.8")
    assert hit is not None and hit["asn"] == 15169
    assert hit["description"] == "GOOGLE"


def test_unannounced_space_returns_nothing_rather_than_the_nearest_network(loaded):
    """The query finds the last range starting at or before the address; without
    the containment check it would happily report the previous network as the
    owner of an address that is not in it."""
    assert asn_mod.lookup(loaded, "9.9.9.9") is None
    assert asn_mod.lookup(loaded, "165.228.1.1") is None


def test_private_space_says_so_instead_of_returning_empty(loaded):
    """RFC1918 is in no public BGP table. "Private address" is a useful answer;
    an empty result the caller has to interpret is not."""
    hit = asn_mod.lookup(loaded, "10.0.0.5")
    assert hit is not None and hit["asn"] is None
    assert "private" in hit["note"].lower()


def test_a_non_ip_is_not_an_error(loaded):
    assert asn_mod.lookup(loaded, "example.com") is None


def test_reload_replaces_rather_than_accumulates(loaded):
    """The upstream file is a complete snapshot. Merging would leave withdrawn
    allocations behind forever, so an IP that changed hands would match two
    owners and the query would return whichever sorted first."""
    before = loaded.execute("SELECT COUNT(*) AS n FROM asn_ranges").fetchone()["n"]
    asn_mod.load_rows(loaded, asn_mod.parse_dataset(FIXTURE))
    loaded.commit()
    after = loaded.execute("SELECT COUNT(*) AS n FROM asn_ranges").fetchone()["n"]
    assert after == before, f"reload duplicated rows: {before} -> {after}"


def test_enrichment_reports_unsynced_rather_than_unowned():
    """Before the table is loaded, an IP must read as "we have not loaded this
    yet" - never as "this address belongs to nobody"."""
    from dashboard_api.enrichment import _enrich_asn
    with get_conn() as conn:
        conn.execute("DELETE FROM asn_ranges")
        conn.execute("DELETE FROM settings WHERE key IN ('asn_last_synced','asn_range_count')")
        conn.commit()
        res = _enrich_asn(conn, "165.227.1.7", "ip")
    assert res["available"] is False
    assert "sync" in res["reason"].lower()


def test_enrichment_summarises_ownership_for_an_analyst(loaded):
    from dashboard_api.enrichment import _enrich_asn
    res = _enrich_asn(loaded, "165.227.1.7", "ip")
    assert res["available"] is True
    assert "AS14061" in res["summary"] and "US" in res["summary"]
    assert res["data"]["asn"] == 14061
    # Ownership is context, not a verdict: hosting on a cheap VPS network is not
    # evidence of anything on its own.
    assert res["verdict"] == "unknown"


def test_enrichment_reads_the_host_out_of_a_url(loaded):
    from dashboard_api.enrichment import _enrich_asn
    res = _enrich_asn(loaded, "http://165.227.1.7/payload.bin", "url")
    assert res["available"] is True and res["data"]["asn"] == 14061


def test_sync_skips_while_the_table_is_fresh(loaded, monkeypatch):
    """The cadence lives in sync() so every caller does not have to implement
    it. A scheduler tick calling this every second must not re-download a 90 MB
    file every second."""
    def explode():
        raise AssertionError("fetched despite a fresh table")
    monkeypatch.setattr(asn_mod, "fetch_dataset", explode)
    res = asn_mod.sync(loaded)
    assert res.get("skipped") == "fresh"


def test_sync_failure_keeps_the_existing_table(loaded, monkeypatch):
    """A stale table still answers lookups; an emptied one answers nothing. A
    failed refresh must never be worse than not refreshing."""
    def explode():
        raise RuntimeError("network is down")
    monkeypatch.setattr(asn_mod, "fetch_dataset", explode)
    # Make it genuinely due, or sync() would skip and the failure path would
    # never be reached - the assertion would pass without testing anything.
    asn_mod._record_sync(loaded, 4, STALE)
    loaded.commit()
    res = asn_mod.sync_if_due()
    assert "error" in res
    assert asn_mod.lookup(loaded, "165.227.1.7")["asn"] == 14061


def test_a_failed_refresh_backs_off_instead_of_retrying_every_tick(monkeypatch):
    """The freshness check only paces the SUCCESS path. With no table at all
    nothing is ever "fresh", so without an attempt-based backoff the scheduler
    would re-attempt a ~90 MB download on every tick for as long as the network
    stayed down."""
    attempts = []

    def explode():
        attempts.append(1)
        raise RuntimeError("network is down")

    monkeypatch.setattr(asn_mod, "fetch_dataset", explode)
    with get_conn() as conn:
        conn.execute("DELETE FROM asn_ranges")
        conn.execute("DELETE FROM settings WHERE key IN "
                     "('asn_last_synced','asn_range_count','asn_last_attempt')")
        conn.commit()
    try:
        for _ in range(5):
            asn_mod.sync_if_due()
        assert len(attempts) == 1, (
            f"a down network caused {len(attempts)} download attempts, not 1")
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key IN "
                         "('asn_last_synced','asn_range_count','asn_last_attempt')")
            conn.commit()


def test_force_overrides_both_the_freshness_check_and_the_backoff(loaded, monkeypatch):
    """An operator pressing "refresh now" must not be told to wait."""
    monkeypatch.setattr(asn_mod, "fetch_dataset", lambda: FIXTURE.encode())
    res = asn_mod.sync(loaded, force=True)
    assert res.get("ranges") == 4 and "skipped" not in res
