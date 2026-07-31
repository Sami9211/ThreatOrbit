"""Pivots: what else does this deployment hold that is part of the same thing?

An indicator an analyst cannot pivot from is a dead end, and 315,185 dead ends
is a list rather than intelligence. These pin the two properties that make a
pivot worth having: it must find the real links, and it must NOT invent any -
a graph padded with coincidental edges is worse than no graph, because an
analyst cannot tell which edges to trust.
"""
import uuid

import pytest

from dashboard_api.db import get_conn, ip_hex_of, registrable_domain
from dashboard_api.ioc_store import insert_ioc
from dashboard_api.relations import related

NOW = "2026-07-29T00:00:00+00:00"


def _ins(conn, value, itype, **kw):
    iid = f"rel-{uuid.uuid4().hex[:10]}"
    # Written through the SAME writer production uses, so the derived columns
    # every pivot indexes on are populated identically. A fixture that fills its
    # own index is testing nothing - it was that exact gap that let `reg_domain`
    # go unwritten by the whole import path while these tests stayed green.
    insert_ioc(conn, id=iid, type=itype, value=value,
               threat_type=kw.get("threat_type", "malicious-activity"),
               confidence=kw.get("confidence", 60),
               severity=kw.get("severity", "medium"),
               source=kw.get("source", "feed-a"), actor=kw.get("actor", ""),
               first_seen=NOW, last_seen=NOW, report_id=kw.get("report_id"),
               intel_score=kw.get("score", 50))
    return iid


@pytest.fixture
def store():
    made = []
    with get_conn() as conn:
        yield conn, made
        if made:
            ph = ",".join("?" * len(made))
            conn.execute(f"DELETE FROM iocs WHERE id IN ({ph})", tuple(made))
            conn.commit()


@pytest.mark.parametrize("host,expected", [
    ("login.mail.example.com", "example.com"),
    ("example.com", "example.com"),
    ("a.b.c.example.co.uk", "example.co.uk"),
    ("example.co.uk", "example.co.uk"),
    ("shop.example.com.au", "example.com.au"),
    ("localhost", None),
    ("", None),
    ("1.2.3.4", None),
    ("trailing.dot.test.", "dot.test"),
])
def test_registrable_domain(host, expected):
    """Getting `co.uk` wrong would make every *.co.uk a "sibling" of every other
    - a fabricated relationship presented as evidence."""
    assert registrable_domain(host) == expected


def test_same_report_is_the_strongest_link(store):
    conn, made = store
    rid = f"rep-{uuid.uuid4().hex[:8]}"
    a = _ins(conn, f"a-{rid}.test", "domain", report_id=rid)
    b = _ins(conn, f"b-{rid}.test", "domain", report_id=rid)
    c = _ins(conn, f"c-{rid}.test", "domain")            # no report
    made += [a, b, c]
    conn.commit()

    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    rep = next((g for g in groups if g["key"] == "report"), None)
    assert rep is not None, [g["key"] for g in groups]
    vals = [i["value"] for i in rep["items"]]
    assert f"b-{rid}.test" in vals
    assert f"c-{rid}.test" not in vals, "an unrelated indicator was reported as related"
    # A pivot the UI can act on, not just a list.
    assert rep["pivot"] == {"kind": "report", "value": rid}


def test_the_indicator_is_never_related_to_itself(store):
    conn, made = store
    rid = f"rep-{uuid.uuid4().hex[:8]}"
    a = _ins(conn, f"self-{rid}.test", "domain", report_id=rid)
    b = _ins(conn, f"other-{rid}.test", "domain", report_id=rid)
    made += [a, b]
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    for g in groups:
        assert all(i["id"] != a for i in g["items"]), f"{g['key']} included the indicator itself"


def test_url_pivots_to_the_domain_that_hosts_it_and_back(store):
    conn, made = store
    tag = uuid.uuid4().hex[:8]
    host = f"payload-{tag}.test"
    dom = _ins(conn, host, "domain")
    url = _ins(conn, f"http://{host}/a.bin", "url")
    url2 = _ins(conn, f"http://{host}/b.bin", "url")
    made += [dom, url, url2]
    conn.commit()

    # From the domain: the URLs served from it.
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (dom,)).fetchone()))
    g = next((x for x in groups if x["key"] == "host"), None)
    assert g is not None and g["total"] == 2
    # From a URL: the domain and its sibling URL.
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (url,)).fetchone()))
    g = next((x for x in groups if x["key"] == "host"), None)
    assert g is not None
    assert host in [i["value"] for i in g["items"]]


def test_sibling_subdomains_are_found_without_matching_a_lookalike(store):
    conn, made = store
    tag = uuid.uuid4().hex[:8]
    reg = f"kit-{tag}.test"
    a = _ins(conn, f"login.{reg}", "domain")
    b = _ins(conn, f"mail.{reg}", "domain")
    # A DIFFERENT registration that merely ENDS with the same text. A LIKE
    # without the dot anchor would report this as a sibling.
    evil = _ins(conn, f"notkit-{tag}.test", "domain")
    made += [a, b, evil]
    conn.commit()

    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    sib = next((g for g in groups if g["key"] == "sibling"), None)
    assert sib is not None, [g["key"] for g in groups]
    vals = [i["value"] for i in sib["items"]]
    assert f"mail.{reg}" in vals
    assert f"notkit-{tag}.test" not in vals, "a lookalike domain was reported as a sibling"


def test_the_exact_host_is_not_repeated_in_the_sibling_group(store):
    """Otherwise the sibling group is just a longer copy of the host group and
    the analyst reads the same rows twice."""
    conn, made = store
    tag = uuid.uuid4().hex[:8]
    reg = f"dup-{tag}.test"
    a = _ins(conn, f"www.{reg}", "domain")
    b = _ins(conn, f"http://www.{reg}/x", "url")
    c = _ins(conn, f"other.{reg}", "domain")
    made += [a, b, c]
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    sib = next((g for g in groups if g["key"] == "sibling"), None)
    assert sib is not None
    assert all((i["value"] or "").lower() != f"www.{reg}" for i in sib["items"])


def test_actor_attribution_pivots(store):
    conn, made = store
    actor = f"APT-{uuid.uuid4().hex[:6]}"
    a = _ins(conn, f"a-{actor}.test", "domain", actor=actor)
    b = _ins(conn, f"b-{actor}.test", "domain", actor=actor)
    made += [a, b]
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    g = next((x for x in groups if x["key"] == "actor"), None)
    assert g is not None and actor in g["label"]


def test_an_empty_actor_does_not_group_every_unattributed_indicator(store):
    """Most of a blocklist has no actor. Grouping on "" would relate hundreds of
    thousands of unrelated values and call it attribution."""
    conn, made = store
    a = _ins(conn, f"noattr-{uuid.uuid4().hex[:8]}.test", "domain", actor="")
    made.append(a)
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    assert all(g["key"] != "actor" for g in groups)


def test_groups_report_the_true_total_even_when_truncated(store):
    conn, made = store
    rid = f"rep-{uuid.uuid4().hex[:8]}"
    ids = [_ins(conn, f"n{n}-{rid}.test", "domain", report_id=rid) for n in range(12)]
    made += ids
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (ids[0],)).fetchone()),
                     limit=3)
    rep = next(g for g in groups if g["key"] == "report")
    assert len(rep["items"]) == 3, "the group ignored its limit"
    assert rep["total"] == 11, f"truncated group misreported its total: {rep['total']}"


def test_items_come_back_best_first(store):
    """A truncated group must show what is worth opening, not whatever was
    inserted first."""
    conn, made = store
    rid = f"rep-{uuid.uuid4().hex[:8]}"
    low = _ins(conn, f"low-{rid}.test", "domain", report_id=rid, score=10)
    high = _ins(conn, f"high-{rid}.test", "domain", report_id=rid, score=95)
    anchor = _ins(conn, f"anchor-{rid}.test", "domain", report_id=rid, score=50)
    made += [low, high, anchor]
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (anchor,)).fetchone()),
                     limit=1)
    rep = next(g for g in groups if g["key"] == "report")
    assert rep["items"][0]["value"] == f"high-{rid}.test"


def test_an_isolated_indicator_gets_no_groups_rather_than_weak_guesses(store):
    conn, made = store
    a = _ins(conn, f"alone-{uuid.uuid4().hex[:10]}.test", "domain")
    made.append(a)
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    # A sibling group would be the only candidate, and there are no siblings.
    assert [g["key"] for g in groups if g["items"]] == []


def test_every_group_explains_the_evidence_for_its_link(store):
    """A graph an analyst cannot interrogate is one they are right to ignore."""
    conn, made = store
    rid = f"rep-{uuid.uuid4().hex[:8]}"
    actor = f"APT-{uuid.uuid4().hex[:6]}"
    host = f"multi-{uuid.uuid4().hex[:8]}.test"
    a = _ins(conn, f"www.{host}", "domain", report_id=rid, actor=actor)
    _ins(conn, f"other.{host}", "domain", report_id=rid, actor=actor)
    made += [r["id"] for r in conn.execute(
        "SELECT id FROM iocs WHERE report_id=?", (rid,)).fetchall()]
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    assert groups, "a well-connected indicator produced no groups"
    for g in groups:
        assert g["why"] and len(g["why"]) > 10, f"{g['key']} has no stated evidence"
        assert "pivot" in g and g["pivot"]["value"]


def test_network_pivot_is_absent_until_the_bgp_table_is_synced(store):
    """An unsynced deployment must get no network group - never an empty-looking
    "AS unknown" one."""
    conn, made = store
    conn.execute("DELETE FROM asn_ranges")
    conn.execute("DELETE FROM settings WHERE key IN ('asn_last_synced','asn_range_count')")
    a = _ins(conn, "165.227.9.9", "ip")
    b = _ins(conn, "165.227.9.10", "ip")
    made += [a, b]
    conn.commit()
    groups = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (a,)).fetchone()))
    assert all(g["key"] != "network" for g in groups)


def test_network_pivot_finds_neighbours_in_the_same_announced_range(store):
    conn, made = store
    from dashboard_api import asn as asn_mod
    conn.execute("DELETE FROM asn_ranges")
    n = asn_mod.load_rows(conn, asn_mod.parse_dataset(
        "165.227.0.0\t165.227.255.255\t14061\tUS\tDIGITALOCEAN-ASN"))
    asn_mod._record_sync(conn, n, NOW)
    near1 = _ins(conn, "165.227.5.5", "ip")
    near2 = _ins(conn, "165.227.200.200", "ip")
    far = _ins(conn, "8.8.4.4", "ip")            # different network entirely
    made += [near1, near2, far]
    conn.commit()
    try:
        groups = related(conn, dict(
            conn.execute("SELECT * FROM iocs WHERE id=?", (near1,)).fetchone()))
        net = next((g for g in groups if g["key"] == "network"), None)
        assert net is not None, [g["key"] for g in groups]
        vals = [i["value"] for i in net["items"]]
        assert "165.227.200.200" in vals
        assert "8.8.4.4" not in vals, "an address outside the range was reported as a neighbour"
        assert "AS14061" in net["label"]
    finally:
        conn.execute("DELETE FROM asn_ranges")
        conn.execute("DELETE FROM settings WHERE key IN ('asn_last_synced','asn_range_count')")
        conn.commit()


def test_ip_hex_matches_the_asn_table_encoding():
    """The network pivot is a BETWEEN across two tables. If the two encodings
    ever diverge, every comparison silently returns nothing."""
    import ipaddress

    from dashboard_api import asn as asn_mod
    for v in ("1.2.3.4", "255.255.255.255", "8.8.8.8"):
        assert ip_hex_of(v, "ip") == asn_mod.hex_key(ipaddress.ip_address(v))
    assert ip_hex_of("2001:4860:4860::8888", "ip") == asn_mod.hex_key(
        ipaddress.ip_address("2001:4860:4860::8888"))
    # Non-IPs get no key rather than a bogus one.
    assert ip_hex_of("example.com", "domain") is None
    assert ip_hex_of("not-an-ip", "ip") is None


@pytest.mark.parametrize("host,expected", [
    # Free-hosting platforms: every subdomain is a DIFFERENT tenant, so the
    # registrable name is the tenant's, not the platform's.
    ("evil.000webhostapp.com", "evil.000webhostapp.com"),
    ("phish.vercel.app", "phish.vercel.app"),
    ("a.b.github.io", "b.github.io"),
    ("x.duckdns.org", "x.duckdns.org"),
    # LONGEST suffix wins: `r.appspot.com` is itself a platform suffix, so
    # testing only the last two labels would match `appspot.com` and resolve
    # this back to the platform.
    ("x.r.appspot.com", "x.r.appspot.com"),
    # ...while an ordinary registration still clusters by its registration.
    ("1623867673.corolain.ru", "corolain.ru"),
    ("deep.sub.corolain.ru", "corolain.ru"),
])
def test_platform_suffixes_do_not_become_one_giant_fake_cluster(host, expected):
    """Measured on the real store: `000webhostapp.com` had 4,912 subdomains and
    `vercel.app` 2,837. Treating those as one registration told an analyst that
    4,911 unrelated people abusing a free host were a single actor's cluster -
    a fabricated relationship, presented as evidence. Meanwhile `corolain.ru`
    (1,940 generated subdomains under ONE registration) is exactly the cluster
    the pivot exists to surface, and must keep working."""
    assert registrable_domain(host) == expected


def test_platform_tenants_get_no_sibling_group_but_dga_clusters_do(store):
    conn, made = store
    tag = uuid.uuid4().hex[:8]
    # Two unrelated tenants on the same free host.
    p1 = _ins(conn, f"victim-{tag}.000webhostapp.com", "domain")
    p2 = _ins(conn, f"other-{tag}.000webhostapp.com", "domain")
    # Two generated names under one real registration.
    d1 = _ins(conn, f"111.dga-{tag}.ru", "domain")
    d2 = _ins(conn, f"222.dga-{tag}.ru", "domain")
    made += [p1, p2, d1, d2]
    conn.commit()

    plat = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (p1,)).fetchone()))
    assert all(g["key"] != "sibling" for g in plat), (
        "unrelated tenants on a free host were reported as one actor's cluster")

    dga = related(conn, dict(conn.execute("SELECT * FROM iocs WHERE id=?", (d1,)).fetchone()))
    sib = next((g for g in dga if g["key"] == "sibling"), None)
    assert sib is not None and f"222.dga-{tag}.ru" in [i["value"] for i in sib["items"]]


# -- Same subnet: the only pivot an IP has without the BGP table ---------------


def _ips(conn, made, *values):
    for v in values:
        made.append(_ins(conn, v, "ip"))
    conn.commit()


def _free_slash24(conn) -> str:
    """A /24 no other test has put an indicator in, as `a.b.c.` ready to append.

    Hard-coding one does not work: the suite seeds addresses across the
    documentation and benchmarking ranges, so a fixed choice passes alone and
    fails in a full run depending on which tests ran first. Emptiness is checked
    rather than assumed."""
    import random

    from dashboard_api.db import ip_hex_of
    for _ in range(50):
        a, b, c = random.randint(11, 126), random.randint(0, 255), random.randint(0, 255)
        prefix = ip_hex_of(f"{a}.{b}.{c}.1", "ip")[:6]
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM iocs WHERE ip_hex BETWEEN ? AND ?",
            (prefix + "00", prefix + "ff")).fetchone()["n"]
        if n == 0:
            return f"{a}.{b}.{c}."
    raise AssertionError("no empty /24 found - the store under test is unusually full")


def test_ip_indicators_pivot_on_their_subnet(store):
    """Measured on the real 327,984-indicator store: 68,457 IP indicators had no
    pivot at all, because the only group that applies to them is `network` and
    that needs the BGP table synced. A deployment that has never reached
    iptoasn - air-gapped, or behind an egress policy - gets nothing.

    `ip_hex` is fixed-width, so "same /24" is a prefix on the existing index."""
    conn, made = store
    net = _free_slash24(conn)
    third = int(net.split(".")[2])
    adjacent = ".".join(net.split(".")[:2] + [str((third + 1) % 256), ""])
    _ips(conn, made, f"{net}7", f"{net}99", f"{net}203",
         f"{adjacent}7")            # neighbouring /24 - deliberately NOT a match
    row = conn.execute("SELECT * FROM iocs WHERE value=?", (f"{net}7",)).fetchone()
    g = next((x for x in related(conn, dict(row)) if x["key"] == "subnet"), None)
    assert g is not None, "an IP with listed neighbours must have somewhere to go"
    assert g["total"] == 2, f"the neighbouring /24 leaked in: {g['total']}"
    assert f"{net}0/24" in g["label"]
    assert {i["value"] for i in g["items"]} == {f"{net}99", f"{net}203"}


def test_a_lone_address_gets_no_subnet_group(store):
    """The rule the whole module runs on: no link is an answer. A group holding
    only the indicator you are already looking at is padding."""
    conn, made = store
    net = _free_slash24(conn)
    _ips(conn, made, f"{net}42")
    row = conn.execute("SELECT * FROM iocs WHERE value=?", (f"{net}42",)).fetchone()
    assert "subnet" not in [x["key"] for x in related(conn, dict(row))]


def test_a_dense_block_says_so(store):
    """The finding is not "here are four more addresses", it is "most of this
    subnet is listed" - a different remediation. An analyst blocks the /24
    rather than chasing hosts."""
    conn, made = store
    net = _free_slash24(conn)
    _ips(conn, made, *[f"{net}{n}" for n in range(1, 40)])
    row = conn.execute("SELECT * FROM iocs WHERE value=?", (f"{net}1",)).fetchone()
    g = next(x for x in related(conn, dict(row)) if x["key"] == "subnet")
    assert "of 256 addresses in it are listed" in g["why"], g["why"]
    assert g["total"] == 38


def test_the_subnet_group_states_that_it_is_weaker_evidence(store):
    """Adjacency in cloud space means unrelated tenants. The group is worth
    showing because both ends are already known-bad - but an analyst has to see
    which edges to trust, so it says so rather than presenting itself alongside
    a shared-AS link as equal evidence."""
    conn, made = store
    net = _free_slash24(conn)
    _ips(conn, made, f"{net}10", f"{net}11")
    row = conn.execute("SELECT * FROM iocs WHERE value=?", (f"{net}10",)).fetchone()
    g = next(x for x in related(conn, dict(row)) if x["key"] == "subnet")
    assert "weaker evidence" in g["why"]


def test_domains_get_no_subnet_group(store):
    conn, made = store
    made.append(_ins(conn, f"sub-{uuid.uuid4().hex[:8]}.test", "domain"))
    conn.commit()
    row = conn.execute("SELECT * FROM iocs WHERE id=?", (made[-1],)).fetchone()
    assert "subnet" not in [x["key"] for x in related(conn, dict(row))]
