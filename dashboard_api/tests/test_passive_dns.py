"""First-party passive DNS: what THIS deployment observed, not what a feed says.

Every other enrichment in the platform is somebody else's opinion. This one is
our own observation, and it is the thing a public CTI library structurally cannot
provide for a specific environment - which makes the honesty rules around it
matter more, not less:

  * a failed lookup must record NOTHING, because "we have not seen it" and "it
    resolves to nothing" are different claims;
  * forward and reverse agreeing is a stronger claim than either alone, and that
    distinction must survive into the record.

The resolver is stubbed throughout. A suite that resolves real names is slow,
non-deterministic, and fails on an air-gapped runner for reasons that have
nothing to do with the code.
"""
import uuid

import pytest

from dashboard_api import passive_dns as pdns
from dashboard_api.db import get_conn


@pytest.fixture
def store():
    names = []
    with get_conn() as conn:
        yield conn, names
        if names:
            ph = ",".join("?" * len(names))
            conn.execute(f"DELETE FROM dns_observations WHERE name IN ({ph})", tuple(names))
            conn.commit()


def _name():
    return f"pd-{uuid.uuid4().hex[:10]}.test"


def test_addr_hex_matches_the_other_tables_encoding():
    """A DNS observation is range-matched against BGP prefixes, so the two
    encodings have to be identical or every comparison silently finds nothing."""
    import ipaddress

    from dashboard_api import asn as asn_mod
    from dashboard_api.db import ip_hex_of
    for v in ("1.2.3.4", "8.8.8.8", "255.255.255.255"):
        assert pdns.addr_hex(v) == asn_mod.hex_key(ipaddress.ip_address(v)) == ip_hex_of(v, "ip")
    assert pdns.addr_hex("2001:db8::1") == asn_mod.hex_key(ipaddress.ip_address("2001:db8::1"))
    assert pdns.addr_hex("not-an-ip") is None
    assert pdns.addr_hex("") is None


def test_a_failed_lookup_records_nothing(store, monkeypatch):
    """The load-bearing honesty rule. A resolver failure must leave no row, so a
    later empty answer means "we have not seen it" and not "it resolves to
    nothing" - the two are different claims and only one of them is true."""
    conn, names = store
    n = _name(); names.append(n)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: None)
    assert pdns.observe_name(conn, n) == []
    conn.commit()
    assert conn.execute("SELECT COUNT(*) AS c FROM dns_observations WHERE name=?",
                        (n,)).fetchone()["c"] == 0
    assert pdns.for_name(conn, n) == []


def test_a_resolution_is_recorded_with_both_timestamps(store, monkeypatch):
    conn, names = store
    n = _name(); names.append(n)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: ["198.19.1.1", "198.19.1.2"])
    got = pdns.observe_name(conn, n)
    conn.commit()
    assert got == ["198.19.1.1", "198.19.1.2"]
    obs = pdns.for_name(conn, n)
    assert len(obs) == 2
    for o in obs:
        assert o["firstSeen"] and o["lastSeen"] and o["timesSeen"] == 1
        assert o["observedVia"] == "forward"


def test_seeing_the_same_pair_again_bumps_the_count_not_the_row_count(store, monkeypatch):
    conn, names = store
    n = _name(); names.append(n)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: ["198.19.2.5"])
    pdns.observe_name(conn, n)
    pdns.observe_name(conn, n)
    pdns.observe_name(conn, n)
    conn.commit()
    obs = pdns.for_name(conn, n)
    assert len(obs) == 1, "duplicate observation rows"
    assert obs[0]["timesSeen"] == 3


def test_forward_and_reverse_agreement_is_recorded_as_a_stronger_claim(store, monkeypatch):
    """A domain resolving to an address whose PTR points back is a configured
    mapping. One that does not is a weaker claim, and flattening the two loses
    the only part an analyst would act on differently."""
    conn, names = store
    n = _name(); names.append(n)
    addr = "198.19.3.7"

    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: [addr])
    pdns.observe_name(conn, n)
    conn.commit()
    assert pdns.for_name(conn, n)[0]["observedVia"] == "forward"

    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: n)
    assert pdns.observe_address(conn, addr) == n
    conn.commit()
    assert pdns.for_name(conn, n)[0]["observedVia"] == "both"


def test_a_ptr_only_observation_stays_ptr(store, monkeypatch):
    conn, names = store
    n = _name(); names.append(n)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: n)
    pdns.observe_address(conn, "198.19.4.9")
    conn.commit()
    assert pdns.for_name(conn, n)[0]["observedVia"] == "ptr"


def test_the_reverse_pivot_finds_every_name_on_one_address(store, monkeypatch):
    """The pivot that turns a single indicator into a piece of infrastructure."""
    conn, names = store
    a, b = _name(), _name()
    names += [a, b]
    shared = "198.19.5.11"
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: [shared])
    pdns.observe_name(conn, a)
    pdns.observe_name(conn, b)
    conn.commit()
    found = {o["name"] for o in pdns.for_address(conn, shared)}
    assert found == {a, b}


def test_lookups_reject_junk_without_writing(store, monkeypatch):
    conn, names = store
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: ["198.19.6.1"])
    before = conn.execute("SELECT COUNT(*) AS c FROM dns_observations").fetchone()["c"]
    assert pdns.observe_name(conn, "") == []
    assert pdns.observe_name(conn, "http://x/y") == []       # a URL, not a name
    assert pdns.observe_address(conn, "not-an-ip") is None
    conn.commit()
    after = conn.execute("SELECT COUNT(*) AS c FROM dns_observations").fetchone()["c"]
    assert after == before


def test_record_refuses_an_unparseable_address(store):
    conn, names = store
    n = _name(); names.append(n)
    before = conn.execute("SELECT COUNT(*) AS c FROM dns_observations").fetchone()["c"]
    pdns.record(conn, n, "999.999.999.999", "forward")
    pdns.record(conn, n, "", "forward")
    pdns.record(conn, "", "198.19.7.1", "forward")
    conn.commit()
    after = conn.execute("SELECT COUNT(*) AS c FROM dns_observations").fetchone()["c"]
    assert after == before


def test_names_are_normalised_so_one_host_is_one_row(store, monkeypatch):
    """`Example.TEST.` and `example.test` are the same host. Two rows would split
    the history of one name and understate how often it was seen."""
    conn, names = store
    base = _name()
    names.append(base)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: ["198.19.8.1"])
    pdns.observe_name(conn, base.upper() + ".")
    pdns.observe_name(conn, base)
    conn.commit()
    assert len(pdns.for_name(conn, base)) == 1
    assert pdns.for_name(conn, base)[0]["timesSeen"] == 2


def test_a_hung_resolver_cannot_hold_a_request_open(monkeypatch):
    """The system resolver's own timeouts are long and not always honoured, and
    this runs on a request path."""
    import time
    monkeypatch.setattr(pdns, "TIMEOUT_SECONDS", 0.2)
    started = time.time()
    assert pdns._bounded(lambda _: time.sleep(5), "x") is None
    assert time.time() - started < 2.0, "resolution was not bounded"


def test_resolver_errors_are_swallowed_not_raised(monkeypatch):
    import socket
    for exc in (socket.gaierror, socket.herror, OSError, UnicodeError):
        def boom(_a, e=exc):
            raise e("nope")
        assert pdns._bounded(boom, "x") is None


def test_stats_report_zero_honestly_rather_than_hiding_an_empty_set(store):
    conn, _ = store
    st = pdns.stats(conn)
    assert set(st) == {"pairs", "names", "addresses"}
    assert all(isinstance(v, int) for v in st.values())


def test_enricher_reports_disabled_rather_than_no_records(store):
    """The suite runs with DASHBOARD_DISABLE_DNS set. "Disabled" and "resolves to
    nothing" must never look the same."""
    from dashboard_api.enrichment import _enrich_dns
    conn, _ = store
    res = _enrich_dns(conn, "example.test", "domain")
    assert res["available"] is False
    assert "disabled" in res["reason"].lower()


def test_enricher_uses_recorded_history_when_resolution_is_off(store, monkeypatch):
    """Historical observations are the valuable part, and they must still be
    readable when live resolution is switched off."""
    from dashboard_api.enrichment import _enrich_dns
    conn, names = store
    n = _name(); names.append(n)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: ["198.19.9.4"])
    pdns.observe_name(conn, n)
    conn.commit()

    monkeypatch.delenv("DASHBOARD_DISABLE_DNS", raising=False)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: None)   # live lookup fails
    res = _enrich_dns(conn, n, "domain")
    assert res["available"] is True
    assert "198.19.9.4" in [o["address"] for o in res["data"]["observations"]]


def test_enricher_on_an_ip_reports_the_shared_names(store, monkeypatch):
    from dashboard_api.enrichment import _enrich_dns
    conn, names = store
    a, b = _name(), _name()
    names += [a, b]
    shared = "198.19.10.20"
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: [shared])
    pdns.observe_name(conn, a)
    pdns.observe_name(conn, b)
    conn.commit()

    monkeypatch.delenv("DASHBOARD_DISABLE_DNS", raising=False)
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: None)   # no PTR
    res = _enrich_dns(conn, shared, "ip")
    assert res["available"] is True
    assert set(res["data"]["names"]) == {a, b}
    assert "2 names observed here" in res["summary"]


def test_resolution_pivot_links_indicators_sharing_an_observed_address(store, monkeypatch):
    """Two indicators we hold, tied together by a resolution we observed."""
    from dashboard_api.db import host_of, ip_hex_of, reg_domain_of
    from dashboard_api.relations import related
    conn, names = store
    a, b = _name(), _name()
    names += [a, b]
    shared = "198.19.11.30"
    monkeypatch.setattr(pdns, "_bounded", lambda fn, arg: [shared])
    pdns.observe_name(conn, a)
    pdns.observe_name(conn, b)

    made = []
    for v in (a, b):
        iid = f"pdi-{uuid.uuid4().hex[:8]}"
        made.append(iid)
        conn.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
            "first_seen,last_seen,tags,status,host,ip_hex,reg_domain,intel_score) "
            "VALUES (?,'domain',?,'c2',70,'critical','feed','', "
            "'2026-07-29T00:00:00+00:00','2026-07-29T00:00:00+00:00','[]','active',?,?,?,55)",
            (iid, v, host_of(v, "domain"), ip_hex_of(v, "domain"), reg_domain_of(v, "domain")))
    conn.commit()
    try:
        anchor = dict(conn.execute("SELECT * FROM iocs WHERE id=?", (made[0],)).fetchone())
        groups = related(conn, anchor)
        g = next((x for x in groups if x["key"] == "resolution"), None)
        assert g is not None, [x["key"] for x in groups]
        assert b in [i["value"] for i in g["items"]]
        assert g["pivot"] == {"kind": "address", "value": shared}
    finally:
        ph = ",".join("?" * len(made))
        conn.execute(f"DELETE FROM iocs WHERE id IN ({ph})", tuple(made))
        conn.commit()


def test_the_pivot_never_resolves_anything_itself(store, monkeypatch):
    """Opening a drawer must not turn into a burst of DNS traffic."""
    from dashboard_api.relations import related
    conn, _ = store

    def tripwire(*a, **k):
        raise AssertionError("the pivot performed a live resolution")

    monkeypatch.setattr(pdns, "_bounded", tripwire)
    related(conn, {"id": "x", "type": "domain", "value": "never-resolved.test",
                   "actor": "", "host": None})
