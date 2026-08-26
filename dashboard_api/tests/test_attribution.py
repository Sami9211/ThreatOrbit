"""Attribution: an indicator with a name, not just a verdict.

Measured on a live store of 322,421 indicators drawn from the nine public feeds
this deployment can actually reach: **0% carried a malware family, 0% an actor,
0% a report.** That is not a code gap - those nine are bulk blocklists, and a
blocklist publishes a value and the claim that it is bad. It is also exactly the
complaint that a public CTI library holds more than this engine imports. It
does, if all the engine imports is values.

Maltrail publishes its static trails one file PER FAMILY, so the file an entry
sits in IS its attribution, from the source. These tests hold the three things
that has to get right:

  * the family is recorded as a family, and never as an actor - AsyncRAT is sold
    to whoever pays and Cobalt Strike is licensed software, so a family is a fact
    the source published and an operator is an assessment somebody must defend;
  * thirty-five files from one project count as ONE source, because corroboration
    counts independent sources and this store has already been burned once by
    counting the same opinion repeatedly;
  * a value already in the store gains its family when a trail names it, or the
    whole exercise is lost on any deployment that already holds the value.
"""
import uuid

import pytest

from dashboard_api import connectors as conn_mod
from dashboard_api.db import get_conn
from dashboard_api.ioc_store import COLUMNS, ioc_row


@pytest.fixture(autouse=True)
def _no_residue():
    with get_conn() as conn:
        before = {r["id"] for r in conn.execute("SELECT id FROM iocs").fetchall()}
    yield
    with get_conn() as conn:
        for r in conn.execute("SELECT id FROM iocs").fetchall():
            if r["id"] not in before:
                conn.execute("DELETE FROM iocs WHERE id=?", (r["id"],))
        conn.commit()


def _row(**kw):
    return dict(zip(COLUMNS, ioc_row(**kw)))


# -- family and actor are different things -----------------------------------------

def test_the_store_records_a_family_as_a_family():
    r = _row(type="domain", value="c2.example.test", malware_family="Emotet")
    assert r["malware_family"] == "emotet", "normalised, so Emotet and emotet are one family"
    assert r["actor"] == "", "a family is not an adversary"


def test_a_family_trail_never_names_an_actor(monkeypatch):
    """Every RAT, stealer and loader in the catalogue is commodity - sold, leaked
    or cracked - and Cobalt Strike is commercial software. Deriving an operator
    from the family alone would be invention, so the trails never try."""
    class _R:
        def __init__(self, text):
            self.text = text
            self.not_modified = False
            self.headers = {}

    def fake(url, headers=None, **kw):
        if "/malware/" not in url:
            raise ValueError("not part of this test")
        return _R("evil-c2.example.test\n198.51.100.44\n")

    monkeypatch.setattr(conn_mod, "_http_get", fake)
    out = conn_mod._fetch_bulk_osint({})
    attributed = [o for o in out if o.get("malware_family")]
    assert attributed, "the family trails produced nothing"
    assert all(not o.get("actor") for o in attributed), \
        "a malware family was written into the attribution column"
    families = {o["malware_family"] for o in attributed}
    assert "cobaltstrike" in families, "the clearest family/actor separation case is missing"
    # And the family reaches the analyst as a tag too, so a text search finds it.
    one = next(o for o in attributed if o["malware_family"] == "cobaltstrike")
    assert "malware:cobaltstrike" in one["tags"]
    assert one["source"] == conn_mod._bulk_source_id(conn_mod._MALTRAIL_SOURCE)


def test_threatfox_malware_name_is_a_family_not_an_actor(monkeypatch):
    """The same conflation, in the path that had it first: ThreatFox publishes a
    malware family per IOC, and it was being stored as the adversary."""
    class _R:
        def __init__(self, text):
            self.text = text
            self.not_modified = False
            self.headers = {}

    def fake(url, headers=None, **kw):
        if "threatfox" in url:
            return _R('"2026","1","203.0.113.9:443","ip:port","botnet_cc","x","y","Emotet"\n')
        raise ValueError("only ThreatFox in this test")

    monkeypatch.setattr(conn_mod, "_http_get", fake)
    out = conn_mod._fetch_bulk_osint({})
    hit = next(o for o in out if o["value"] == "203.0.113.9")
    assert hit["malware_family"] == "Emotet"
    assert hit["actor"] == ""


# -- one project is one source -----------------------------------------------------

def test_the_family_trails_are_one_source_not_thirty_five():
    ids = {conn_mod._bulk_source_id(conn_mod._MALTRAIL_SOURCE)}
    assert len(conn_mod.family_feeds()) > 20, "the catalogue should be many families"
    assert len(ids) == 1
    assert ids <= conn_mod.bulk_feed_source_ids(), \
        "the family source must count toward feed coverage"


def test_every_family_url_is_distinct_and_https():
    seen = set()
    for family, url, role, threat in conn_mod.family_feeds():
        assert url.startswith("https://"), f"{family} must be fetched over TLS"
        assert url not in seen, f"{family} duplicates another family's URL"
        seen.add(url)
        assert family == family.lower().strip(), f"{family} is not normalised"
        assert role, f"{family} has no stated role"
        assert threat, f"{family} has no threat_type"


def test_the_retired_aggregate_is_gone():
    """It was the same project's convenience file, with no attribution on any
    entry. Keeping both would have made one source look like two."""
    urls = [f[1] for f in conn_mod._BULK_FEEDS]
    assert not any("maltrail-malware-domains" in u for u in urls)
    assert not any("Maltrail malware domains" == f[0] for f in conn_mod._BULK_FEEDS)


# -- a value we already hold gains its family --------------------------------------

def test_a_value_already_in_the_store_gains_its_family():
    """Without this the trails are wasted on any store that already holds the
    value: `_import` inserts new rows and counts the rest as duplicates, so the
    50,192 Maltrail domains imported before attribution existed would have stayed
    bare for ever."""
    value = f"already-held-{uuid.uuid4().hex[:8]}.example.test"
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        insert_ioc(conn, type="domain", value=value, source="osint:some blocklist")
        conn.commit()

    res = conn_mod._import(
        [{"type": "domain", "value": value, "malware_family": "qakbot",
          "confidence": 72, "source": conn_mod._bulk_source_id(conn_mod._MALTRAIL_SOURCE)}],
        "Maltrail malware trails")
    assert res["imported"] == 0 and res["duplicates"] == 1, res
    assert res["attributed"] == 1, "the family was thrown away"

    with get_conn() as conn:
        row = conn.execute("SELECT malware_family FROM iocs WHERE value=?", (value,)).fetchone()
    assert row["malware_family"] == "qakbot"


def test_an_existing_family_is_never_overwritten():
    """Only a blank is filled. One source's family must not be able to relabel
    another's - that is a disagreement to surface, not to silently resolve."""
    value = f"already-named-{uuid.uuid4().hex[:8]}.example.test"
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        insert_ioc(conn, type="domain", value=value, source="osint:a", malware_family="emotet")
        conn.commit()

    res = conn_mod._import(
        [{"type": "domain", "value": value, "malware_family": "trickbot", "confidence": 72,
          "source": conn_mod._bulk_source_id(conn_mod._MALTRAIL_SOURCE)}],
        "Maltrail malware trails")
    assert res["attributed"] == 0
    with get_conn() as conn:
        row = conn.execute("SELECT malware_family FROM iocs WHERE value=?", (value,)).fetchone()
    assert row["malware_family"] == "emotet"


# -- what an analyst gets out of it ------------------------------------------------

def test_a_family_is_a_pivot():
    """One indicator becomes a piece of named infrastructure."""
    from dashboard_api.relations import related
    fam = f"pytestfam{uuid.uuid4().hex[:6]}"
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        rows = [insert_ioc(conn, type="domain", value=f"{fam}-{i}.example.test",
                           source="osint:trails", malware_family=fam) for i in range(4)]
        conn.commit()
        ioc = conn.execute("SELECT * FROM iocs WHERE id=?",
                           (rows[0][COLUMNS.index("id")],)).fetchone()
        groups = related(conn, dict(ioc))
    g = next((x for x in groups if x["key"] == "malware"), None)
    assert g is not None, f"no malware pivot: {[x['key'] for x in groups]}"
    assert g["total"] == 3
    assert g["pivot"] == {"kind": "malware", "value": fam}
    # The count is the finding, so it has to be in the sentence.
    assert "4" in g["why"] and fam in g["why"]


def test_the_store_reports_how_much_it_can_name(client, auth):
    fam = f"pytestfam{uuid.uuid4().hex[:6]}"
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        for i in range(3):
            insert_ioc(conn, type="domain", value=f"{fam}-sum-{i}.example.test",
                       source="osint:trails", malware_family=fam)
        conn.commit()
    body = client.get("/cti/store-summary", headers=auth).json()
    assert body["attributedToFamily"] >= 3
    assert isinstance(body["attributedShare"], float)
    assert any(f["family"] == fam for f in body["families"]), body["families"][:5]


def test_the_list_filters_by_family(client, auth):
    fam = f"pytestfam{uuid.uuid4().hex[:6]}"
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        for i in range(3):
            insert_ioc(conn, type="domain", value=f"{fam}-list-{i}.example.test",
                       source="osint:trails", malware_family=fam)
        insert_ioc(conn, type="domain", value=f"{fam}-other.example.test",
                   source="osint:trails")
        conn.commit()
    body = client.get(f"/cti/iocs?family={fam.upper()}&limit=50", headers=auth).json()
    assert body["total"] == 3, "case must not decide whether a family matches"
    # The API answers in snake_case; the browser client camelises.
    assert all(i["malware_family"] == fam for i in body["items"])


def test_a_named_family_leads_somewhere_that_uses_the_name():
    """Naming a family is only worth doing if the name is a route into
    something. The chip opens the family's page (what IS this, and can anyone
    honestly say who runs it), and that page offers the filtered library. A link
    the destination ignores is the same dead end a bell roll-up would have been
    without ?severity=."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2] / "frontend"
    panel = (root / "components/dashboard/StoreCompositionPanel.tsx").read_text()
    assert "/dashboard/cti/malware/" in panel, "the family chips link nowhere"
    entity = (root / "app/dashboard/cti/malware/[family]/page.tsx").read_text()
    assert "/dashboard/feeds?family=" in entity, \
        "the family page must offer the indicators it is counting"
    library = (root / "app/dashboard/feeds/page.tsx").read_text()
    assert "get('family')" in library, "the library must honour ?family="
    assert "{ family }" in library, "the parameter must reach the API query"


# -- a value with a port on it is not a new value ----------------------------------

@pytest.mark.parametrize("raw,expected", [
    # The form the family trails actually publish, and the reason this exists.
    ("66.210.228.178:443", "66.210.228.178"),
    ("66.210.228.178:80", "66.210.228.178"),
    ("bad.example.test:8080", "bad.example.test"),
    # Nothing to do.
    ("66.210.228.178", "66.210.228.178"),
    ("bad.example.test", "bad.example.test"),
    ("198.51.100.0/24", "198.51.100.0/24"),
    # A URL's colon belongs to the scheme (and to its own port).
    ("http://bad.example.test:8080/x", "http://bad.example.test:8080/x"),
    # IPv6 IS colons. Two or more of them means the colons are the address.
    ("2001:db8::1", "2001:db8::1"),
    ("[2001:db8::1]:443", "[2001:db8::1]:443"),
    # One colon, but what follows is not a port.
    ("host:notaport", "host:notaport"),
    # An address with two ports on it. Three of these are in the Cobalt Strike
    # trail, and they are why the rule cannot simply be "exactly one colon".
    ("139.9.234.13:33:1099", "139.9.234.13"),
    ("54.246.146.207:22:50050", "54.246.146.207"),
    # A full IPv6 address has as many colons, and none of them are ports.
    ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6"),
    ("::1", "::1"),
])
def test_a_port_is_not_part_of_the_indicator(raw, expected):
    assert conn_mod.strip_port(raw) == expected


def test_an_address_on_three_ports_is_one_indicator():
    """Stored verbatim, `1.2.3.4:443` is not an IP address: no ip_hex, so no
    subnet or BGP pivot, and - the part that matters - it can never equal the
    src_ip or dest_ip of an event, so threat-intel matching is structurally
    unable to fire on it. It also stored the same host three times."""
    addr = f"203.0.113.{uuid.uuid4().int % 200 + 20}"
    res = conn_mod._import(
        [{"value": f"{addr}:443", "malware_family": "emotet", "confidence": 72},
         {"value": f"{addr}:80", "malware_family": "emotet", "confidence": 72},
         {"value": f"{addr}:8080", "malware_family": "emotet", "confidence": 72}],
        "Maltrail malware trails")
    assert res["imported"] == 1, f"three ports on one host is one indicator: {res}"
    assert res["duplicates"] == 2
    with get_conn() as conn:
        row = conn.execute("SELECT type, value, ip_hex FROM iocs WHERE value=?", (addr,)).fetchone()
    assert row is not None, "the address was stored with its port still attached"
    assert row["type"] == "ip"
    assert row["ip_hex"], "no network key - the subnet and BGP pivots cannot work"


def test_no_import_path_can_store_a_port_on_an_ip():
    """The guard lives in `_import`, which every connector import funnels
    through, so a JSON, CSV or STIX feed publishing host:port is covered too."""
    res = conn_mod._import(
        [{"type": "ip", "value": "203.0.113.251:31337", "confidence": 60}],
        "some other feed")
    assert res["imported"] == 1
    with get_conn() as conn:
        assert conn.execute("SELECT 1 FROM iocs WHERE value='203.0.113.251:31337'").fetchone() is None
        assert conn.execute("SELECT 1 FROM iocs WHERE value='203.0.113.251'").fetchone() is not None


def test_the_brief_stops_claiming_there_is_no_attribution(client, auth):
    """The Normal-mode brief told analysts that blocklists come with no
    attribution at all. That was true when it was written and stopped being true
    the day the family trails landed - and telling someone there is nothing to
    work with when a third of the store is named is worse than saying nothing."""
    import pathlib
    fam = f"pytestfam{uuid.uuid4().hex[:6]}"
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        insert_ioc(conn, type="domain", value=f"{fam}-brief.example.test",
                   source="osint:trails", malware_family=fam)
        conn.commit()
    body = client.get("/cti/summary", headers=auth).json()
    assert body["attributedToFamily"] >= 1
    assert any(f["family"] == fam for f in body["topFamilies"]) or body["topFamilies"]

    page = (pathlib.Path(__file__).resolve().parents[2]
            / "frontend/app/dashboard/cti/page.tsx").read_text()
    assert "without\n                attributing them" not in page
    assert "attributedToFamily" in page, "the brief must read the figure it now has"
