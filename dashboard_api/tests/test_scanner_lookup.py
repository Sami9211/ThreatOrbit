"""IntelScope lookup + enrichment - no fabricated maliciousness.

The old lookup fell back to a blind substring match (`LIKE %query%`): scanning
`linkedin.com` matched a phishing URL hosted elsewhere that merely EMBEDS the
string (e.g. https://evil.example/linkedin.com/login) and branded the
legitimate domain malicious. Matching is now delimiter-bounded, and unknown
values report "unverified" - absence from our TI proves nothing, in neither
direction.
"""
import uuid

from dashboard_api.db import get_conn, host_of
from dashboard_api.tenancy import DEFAULT_ORG_ID


def _put_ioc(value, ioc_type="url", severity="critical", confidence=95):
    # Built through the SAME writer production uses, so these rows carry exactly
    # the derived columns a real row does. A helper with its own INSERT makes the
    # lookup tests pass against rows that could not exist in a live store, hiding
    # the breakage they exist to catch - which is how `reg_domain` stayed NULL on
    # every import for as long as it did.
    from datetime import datetime, timedelta, timezone

    from dashboard_api.ioc_store import insert_ioc
    # Dated RELATIVE to now, and that is the whole point. These used to be
    # `first_seen 2026-01-01, last_seen 2026-07-01`, which was fine on the day
    # they were written and became a time bomb: a URL decays on a 21-day
    # half-life and is revoked below score 15, so on 2026-08-27 - fifty-seven
    # days after that fixed last_seen, and with nothing in the code changed -
    # the lookup started answering "expired" instead of "malicious" and the
    # suite went red for calendar reasons. A test that fails on a date nobody
    # can point at is a test people learn to ignore.
    #
    # These tests are about MATCHING, not decay, so the row is freshly asserted.
    # Decay has its own tests, which set the age deliberately.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with get_conn() as conn:
        insert_ioc(conn, type=ioc_type, value=value, threat_type="Phishing",
                   confidence=confidence, severity=severity, source="pytest-feed",
                   first_seen=(now - timedelta(days=180)).isoformat(),
                   last_seen=now.isoformat(),
                   org_id=DEFAULT_ORG_ID)
        conn.commit()


def _cleanup(*values):
    with get_conn() as conn:
        for v in values:
            conn.execute("DELETE FROM iocs WHERE value=?", (v,))
        conn.commit()


def test_embedded_string_cannot_brand_a_legit_domain(client, auth):
    """The LinkedIn regression: an IOC that merely CONTAINS the query string
    must not match it."""
    bad = "https://evil.example/linkedin.com/login"
    _put_ioc(bad)
    try:
        for q in ("linkedin.com", "https://www.linkedin.com/in/someone"):
            r = client.get(f"/cti/lookup?value={q}", headers=auth).json()
            assert r["found"] is False, f"{q} falsely matched {bad}"
            assert r["verdict"] == "unverified"
    finally:
        _cleanup(bad)


def test_domain_query_matches_urls_hosted_on_it(client, auth):
    """The legitimate direction still works: URL indicators hosted ON the
    queried domain (host position, delimiter-bounded)."""
    bad = "https://evil.example/pay/confirm"
    _put_ioc(bad)
    try:
        r = client.get("/cti/lookup?value=evil.example", headers=auth).json()
        assert r["found"] is True and r["verdict"] == "malicious"
        assert r["source"] == "pytest-feed"
    finally:
        _cleanup(bad)


def test_url_query_matches_its_known_bad_host(client, auth):
    bad_domain = "bad-domain.example"
    _put_ioc(bad_domain, ioc_type="domain")
    try:
        r = client.get(f"/cti/lookup?value=http://{bad_domain}/anything", headers=auth).json()
        assert r["found"] is True and r["verdict"] == "malicious"
    finally:
        _cleanup(bad_domain)


def test_unknown_value_is_unverified_not_clean(client, auth):
    r = client.get("/cti/lookup?value=totally-unknown-value.example", headers=auth).json()
    assert r["found"] is False
    assert r["verdict"] == "unverified"


def test_scan_enrich_by_value(client, auth):
    """The scanner's provider panel: builtin providers run, external ones
    report honest availability instead of fabricated verdicts."""
    r = client.get("/cti/scan/enrich?value=203.0.113.99&type=ip", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    providers = {p["provider"]: p for p in body["providers"]}
    assert "internal" in providers and providers["internal"]["available"] is True
    # No keys configured in tests → external providers must say so, not invent.
    for ext in ("otx", "virustotal"):
        if ext in providers:
            assert providers[ext]["available"] is False


def test_scan_history_accepts_unverified(client, auth):
    r = client.post("/cti/scans", headers=auth, json={
        "target": "https://www.linkedin.com/in/someone", "type": "url",
        "verdict": "unverified", "score": 0, "engines": "0/4"})
    assert r.status_code == 201, r.text
    assert r.json()["verdict"] == "unverified"


# -- /cti/scan/context: relations come from real stored records ------------------

def test_scan_context_surfaces_real_relations(client, auth):
    """Alerts, sibling IOCs and prior analyst scans around a known indicator
    all come back with real record ids (deep-linkable), plus the co-observed
    entities from those alerts."""
    ip = "198.51.100.77"
    sibling = "https://198.51.100.77/payload"
    _put_ioc(ip, ioc_type="ip")
    _put_ioc(sibling, ioc_type="url", severity="high", confidence=80)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,src_ip,dest_ip,username,hostname) "
            "VALUES ('AL-CTX-1','2026-07-01T10:00:00','C2 beacon','high','new',?,"
            "'10.0.0.9','svc-web','web-01')", (ip,))
        conn.execute(
            "INSERT INTO scans (id,ts,target,type,verdict,score) "
            "VALUES ('SC-CTX-1','2026-07-01T11:00:00',?,'ip','malicious',0.9)", (ip,))
        conn.commit()
    try:
        r = client.get(f"/cti/scan/context?value={ip}", headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["indicator"] is not None and body["indicator"]["value"] == ip
        assert any(i["value"] == sibling for i in body["relatedIocs"])
        assert body["alerts"]["total"] == 1
        assert body["alerts"]["items"][0]["id"] == "AL-CTX-1"
        rel = body["relatedEntities"]
        assert "10.0.0.9" in rel["ips"] and "svc-web" in rel["usernames"]
        assert "web-01" in rel["hostnames"]
        assert body["analystActivity"]["scans"] >= 1
        assert body["analystActivity"]["byVerdict"].get("malicious", 0) >= 1
    finally:
        _cleanup(ip, sibling)
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE id='AL-CTX-1'")
            conn.execute("DELETE FROM scans WHERE id='SC-CTX-1'")
            conn.commit()


def test_scan_context_unknown_value_is_empty_not_invented(client, auth):
    r = client.get("/cti/scan/context?value=never-seen.example", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["indicator"] is None
    assert body["relatedIocs"] == [] and body["cases"] == [] and body["assets"] == []
    assert body["alerts"]["total"] == 0 and body["darkWeb"]["total"] == 0
    assert body["analystActivity"]["scans"] == 0


# -- RDAP enricher: real registry data, parsed - never fabricated ----------------

class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.headers = {}

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_rdap_disabled_reports_honestly(client, auth):
    """With DASHBOARD_DISABLE_RDAP set (as in this suite), the provider says
    'disabled' - it never silently fabricates registry data."""
    r = client.get("/cti/scan/enrich?value=weird-new-domain.example&type=domain",
                   headers=auth).json()
    rdap = next(p for p in r["providers"] if p["provider"] == "rdap")
    assert rdap["available"] is False
    assert "disabled" in rdap["reason"]


def test_rdap_parses_domain_registration(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from dashboard_api import enrichment
    monkeypatch.delenv("DASHBOARD_DISABLE_RDAP", raising=False)
    young = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    payload = {
        "handle": "EXAMPLE-TEST",
        "events": [{"eventAction": "registration", "eventDate": young},
                   {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                               ["fn", {}, "text", "NameCheap, Inc."]]]}],
        "status": ["client transfer prohibited"],
        "nameservers": [{"ldhName": "dns1.example.net"}, {"ldhName": "dns2.example.net"}],
    }
    monkeypatch.setattr(enrichment, "_rdap_get", lambda url: _FakeResp(payload))
    res = enrichment._enrich_rdap(None, "weird-new-domain.example", "domain")
    assert res["available"] is True
    assert res["data"]["registrar"] == "NameCheap, Inc."
    assert res["data"]["ageDays"] is not None and res["data"]["ageDays"] <= 11
    assert res["verdict"] == "suspicious"          # <30d old
    assert "very young domain" in res["summary"]
    assert res["data"]["nameservers"] == ["dns1.example.net", "dns2.example.net"]


def test_rdap_parses_ip_network(monkeypatch):
    from dashboard_api import enrichment
    monkeypatch.delenv("DASHBOARD_DISABLE_RDAP", raising=False)
    payload = {"handle": "NET-8-8-8-0-1", "name": "GOGL", "country": "US",
               "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
               "type": "ALLOCATION",
               "entities": [{"roles": ["registrant"],
                             "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]}
    monkeypatch.setattr(enrichment, "_rdap_get", lambda url: _FakeResp(payload))
    res = enrichment._enrich_rdap(None, "8.8.8.8", "ip")
    assert res["available"] is True
    assert res["verdict"] == "unknown"             # registry data is context, not a verdict
    assert res["data"]["country"] == "US" and res["data"]["org"] == "Google LLC"
    assert res["data"]["range"] == "8.8.8.0 - 8.8.8.255"


def test_rdap_private_ip_needs_no_registry(monkeypatch):
    from dashboard_api import enrichment
    monkeypatch.delenv("DASHBOARD_DISABLE_RDAP", raising=False)
    called = []
    monkeypatch.setattr(enrichment, "_rdap_get",
                        lambda url: called.append(url) or _FakeResp({}))
    res = enrichment._enrich_rdap(None, "192.168.1.10", "ip")
    assert res["available"] is True and called == []
    assert "non-routable" in res["summary"]


# -- Bulk lookup: the L1 triage action, and it must agree with the single one ---

def test_bulk_lookup_returns_every_submitted_value_in_order(client, auth):
    """An analyst pasting a firewall extract needs to see which lines were clean,
    not only the hits - a response containing just the matches makes it
    impossible to tell "checked and clean" from "not checked"."""
    bad, unknown = "bulk-evil.example", "bulk-never-seen.example"
    _put_ioc(bad, ioc_type="domain")
    try:
        r = client.post("/cti/lookup/bulk",
                        json={"values": [unknown, bad, "  ", unknown]}, headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        # Blank dropped, duplicate collapsed, submission order preserved.
        assert [x["value"] for x in body["results"]] == [unknown, bad]
        assert body["total"] == 2 and body["found"] == 1
        assert body["results"][0]["found"] is False
        assert body["results"][0]["verdict"] == "unverified"
        assert body["results"][1]["found"] is True
        assert body["results"][1]["verdict"] == "malicious"
    finally:
        _cleanup(bad)


def test_bulk_and_single_lookup_never_disagree(client, auth):
    """Two triage paths that reached different verdicts on the same value would
    be worse than having only one, so they share a matcher. This pins that: the
    delimiter-bounded fallbacks and the LinkedIn regression must behave
    identically through both endpoints."""
    hosted = "https://evil.example/agree-check/login"
    domain = "agree-evil.example"
    _put_ioc(hosted)
    _put_ioc(domain, ioc_type="domain", severity="medium", confidence=60)
    probes = [domain, "evil.example", hosted, "agree-check", "agree-never-seen.example"]
    try:
        bulk = {r["value"]: r for r in client.post(
            "/cti/lookup/bulk", json={"values": probes}, headers=auth).json()["results"]}
        for v in probes:
            single = client.get(f"/cti/lookup?value={v}", headers=auth).json()
            b = bulk[v]
            assert b["found"] == single["found"], f"{v}: found differs"
            assert b["verdict"] == single["verdict"], f"{v}: verdict differs"
            assert b["severity"] == single["severity"], f"{v}: severity differs"
            if single["found"]:
                # Single keys `value` to the matched indicator; bulk keeps the
                # query in `value` and reports the match in `matched`.
                assert b["matched"] == single["value"], f"{v}: matched indicator differs"
    finally:
        _cleanup(hosted, domain)


def test_bulk_lookup_refuses_an_unbounded_paste(client, auth):
    """A whole log pasted in must be refused with a clear limit, not turned into
    an unbounded scan of the store."""
    r = client.post("/cti/lookup/bulk",
                    json={"values": [f"v{i}.example" for i in range(1500)]}, headers=auth)
    assert r.status_code == 413
    # The app wraps HTTPException.detail as {"error": ...} - assert the contract
    # the browser actually receives, not the one FastAPI would emit by default.
    assert "1000" in r.json()["error"]


def test_bulk_lookup_handles_an_empty_submission(client, auth):
    r = client.post("/cti/lookup/bulk", json={"values": ["", "   "]}, headers=auth)
    assert r.status_code == 200
    assert r.json() == {"total": 0, "found": 0, "results": []}


def test_bulk_lookup_requires_authentication(client):
    r = client.post("/cti/lookup/bulk", json={"values": ["x.example"]})
    assert r.status_code in (401, 403), "the IOC store must not be readable anonymously"


def test_there_is_exactly_one_place_an_indicator_is_written():
    """Eight call sites used to spell `INSERT INTO iocs (...)` out by hand, each
    with its own column list, and every column added since was populated by some
    of them and not others. The ones that went missing were always the DERIVED
    columns, because those are the ones a caller has to remember to compute.

    Grepping each statement for each column - which is what this test used to
    do - scales with columns x call sites and only ever caught the column
    somebody thought to check. One writer makes the property structural."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts or path.name == "ioc_store.py":
            continue
        for m in re.finditer(r'"INSERT INTO iocs\b', path.read_text()):
            offenders.append(f"{path.relative_to(root)}:"
                             f"{path.read_text()[:m.start()].count(chr(10)) + 1}")
    assert not offenders, (
        "indicators must be written through ioc_store.ioc_row/insert_iocs, which "
        f"owns the column list and derives host/ip_hex/reg_domain: {offenders}")


def test_the_one_writer_populates_every_derived_column():
    """The behavioural half. Each of these columns backs a lookup that fails
    SILENTLY when it is NULL - no error, no failing request, just a quietly
    worse answer:

      host        "is this domain known-bad?" as an indexed lookup
      ip_hex      the ASN range query and the `network` pivot
      reg_domain  sibling clustering - the pivot that shows a phishing KIT
                  rather than three unrelated domains
      intel_score the default ranking; a zero sorts to the bottom of the list
                  an analyst actually opens
    """
    from dashboard_api.ioc_store import COLUMNS, ioc_row

    def col(row, name):
        return row[COLUMNS.index(name)]

    url = ioc_row(type="url", value="http://login.kit-example.test/a/b", confidence=80)
    assert col(url, "host") == "login.kit-example.test"
    assert col(url, "reg_domain") == "kit-example.test"
    assert col(url, "intel_score") > 0

    dom = ioc_row(type="domain", value="mail.kit-example.test", confidence=80)
    assert col(dom, "reg_domain") == col(url, "reg_domain"), (
        "a URL and a domain on the same site must cluster together")

    ip = ioc_row(type="ip", value="198.51.100.7", confidence=80)
    assert col(ip, "ip_hex") == "c6336407", "the ASN range key must be derivable"
    assert col(ip, "reg_domain") is None and col(ip, "host") is None


# -- Offset paging: the IOC library pages through the whole store ----------------

def test_paging_covers_every_row_exactly_once(client, auth):
    """The library pager walks the store with limit/offset. If the sort order is
    not total, tied keys come back in backend-dependent order and paging silently
    repeats some rows while skipping others - the analyst sees a list that looks
    complete and is not. Bulk feeds import thousands of rows sharing one
    last_seen second, so ties are the normal case here, not an edge case."""
    tag = uuid.uuid4().hex[:8]
    values = [f"page-{tag}-{i:03d}.example" for i in range(25)]
    for v in values:
        _put_ioc(v, ioc_type="domain")     # identical first_seen/last_seen: all tied
    try:
        seen, page, guard = [], 0, 0
        while guard < 20:
            guard += 1
            r = client.get(f"/cti/iocs?q=page-{tag}-&limit=10&offset={page * 10}",
                           headers=auth).json()
            assert r["total"] == 25, f"filtered total wrong: {r['total']}"
            if not r["items"]:
                break
            seen.extend(i["value"] for i in r["items"])
            page += 1
        assert len(seen) == 25, f"paging returned {len(seen)} rows for 25"
        assert len(set(seen)) == 25, "paging repeated rows across pages"
        assert set(seen) == set(values), "paging skipped rows"
    finally:
        _cleanup(*values)


def test_search_and_type_filters_narrow_the_total_together(client, auth):
    """The library sends q + type + status together; `total` must describe the
    filtered set, or the pager reports pages that do not exist."""
    tag = uuid.uuid4().hex[:8]
    dom, ip = f"combo-{tag}.example", f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    _put_ioc(dom, ioc_type="domain")
    _put_ioc(ip, ioc_type="ip")
    try:
        both = client.get(f"/cti/iocs?q=combo-{tag}", headers=auth).json()
        assert both["total"] == 1 and both["items"][0]["value"] == dom

        typed = client.get(f"/cti/iocs?q=combo-{tag}&type=ip", headers=auth).json()
        assert typed["total"] == 0 and typed["items"] == []
    finally:
        _cleanup(dom, ip)


def test_sources_online_counts_connectors_not_only_the_feeds_table(client, auth):
    """"Sources Online" on the front page is labelled "feeds & connectors
    active" but counted only the `feeds` table. Live mode deliberately seeds no
    feed rows, so the tile was structurally zero: a deployment pulling hundreds
    of thousands of indicators through working connectors reported 0 sources on
    the first screen an operator sees - which reads as "nothing is connected"."""
    from dashboard_api.db import get_conn as real_get_conn

    before = client.get("/overview/kpis", headers=auth).json()["sources"]
    cid = "srccount-" + uuid.uuid4().hex[:8]
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,"
            "interval_seconds,field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','ok',0,?)",
            (cid, f"Counted {cid}", "json", "https://example.test/feed",
             "2026-01-01T00:00:00"))
        c.commit()
    try:
        after = client.get("/overview/kpis", headers=auth).json()["sources"]
        assert after == before + 1, (
            f"an enabled connector did not count as a source ({before} -> {after})")

        # A disabled connector is not an online source.
        with real_get_conn() as c:
            c.execute("UPDATE connectors SET enabled=0 WHERE id=?", (cid,))
            c.commit()
        disabled = client.get("/overview/kpis", headers=auth).json()["sources"]
        assert disabled == before, f"a disabled connector still counted ({disabled})"
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connectors WHERE id=?", (cid,)); c.commit()


def test_kpis_report_how_many_assets_the_risk_score_covers(client, auth):
    """`score` is a criticality-weighted MEAN over assets, and the mean of an
    empty inventory is 0 - indistinguishable from "assessed, no risk found". The
    dashboard inverts it into a Prevention pillar, so nothing assessed rendered
    as 100% prevention: a perfect security posture asserted from no data. The
    count lets the UI say "not assessed" instead of inventing a pass."""
    from dashboard_api.db import get_conn as real_get_conn

    body = client.get("/overview/kpis", headers=auth).json()
    assert "assetsAssessed" in body, "the UI cannot tell an empty inventory from a clean one"

    with real_get_conn() as c:
        actual = c.execute("SELECT COUNT(*) AS n FROM assets").fetchone()["n"]
    assert body["assetsAssessed"] == actual
    # And the invariant that matters: a score of 0 with nothing assessed must be
    # reported as covering nothing, never as a measured result.
    if actual == 0:
        assert body["score"] == 0 and body["assetsAssessed"] == 0


def test_the_lookup_fixtures_do_not_decay_out_from_under_the_tests():
    """The invariant that broke, stated so it cannot break again quietly.

    Every lookup test here asks "does this value match, and what does the
    platform say about it". None of them are about decay. If the fixture row is
    old enough to be revoked, they all start asserting against an `expired`
    verdict - which is what happened when the dates were literals: fifty-seven
    days after a hardcoded `last_seen`, with no code change at all, the suite
    went red.
    """
    val = f"freshness-{uuid.uuid4().hex[:8]}.example"
    _put_ioc(val, ioc_type="url")
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT status, last_seen, intel_score FROM iocs WHERE value=?",
                (val,)).fetchone()
        assert row["status"] == "active", (
            f"the fixture is already {row['status']} on insert - every lookup "
            f"test in this file is now asserting against a decayed row")
        assert row["intel_score"] > 0
    finally:
        _cleanup(val)


# -- Corroboration: 16 feeds used to produce one opinion ------------------------

def _assert_source(value, source_id, ts=None):
    # Relative for the same reason `_put_ioc` is: these tests are about how many
    # sources agree, not about how long ago they said so, and a fixed date is a
    # bomb waiting for the scoring to start weighing recency.
    from datetime import datetime, timezone
    ts = ts or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO observable_sources (value,source_id,first_seen,last_seen,"
            "raw_label,confidence) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(value,source_id) DO UPDATE SET last_seen=?",
            (value, source_id, ts, ts, "phishing", 70, ts))
        conn.commit()


def test_lookup_reports_every_source_that_asserts_a_value(client, auth):
    """One blocklist listing an IP is weak evidence; five independent feeds
    agreeing is not. The store held 16 feeds and could not tell those apart,
    because a second feed listing a known value was counted as a duplicate and
    discarded - the corroborating fact was never recorded at all."""
    val = f"corrob-{uuid.uuid4().hex[:8]}.example"
    _put_ioc(val, ioc_type="domain")
    for src in ("osint:Feed A", "osint:Feed B", "osint:Feed C"):
        _assert_source(val, src)
    try:
        r = client.get(f"/cti/lookup?value={val}", headers=auth).json()
        assert r["found"] is True
        assert r["sourceCount"] == 3, f"expected 3 corroborating sources, got {r['sourceCount']}"
        assert set(r["sources"]) == {"osint:Feed A", "osint:Feed B", "osint:Feed C"}
    finally:
        _cleanup(val)
        with get_conn() as c:
            c.execute("DELETE FROM observable_sources WHERE value=?", (val,)); c.commit()


def test_bulk_check_carries_corroboration_for_every_hit(client, auth):
    """The triage screen is where this matters most: which of these 40 lines is
    backed by more than one source."""
    weak = f"weak-{uuid.uuid4().hex[:8]}.example"
    strong = f"strong-{uuid.uuid4().hex[:8]}.example"
    _put_ioc(weak, ioc_type="domain")
    _put_ioc(strong, ioc_type="domain")
    _assert_source(weak, "osint:Only Feed")
    for src in ("osint:Feed A", "osint:Feed B", "osint:Feed C", "osint:Feed D"):
        _assert_source(strong, src)
    try:
        res = client.post("/cti/lookup/bulk", json={"values": [weak, strong]},
                          headers=auth).json()
        by_val = {r["value"]: r for r in res["results"]}
        assert by_val[weak]["sourceCount"] == 1
        assert by_val[strong]["sourceCount"] == 4
    finally:
        _cleanup(weak, strong)
        with get_conn() as c:
            c.execute("DELETE FROM observable_sources WHERE value IN (?,?)", (weak, strong))
            c.commit()


def test_an_indicator_with_no_recorded_assertions_reports_one_not_zero(client, auth):
    """Rows imported before corroboration existed have no assertion rows. They
    are not "claimed by nobody" - something put them in the store - and showing
    0 would read as a value with no backing at all."""
    val = f"legacy-{uuid.uuid4().hex[:8]}.example"
    _put_ioc(val, ioc_type="domain")
    try:
        r = client.get(f"/cti/lookup?value={val}", headers=auth).json()
        assert r["found"] is True and r["sourceCount"] == 1
        listed = client.get(f"/cti/iocs?q={val}", headers=auth).json()
        assert listed["items"][0]["sourceCount"] == 1
    finally:
        _cleanup(val)


def test_an_unknown_value_claims_no_sources(client, auth):
    r = client.get("/cti/lookup?value=never-seen-anywhere.example", headers=auth).json()
    assert r["found"] is False and r["sourceCount"] == 0


def test_a_freshly_imported_kit_clusters_without_a_restart(client, auth):
    """The bug the single writer exists to prevent, stated end to end.

    `reg_domain` was populated by NOTHING except the boot-time backfill, and
    sibling clustering is an indexed equality on it. So three domains of one
    phishing kit, imported normally, returned no pivot groups at all - and
    started clustering the moment the process restarted, which is the worst
    possible shape for a bug: it works on every developer's machine and on a
    freshly-restarted deployment, and fails in production between restarts.
    """
    import uuid

    from dashboard_api.connectors import import_indicators
    from dashboard_api.db import get_conn
    from dashboard_api.relations import related

    base = f"kit{uuid.uuid4().hex[:8]}.test"
    vals = [f"{s}.{base}" for s in ("login", "mail", "vpn")]
    try:
        out = import_indicators(
            [{"type": "domain", "value": v, "threat_type": "phishing",
              "confidence": 80} for v in vals], source="test-kit")
        assert out["imported"] == 3, out
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM iocs WHERE value=?", (vals[0],)).fetchone()
            assert row["reg_domain"] == base, (
                "the import path must derive reg_domain, not wait for a restart")
            assert row["intel_score"] > 0, "a new indicator must rank on arrival"
            keys = [g["key"] for g in related(conn, dict(row))]
            assert "sibling" in keys, (
                f"the other two names of the same kit are invisible: {keys}")
    finally:
        with get_conn() as conn:
            conn.executemany("DELETE FROM iocs WHERE value=?", [(v,) for v in vals])
            conn.executemany("DELETE FROM observable_sources WHERE value=?",
                             [(v,) for v in vals])
            conn.commit()
