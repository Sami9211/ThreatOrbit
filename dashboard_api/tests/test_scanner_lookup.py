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
    # Sets `host` exactly as every production insert path does. A helper that
    # skipped it would make the domain-lookup tests pass against rows that could
    # not exist in a real store, hiding the very breakage they exist to catch.
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
            "first_seen,last_seen,tags,org_id,host) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), ioc_type, value, "Phishing", confidence, severity,
             "pytest-feed", "", "2026-01-01T00:00:00", "2026-07-01T00:00:00", "[]",
             DEFAULT_ORG_ID, host_of(value, ioc_type)),
        )
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


def test_every_ioc_insert_path_populates_host():
    """`iocs.host` powers "is this domain known-bad?" as an indexed lookup. A row
    written without it is invisible to that question - silently, with no error
    and no failing request, just a quietly less accurate answer.

    There are eight insert paths across the app. This is a static fence rather
    than a behavioural one because the failure is a NEGATIVE: a ninth insert
    added later would break domain lookups for whatever it writes, and no
    existing test would notice."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text()
        for m in re.finditer(r'"INSERT INTO iocs \(([^"]*)"(?:\s*"([^"]*)")*', text):
            # Column list can be split across adjacent string literals; join the
            # statement's leading run of literals before checking.
            tail = text[m.start():m.start() + 400]
            cols = " ".join(re.findall(r'"([^"]*)"', tail)[:4])
            if "host" not in cols:
                line = text[:m.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(root)}:{line}")
    assert not offenders, (
        "these INSERT INTO iocs statements do not set `host`, so indicators they "
        f"write will not be found by domain lookups: {offenders}")


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
