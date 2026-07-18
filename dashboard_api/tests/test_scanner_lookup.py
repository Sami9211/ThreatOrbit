"""IntelScope lookup + enrichment - no fabricated maliciousness.

The old lookup fell back to a blind substring match (`LIKE %query%`): scanning
`linkedin.com` matched a phishing URL hosted elsewhere that merely EMBEDS the
string (e.g. https://evil.example/linkedin.com/login) and branded the
legitimate domain malicious. Matching is now delimiter-bounded, and unknown
values report "unverified" - absence from our TI proves nothing, in neither
direction.
"""
import uuid

from dashboard_api.db import get_conn
from dashboard_api.tenancy import DEFAULT_ORG_ID


def _put_ioc(value, ioc_type="url", severity="critical", confidence=95):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
            "first_seen,last_seen,tags,org_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), ioc_type, value, "Phishing", confidence, severity,
             "pytest-feed", "", "2026-01-01T00:00:00", "2026-07-01T00:00:00", "[]",
             DEFAULT_ORG_ID),
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
