"""Unit tests for the threat_api transform pipeline - the core CTI logic
(normalisation, multi-source correlation, trust scoring, STIX conversion) that
had no coverage beyond /health. Audit finding D1.
"""
import json

from threat_api.models import IOC, EnrichedIOC
from threat_api.normalization import boost_confidence_by_correlation, normalize_iocs
from threat_api.stix_converter.converter import convert_to_stix_bundle
from threat_api.trust_scoring import _canonical_source_name, apply_trust_scoring


# ── Normalisation ──────────────────────────────────────────────────────────────
def test_normalize_canonicalises_values_and_drops_invalid():
    iocs = [
        IOC(ioc_type="domain", value="Evil.COM.", source="otx"),       # lower + trailing-dot strip
        IOC(ioc_type="domain", value="HTTPS://Bad.Org", source="otx"), # scheme stripped to host
        IOC(ioc_type="ip", value=" 8.8.8.8 ", source="otx"),           # trimmed + canonical
        IOC(ioc_type="hash", value="ABCDEF123", source="otx"),         # lowercased
        IOC(ioc_type="ip", value="not-an-ip", source="otx"),           # invalid → dropped
    ]
    out = normalize_iocs(iocs)
    vals = {i.value for i in out}
    assert {"evil.com", "bad.org", "8.8.8.8", "abcdef123"} <= vals
    assert len(out) == 4   # the invalid IP was dropped


def test_normalize_infers_tags():
    out = normalize_iocs([
        IOC(ioc_type="url", value="http://bank.example/secure/login", source="rss-feed"),
        IOC(ioc_type="domain", value="x.example", source="darkweb-monitor"),
    ])
    url = next(i for i in out if i.ioc_type == "url")
    dom = next(i for i in out if i.ioc_type == "domain")
    assert "possible-phishing" in url.tags and "rss-ingested" in url.tags
    assert "darkweb-osint" in dom.tags


def test_correlation_boosts_multi_source_confidence():
    iocs = [
        IOC(ioc_type="ip", value="1.2.3.4", source="otx", confidence=50),
        IOC(ioc_type="ip", value="1.2.3.4", source="abuse.ch", confidence=50),
        IOC(ioc_type="ip", value="1.2.3.4", source="rss", confidence=50),
        IOC(ioc_type="ip", value="9.9.9.9", source="otx", confidence=50),  # single source
    ]
    boost_confidence_by_correlation(iocs)
    multi = [i for i in iocs if i.value == "1.2.3.4"]
    single = next(i for i in iocs if i.value == "9.9.9.9")
    assert all(i.confidence == 70 for i in multi)   # +10 (>=2 sources) +10 (>=3)
    assert "multi-source-confirmed" in multi[0].tags and "high-correlation" in multi[0].tags
    assert single.confidence == 50 and "multi-source-confirmed" not in single.tags


# ── Trust scoring ──────────────────────────────────────────────────────────────
def test_trust_scoring_applies_source_weight_and_base():
    config = {"default_weight": 1.0, "default_base_confidence": 40, "feed_overrides": {},
              "sources": {"AlienVault OTX": {"weight": 1.2, "base_confidence": 60},
                          "RSS": {"weight": 0.5, "base_confidence": 30}}}
    otx = IOC(ioc_type="ip", value="1.1.1.1", source="AlienVault OTX pulse", confidence=50)
    rss = IOC(ioc_type="ip", value="2.2.2.2", source="rss-cyberblog", confidence=50)
    apply_trust_scoring([otx, rss], config)
    assert otx.confidence == 72   # max(50,60)=60 * 1.2
    assert rss.confidence == 25   # max(50,30)=50 * 0.5
    assert any(t.startswith("trust_weight:") for t in otx.tags)


def test_canonical_source_name():
    assert _canonical_source_name("AlienVault OTX - Pulse X") == "AlienVault OTX"
    assert _canonical_source_name("abuse.ch URLhaus") == "abuse.ch"
    assert _canonical_source_name("rss-cyber-blog") == "RSS"
    assert _canonical_source_name("darkweb-monitor") == "DarkWeb OSINT"


# ── STIX 2.1 conversion ────────────────────────────────────────────────────────
def test_stix_bundle_structure_and_patterns():
    iocs = [
        EnrichedIOC(ioc_type="ip", value="1.2.3.4", source="otx", confidence=80, tags=["botnet"]),
        EnrichedIOC(ioc_type="domain", value="evil.example", source="otx"),
        EnrichedIOC(ioc_type="url", value="http://evil.example/x", source="otx"),
        EnrichedIOC(ioc_type="hash", value="abc123", source="otx"),
        EnrichedIOC(ioc_type="email", value="a@b.c", source="otx"),  # unsupported → skipped
    ]
    bundle = convert_to_stix_bundle(iocs)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    assert bundle["objects"][0]["type"] == "identity"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 4   # the unsupported email type produced no indicator
    patterns = {o["pattern"] for o in indicators}
    assert "[ipv4-addr:value = '1.2.3.4']" in patterns
    assert "[domain-name:value = 'evil.example']" in patterns
    assert "[url:value = 'http://evil.example/x']" in patterns
    assert "[file:hashes.'SHA-256' = 'abc123']" in patterns
    ip_ind = next(o for o in indicators if "ipv4" in o["pattern"])
    assert ip_ind["pattern_type"] == "stix" and ip_ind["confidence"] == 80
    assert "threatorbit" in ip_ind["labels"] and "botnet" in ip_ind["labels"]


def test_stix_bundle_parses_with_stix2_library():
    try:
        import stix2
    except ImportError:
        return  # optional dependency in some envs
    bundle = convert_to_stix_bundle(
        [EnrichedIOC(ioc_type="ip", value="1.2.3.4", source="otx", confidence=80)])
    stix2.parse(json.dumps(bundle), allow_custom=True)   # validates against the 2.1 object model
