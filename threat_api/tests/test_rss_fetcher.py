"""RSS fetcher IOC extraction: correctness + resilience against a hostile feed.

RSS/Atom bodies are third-party and attacker-influenceable. The extraction
regexes have no match timeout, so a crafted text blob could otherwise drive the
domain pattern into catastrophic backtracking (a ReDoS that stalls the whole
OSINT refresh thread). These lock in the fix: bounded input + a possessive
quantifier keep extraction fast on adversarial input while still finding real
indicators.
"""
import time

from threat_api.fetchers.rss import _extract_iocs, _MAX_EXTRACT_CHARS


def test_extract_finds_real_indicators():
    text = ("New campaign C2 at http://evil.example/panel and 203.0.113.45, "
            "dropper hash abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 "
            "beaconing to bad-domain.example.com")
    found = dict(_extract_iocs(text))
    inv = {}
    for t, v in _extract_iocs(text):
        inv.setdefault(t, set()).add(v)
    assert "203.0.113.45" in inv.get("ip", set())
    assert "http://evil.example/panel" in inv.get("url", set())
    assert "bad-domain.example.com" in inv.get("domain", set())
    assert any(len(v) == 64 for v in inv.get("hash", set()))


def test_extract_is_fast_on_adversarial_input():
    """A long 'a.a.a.…' run made the old greedy domain pattern backtrack for many
    seconds (8.5s at 20k, >20s at 40k). Bounded input + possessive quantifier
    keep it well under a second - a strict ceiling that regresses loudly."""
    evil = "a." * 40000          # ~80k chars, no valid trailing label → worst case
    t = time.time()
    _extract_iocs(evil)
    elapsed = time.time() - t
    assert elapsed < 2.0, f"IOC extraction took {elapsed:.2f}s - ReDoS guard regressed"


def test_extract_input_is_capped():
    """Extraction only scans up to the cap, so a huge blob can't drive unbounded
    regex work regardless of the pattern."""
    # A real domain placed AFTER the cap must not be scanned.
    filler = "x" * (_MAX_EXTRACT_CHARS + 100)
    text = filler + " real-domain-after-cap.example"
    domains = {v for t, v in _extract_iocs(text) if t == "domain"}
    assert "real-domain-after-cap.example" not in domains
