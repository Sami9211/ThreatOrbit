"""CORS posture - evaluation installs must work from any private origin.

The default allowlist (localhost:3000/3111) meant reaching the dashboard via
a LAN IP or intranet hostname broke every API call - the loudest symptom was
UI actions "erroring" (the mode toggle POSTs /config/mode on every click).
Evaluation posture now also accepts loopback/private-range IPs and
single-label intranet hostnames via CORS_ORIGIN_REGEX; public domains stay
rejected, and production (REQUIRE_SECRETS) keeps the explicit allowlist.
"""
import re

from dashboard_api import config


def _preflight(client, origin):
    return client.options(
        "/config/mode",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )


def test_private_origins_pass_preflight(client):
    for origin in ("http://192.168.1.20:3000", "http://10.0.0.5:8080",
                   "http://desk-01:3000", "http://localhost:3005"):
        r = _preflight(client, origin)
        assert r.headers.get("access-control-allow-origin") == origin, \
            f"{origin} should be allowed in evaluation posture"


def test_public_origins_stay_rejected(client):
    for origin in ("https://evil.com", "http://phishing.example.org:3000"):
        r = _preflight(client, origin)
        assert r.headers.get("access-control-allow-origin") != origin, \
            f"{origin} must NOT be CORS-allowed"


def test_regex_shape():
    """The private-origin pattern itself: single-label hostnames only (a dot
    means a public-DNS-reachable name and must not match)."""
    r = re.compile(config._PRIVATE_ORIGIN_REGEX)
    assert r.match("http://172.16.9.9:3000")
    assert r.match("http://[::1]:3000")
    assert not r.match("http://172.32.0.1:3000")     # outside 172.16-31
    assert not r.match("http://a.b:3000")            # dotted hostname
    assert not r.match("https://sub.evil.com")