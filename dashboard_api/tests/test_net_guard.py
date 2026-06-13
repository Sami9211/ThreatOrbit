"""The SSRF guard for user-supplied outbound URLs (webhooks, connectors, Slack).

These call validate_external_url with allow_private=False explicitly so the test
asserts the blocking behaviour regardless of the DASHBOARD_ALLOW_PRIVATE_URLS
env (conftest sets it true so the webhook-delivery tests can use a local sink).
"""
import pytest

from dashboard_api.net_guard import UnsafeUrlError, validate_external_url

BLOCKED = [
    "http://127.0.0.1/x",                              # loopback
    "http://localhost/x",                              # loopback name
    "http://169.254.169.254/latest/meta-data/",        # cloud metadata (link-local)
    "http://10.0.0.5/internal",                        # private
    "http://192.168.1.1/admin",                        # private
    "http://172.16.0.9/",                              # private
    "http://[::1]/x",                                  # IPv6 loopback
    "http://0.0.0.0/x",                                # unspecified
]


@pytest.mark.parametrize("url", BLOCKED)
def test_blocks_internal_targets(url):
    with pytest.raises(UnsafeUrlError):
        validate_external_url(url, allow_private=False)


@pytest.mark.parametrize("url", [
    "ftp://example.com/x",       # non-http scheme
    "file:///etc/passwd",        # file scheme
    "not-a-url",                 # no scheme/host
    "http://",                   # no host
])
def test_rejects_non_http_or_hostless(url):
    with pytest.raises(UnsafeUrlError):
        validate_external_url(url, allow_private=False)


def test_allows_public_target():
    # A public hostname passes: when DNS resolves it is a public IP; offline the
    # resolution failure is treated as allowed (so air-gapped setups still work).
    out = validate_external_url("https://hooks.example.com/threatorbit", allow_private=False)
    assert out == "https://hooks.example.com/threatorbit"


def test_override_permits_private():
    # The escape hatch (local dev / internal webhooks) lets a loopback through.
    assert validate_external_url("http://127.0.0.1:9000/sink", allow_private=True) == \
        "http://127.0.0.1:9000/sink"
