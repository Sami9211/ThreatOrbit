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


# -- Send-time SSRF defences (audit B1): pin the resolved IP, re-validate at the
#    moment of sending, and never follow redirects. ----------------------------

def test_safe_post_blocks_dns_rebinding(monkeypatch):
    """A public-looking name that resolves to the cloud-metadata IP at SEND time
    is rejected, even though it would have passed a check done at registration."""
    import socket

    from dashboard_api import net_guard
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 80))])
    with pytest.raises(net_guard.UnsafeUrlError):
        net_guard.safe_post("http://rebinding.example.com/x",
                            allow_private=False, json={})


def test_safe_post_pins_ip_preserves_host_and_blocks_redirects(monkeypatch):
    """The connection is pinned to the validated IP while the Host header + TLS
    SNI stay on the real hostname, and redirects are disabled on the client."""
    import socket

    import httpx

    from dashboard_api import net_guard
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    captured: dict = {}

    class FakeClient:
        def __init__(self, **kw):
            captured["client_kw"] = kw

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, url, **kw):
            captured["url"] = str(url)
            captured["headers"] = kw.get("headers")
            captured["extensions"] = kw.get("extensions")

            class _Resp:
                status_code = 200
            return _Resp()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    r = net_guard.safe_post("https://hooks.example.com/path",
                           allow_private=False, json={"x": 1})
    assert r.status_code == 200
    assert captured["client_kw"]["follow_redirects"] is False          # redirects blocked
    assert "93.184.216.34" in captured["url"]                          # pinned to resolved IP
    assert captured["headers"]["Host"] == "hooks.example.com"          # Host preserved
    assert captured["extensions"]["sni_hostname"] == "hooks.example.com"  # TLS SNI preserved
