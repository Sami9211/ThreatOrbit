"""The SSRF guard for user-supplied outbound URLs (webhooks, connectors, Slack).

These call validate_external_url with allow_private=False explicitly so the test
asserts the blocking behaviour regardless of the DASHBOARD_ALLOW_PRIVATE_URLS
env (conftest sets it true so the webhook-delivery tests can use a local sink).
"""
import pytest

from dashboard_api import net_guard
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


# -- NAT64 / DNS64: an IPv6-only host reaches IPv4 destinations through a
#    synthesized address, and judging the synthesized form blocks everything ----

class TestNat64:
    """`64:ff9b::/96` is the RFC 6052 Well-Known Prefix. On an IPv6-only network
    with DNS64, an IPv4-only host resolves to a synthesized AAAA inside it -
    otx.alienvault.com became 64:ff9b::12f5:fd66, carrying the public
    18.245.253.102. Python reports is_reserved for that whole range, so the
    guard rejected a perfectly public destination and EVERY outbound connector
    failed on such a host. The address to judge is the one it actually reaches.
    """

    def test_public_ipv4_behind_nat64_is_allowed(self):
        # The exact address from the field report.
        assert net_guard._blocked("64:ff9b::12f5:fd66") is False

    def test_the_decoded_address_is_the_real_destination(self):
        import ipaddress
        got = net_guard.embedded_ipv4(ipaddress.ip_address("64:ff9b::12f5:fd66"))
        assert str(got) == "18.245.253.102"

    @pytest.mark.parametrize("addr,reaches", [
        ("64:ff9b::7f00:1", "127.0.0.1"),           # loopback
        ("64:ff9b::a00:1", "10.0.0.1"),             # RFC1918
        ("64:ff9b::c0a8:1", "192.168.0.1"),         # RFC1918
        ("64:ff9b::a9fe:a9fe", "169.254.169.254"),  # cloud metadata
        ("64:ff9b::ac10:1", "172.16.0.1"),          # RFC1918
    ])
    def test_nat64_cannot_be_used_to_smuggle_an_internal_target(self, addr, reaches):
        """The whole point of the guard. Decoding must not become a bypass: an
        attacker who can set a feed URL must not reach the metadata endpoint by
        wrapping it in a NAT64 prefix. We decode, then range-check the DECODED
        address, so these stay blocked."""
        import ipaddress
        assert str(net_guard.embedded_ipv4(ipaddress.ip_address(addr))) == reaches
        assert net_guard._blocked(addr) is True

    def test_ordinary_ipv6_is_unaffected(self):
        assert net_guard._blocked("2606:4700:4700::1111") is False   # public
        assert net_guard._blocked("::1") is True                     # loopback
        assert net_guard._blocked("fc00::1") is True                 # unique-local

    def test_operator_declared_prefix_is_honoured(self, monkeypatch):
        """Networks that use a Network-Specific Prefix instead of the well-known
        one (RFC 7050) can declare it; without this their connectors fail the
        same way."""
        monkeypatch.setenv("DASHBOARD_NAT64_PREFIXES", "2001:db8:64::/96")
        assert net_guard._blocked("2001:db8:64::12f5:fd66") is False
        # and an internal target through that prefix is still refused
        assert net_guard._blocked("2001:db8:64::a9fe:a9fe") is True

    def test_a_declared_prefix_that_is_garbage_is_ignored_not_fatal(self, monkeypatch):
        monkeypatch.setenv("DASHBOARD_NAT64_PREFIXES", "not-a-prefix,,10.0.0.0/8")
        # Still works, and the IPv4 entry is not treated as a NAT64 prefix.
        assert net_guard._blocked("64:ff9b::12f5:fd66") is False
        assert net_guard._blocked("10.0.0.1") is True
