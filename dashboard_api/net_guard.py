"""SSRF guard for user-supplied outbound URLs (webhooks, custom connectors,
personal Slack routing).

A user with config/connector permissions can otherwise point the server at
internal services - `http://127.0.0.1:8002/...`, a private database, or the
cloud metadata endpoint `http://169.254.169.254/...` - and have the server
fetch them (server-side request forgery). This module rejects URLs aimed at
the local host and at private / link-local / reserved address ranges.

Checks, in order:
  1. scheme must be http/https and a host must be present;
  2. a literal-IP host is range-checked directly;
  3. a hostname is resolved (DNS) and every resolved address is range-checked.

A DNS *resolution failure* is treated as "allow" so air-gapped / offline
deployments can still register public feeds whose names don't resolve locally
(an internal name, by contrast, does resolve - to a private IP - and is
blocked). Set ``DASHBOARD_ALLOW_PRIVATE_URLS=true`` to permit private targets
for local development / internal webhooks.
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse

import httpx

_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class UnsafeUrlError(ValueError):
    """Raised when a URL targets a disallowed (internal/reserved) destination."""


def _allow_private() -> bool:
    return os.environ.get("DASHBOARD_ALLOW_PRIVATE_URLS", "false").lower() == "true"


# NAT64 prefixes. `64:ff9b::/96` is the RFC 6052 Well-Known Prefix; operators may
# also use a Network-Specific Prefix, which RFC 7050 discovers and which can be
# declared here. Extra prefixes are comma-separated in DASHBOARD_NAT64_PREFIXES.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def _nat64_prefixes() -> list[ipaddress.IPv6Network]:
    nets = [_NAT64_WELL_KNOWN]
    for raw in os.environ.get("DASHBOARD_NAT64_PREFIXES", "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv6Network):
            nets.append(net)
    return nets


def embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address a NAT64 address stands for, or None.

    On an IPv6-only network with DNS64, a public IPv4-only host resolves to a
    SYNTHESIZED AAAA record inside a NAT64 prefix - e.g. otx.alienvault.com ->
    64:ff9b::12f5:fd66, which carries the public 18.245.253.102. Python reports
    `is_reserved` for that range, so range-checking the synthesized address
    rejects a perfectly public destination and every outbound connector fails on
    such a host. The address to judge is the one it actually reaches."""
    for net in _nat64_prefixes():
        if ip in net:
            # RFC 6052: for a /96 the IPv4 is the last 32 bits. Shorter prefixes
            # interleave around the u-octet at bits 64-71, which is skipped.
            plen = net.prefixlen
            if plen == 96:
                return ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
            if plen in (32, 40, 48, 56, 64):
                bits = int(ip)
                v4 = (bits >> (128 - plen - 32)) & 0xFFFFFFFF if plen <= 56 else \
                     (bits >> 24) & 0xFFFFFFFF
                try:
                    return ipaddress.ip_address(v4)
                except ValueError:
                    return None
    return None


def _blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # Judge a NAT64 address by the IPv4 host it reaches. A synthesized
        # address for an internal IPv4 still gets blocked - it decodes to a
        # private address and fails the same checks below.
        mapped = embedded_ipv4(ip)
        if mapped is not None:
            ip = mapped
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def validate_external_url(url: str, *, allow_private: bool | None = None) -> str:
    """Return the trimmed URL if it is a safe external http(s) target, else
    raise :class:`UnsafeUrlError`. ``allow_private=True`` skips the range checks
    (used by callers that have already opted in); when ``None`` the
    ``DASHBOARD_ALLOW_PRIVATE_URLS`` env var decides."""
    value = (url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeUrlError("URL must start with http:// or https://")
    host = parsed.hostname
    if not host:
        raise UnsafeUrlError("URL has no host")

    allow = _allow_private() if allow_private is None else allow_private
    if allow:
        return value

    if host.lower() in _LOCAL_HOSTNAMES:
        raise UnsafeUrlError("URL must not target the local host")

    # Literal IP host - range-check directly.
    try:
        ipaddress.ip_address(host)
        if _blocked(host):
            raise UnsafeUrlError("URL must not target a private or reserved address")
        return value
    except ValueError:
        pass  # not a literal IP - it's a hostname

    # Hostname: resolve when possible; a resolution failure is allowed (offline).
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return value
    for info in infos:
        ip = info[4][0]
        if _blocked(ip):
            # Name the host AND the offending address. A bare "resolves to a
            # private address" is undiagnosable: the cause is almost always
            # environmental (a DNS sinkhole returning 0.0.0.0, split-horizon
            # corporate DNS, or an unusable IPv6 record alongside a fine A
            # record) and the operator cannot tell which without the address.
            raise UnsafeUrlError(
                f"URL resolves to a private or reserved address "
                f"({host} -> {ip}). Check DNS on this host: a blocker or "
                f"internal resolver may be sinkholing this domain.")
    return value


def _safe_connect_ip(parsed, allow: bool) -> str | None:
    """Resolve ``parsed.hostname`` and return ONE address that's safe to connect
    to, after range-checking *every* resolved address (so a name that resolves to
    a mix of public and private addresses is rejected, not cherry-picked).

    Returns ``None`` when the host is already a literal IP that should be used
    as-is is handled by the caller, when ``allow`` is set, or when resolution
    fails (offline) - in those cases the caller connects normally without
    pinning. Raises :class:`UnsafeUrlError` if a resolved address is blocked.
    """
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        return host  # literal IP - already validated; pin to it directly
    except ValueError:
        pass
    if allow:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None  # offline: validate_external_url already let it through
    ips = [i[4][0] for i in infos]
    for ip in ips:
        if _blocked(ip):
            raise UnsafeUrlError(
                f"URL resolves to a private or reserved address ({host} -> {ip}). "
                f"Check DNS on this host: a blocker or internal resolver may be "
                f"sinkholing this domain.")
    return ips[0] if ips else None


def safe_request(method: str, url: str, *, allow_private: bool | None = None,
                 timeout: float = 5.0, **kwargs) -> httpx.Response:
    """Make an outbound HTTP request to a *user-supplied* URL with the SSRF
    defences applied at SEND time, not just at registration time:

      * the URL is re-validated now (scheme / host / address-range checks);
      * DNS is resolved once and the connection is PINNED to a validated IP, so a
        name that passed validation can't rebind to ``127.0.0.1`` /
        ``169.254.169.254`` between the check and the connect (DNS rebinding /
        TOCTOU - the gap the registration-time check alone leaves open);
      * redirects are NOT followed (a 30x to an internal URL would otherwise be
        re-resolved by the client and bypass the guard).

    TLS still verifies against the real hostname (SNI + certificate check) even
    though the socket connects to the pinned IP. Raises :class:`UnsafeUrlError`
    for disallowed targets; otherwise returns the :class:`httpx.Response`.
    """
    allow = _allow_private() if allow_private is None else allow_private
    validate_external_url(url, allow_private=allow)
    parsed = urlparse((url or "").strip())
    ip = _safe_connect_ip(parsed, allow)

    headers = dict(kwargs.pop("headers", {}) or {})
    extensions = dict(kwargs.pop("extensions", {}) or {})
    request_url: str | httpx.URL = url
    if ip and ip != parsed.hostname:
        # Pin to the validated IP, but keep the Host header + TLS SNI pointed at
        # the real hostname so the request still addresses (and verifies against)
        # the intended server.
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port
        host_header = parsed.hostname if (port is None or port == default_port) \
            else f"{parsed.hostname}:{port}"
        headers.setdefault("Host", host_header)
        if parsed.scheme == "https":
            extensions.setdefault("sni_hostname", parsed.hostname)
        request_url = httpx.URL(url).copy_with(host=ip)

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        return client.request(method, request_url, headers=headers,
                              extensions=extensions, **kwargs)


def safe_post(url: str, **kwargs) -> httpx.Response:
    """SSRF-hardened ``POST`` for user-supplied URLs (see :func:`safe_request`)."""
    return safe_request("POST", url, **kwargs)


def safe_get(url: str, **kwargs) -> httpx.Response:
    """SSRF-hardened ``GET`` for user-supplied URLs (see :func:`safe_request`)."""
    return safe_request("GET", url, **kwargs)
