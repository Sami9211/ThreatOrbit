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

_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class UnsafeUrlError(ValueError):
    """Raised when a URL targets a disallowed (internal/reserved) destination."""


def _allow_private() -> bool:
    return os.environ.get("DASHBOARD_ALLOW_PRIVATE_URLS", "false").lower() == "true"


def _blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
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
        if _blocked(info[4][0]):
            raise UnsafeUrlError("URL resolves to a private or reserved address")
    return value
