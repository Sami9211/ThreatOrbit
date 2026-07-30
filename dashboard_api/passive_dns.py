"""First-party passive DNS: what THIS deployment has actually observed.

Every other enrichment in this platform is somebody else's opinion about an
indicator. This one is not. When we resolve a domain, that resolution is a fact
about the internet at a moment in time, observed here - and once recorded it
answers questions no public CTI library can answer for a given customer:

  * "What did this domain resolve to, and has it moved?" Fast-flux and
    bulletproof hosting show up as churn in this table and nowhere else.
  * "What else resolved to this address?" The classic passive-DNS pivot, and the
    one that turns a single indicator into a piece of infrastructure.
  * "Do forward and reverse agree?" A domain that resolves to an address whose
    PTR points back is a real, configured mapping. One that does not is a weaker
    claim, and the difference is worth showing rather than flattening.

Observations are never invented. A failed or blocked resolution records nothing
at all, because an empty answer here has to mean "we have not seen it" and not
"it resolves to nothing".
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Resolution is a network call on a request path, so it is hard-bounded. The
# system resolver has its own timeouts but they are long and not always honoured;
# a hung lookup must not hold an API request open.
TIMEOUT_SECONDS = float(__import__("os").environ.get("DASHBOARD_DNS_TIMEOUT", "3.0"))

# Addresses per name we are willing to record from one lookup. A round-robin CDN
# name legitimately returns dozens; beyond this it is not adding information.
MAX_ADDRESSES = 12

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def addr_hex(ip: str) -> str | None:
    """Same fixed-width hex encoding as asn_ranges and iocs.ip_hex, so a DNS
    observation can be range-matched against a BGP prefix directly."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return format(int(parsed), "0%dx" % (8 if parsed.version == 4 else 32))


def _forward(name: str) -> list[str]:
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    seen, out = set(), []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out[:MAX_ADDRESSES]


def _reverse(ip: str) -> str | None:
    return socket.gethostbyaddr(ip)[0]


def _bounded(fn, arg):
    """Run a resolver call with a hard timeout. Returns None on any failure -
    callers must treat that as "not observed", never as "resolves to nothing"."""
    try:
        return _pool.submit(fn, arg).result(timeout=TIMEOUT_SECONDS)
    except (FuturesTimeout, socket.gaierror, socket.herror, OSError, UnicodeError):
        return None
    except Exception:                               # noqa: BLE001
        log.debug("unexpected resolver failure for %r", arg, exc_info=True)
        return None


def record(conn, name: str, address: str, via: str) -> None:
    """Store one observed (name, address) pair.

    `via` is how we learned it - 'forward' or 'ptr'. Seeing the same pair from
    BOTH directions is a stronger claim than either alone (it means the mapping
    is actually configured, not just cached), so that is recorded as 'both'
    rather than flattened away.
    """
    n = (name or "").strip().strip(".").lower()
    a = (address or "").strip()
    if not n or not a or addr_hex(a) is None:
        return
    now = _now()
    row = conn.execute(
        "SELECT observed_via FROM dns_observations WHERE name=? AND address=?",
        (n, a)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO dns_observations (name,address,addr_hex,first_seen,last_seen,"
            "times_seen,observed_via) VALUES (?,?,?,?,?,1,?)",
            (n, a, addr_hex(a), now, now, via))
        return
    via_now = row["observed_via"]
    merged = "both" if (via_now and via_now != via) else via
    conn.execute(
        "UPDATE dns_observations SET last_seen=?, times_seen=times_seen+1, "
        "observed_via=? WHERE name=? AND address=?", (now, merged, n, a))


def observe_name(conn, name: str) -> list[str]:
    """Resolve `name` and record what came back. Returns the addresses observed.

    An empty list means the lookup failed or returned nothing, and NOTHING is
    written - so a later "we have no observations" is honest rather than a
    recorded claim that the name resolves nowhere.
    """
    n = (name or "").strip().strip(".").lower()
    if not n or "/" in n:
        return []
    addrs = _bounded(_forward, n)
    if not addrs:
        return []
    for a in addrs:
        record(conn, n, a, "forward")
    return addrs


def observe_address(conn, ip: str) -> str | None:
    """Reverse-resolve `ip` and record the PTR name. None when there is none."""
    if addr_hex(ip) is None:
        return None
    host = _bounded(_reverse, ip.strip())
    if not host:
        return None
    record(conn, host, ip.strip(), "ptr")
    return host.strip(".").lower()


def for_name(conn, name: str, limit: int = 20) -> list[dict]:
    """Everything this deployment has observed `name` resolving to, newest first."""
    n = (name or "").strip().strip(".").lower()
    if not n:
        return []
    return [_shape(r) for r in conn.execute(
        "SELECT * FROM dns_observations WHERE name=? ORDER BY last_seen DESC LIMIT ?",
        (n, limit)).fetchall()]


def for_address(conn, ip: str, limit: int = 20) -> list[dict]:
    """Every name this deployment has observed resolving to `ip`.

    The classic passive-DNS pivot: one indicator becomes a piece of
    infrastructure, and shared hosting becomes visible instead of implied.
    """
    a = (ip or "").strip()
    if addr_hex(a) is None:
        return []
    return [_shape(r) for r in conn.execute(
        "SELECT * FROM dns_observations WHERE address=? ORDER BY last_seen DESC LIMIT ?",
        (a, limit)).fetchall()]


def _shape(r) -> dict:
    return {"name": r["name"], "address": r["address"],
            "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
            "timesSeen": r["times_seen"], "observedVia": r["observed_via"]}


def stats(conn) -> dict:
    """Size of the local observation set, for the UI. Zero is a real answer for a
    deployment that has not resolved anything yet."""
    row = conn.execute(
        "SELECT COUNT(*) AS pairs, COUNT(DISTINCT name) AS names, "
        "COUNT(DISTINCT address) AS addresses FROM dns_observations").fetchone()
    return {"pairs": row["pairs"] or 0, "names": row["names"] or 0,
            "addresses": row["addresses"] or 0}
