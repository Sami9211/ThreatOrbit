"""What else is this indicator connected to?

An indicator an analyst cannot pivot from is a dead end, and a store of 315,185
dead ends is a list, not intelligence. The drawer already answers "should I care
about this?" (see intel_scoring) - this answers the question that always comes
next: "what else do we hold that is part of the same thing?"

Every relation here is derived from data the store ALREADY holds, and every one
states the evidence for itself rather than asserting a connection:

  * **same report** - arrived in the same pulse/report. The strongest link
    available, because a human or a feed curator put them together deliberately.
  * **same actor** - attributed to the same adversary.
  * **same host** - a domain and the URLs hosted on it, in both directions.
  * **same registrable domain** - sibling subdomains, which is how phishing kits
    and DGA clusters show up (`login.x.test`, `mail.x.test`).
  * **same network (AS)** - only when the BGP table has been synced. One
    bulletproof host looks very different from 40 unrelated networks.
  * **same subnet (/24)** - the offline fallback for that, and the only pivot an
    IP indicator has on a deployment that has never reached the BGP table.

Nothing here invents a relationship. If two indicators share nothing, the answer
is an empty list, not a weak guess - a graph padded with coincidental edges is
worse than no graph, because an analyst cannot tell which edges to trust.
"""
from __future__ import annotations

from dashboard_api.db import ip_hex_of, registrable_domain

# Per-group cap. An indicator from a 40,000-value blocklist "relates to" all
# 39,999 others by source; showing the top few by score and stating the true
# total is the useful answer, and the only one that renders.
GROUP_LIMIT = 8


def _host_of_row(ioc: dict) -> str | None:
    """The hostname this indicator is about: the stored host for a URL, the
    value itself for a domain."""
    if ioc.get("host"):
        return str(ioc["host"]).lower()
    if (ioc.get("type") or "").lower() == "domain":
        return str(ioc.get("value") or "").strip().strip(".").lower() or None
    return None


def _rows(conn, sql: str, params: tuple, exclude_id: str) -> list[dict]:
    """Run one pivot query and shape the rows the UI needs."""
    out = []
    for r in conn.execute(sql, params).fetchall():
        if r["id"] == exclude_id:
            continue
        out.append({"id": r["id"], "type": r["type"], "value": r["value"],
                    "severity": r["severity"], "intelScore": r["intel_score"] or 0,
                    "threatType": r["threat_type"], "status": r["status"]})
    return out


_SELECT = ("SELECT id, type, value, severity, intel_score, threat_type, status "
           "FROM iocs WHERE ")
# Best-first, so a truncated group shows the ones worth opening rather than
# whichever happened to be inserted first.
_ORDER = " ORDER BY intel_score DESC, id DESC LIMIT ?"


def _count(conn, where: str, params: tuple) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS n FROM iocs WHERE {where}", params).fetchone()
    return (row["n"] if row else 0) or 0


def related(conn, ioc: dict, *, limit: int = GROUP_LIMIT) -> list[dict]:
    """Pivot groups for one indicator, strongest link first.

    Each group carries `total` (the true count, which can far exceed what is
    shown) and `why` - the evidence for the link, so an analyst can judge whether
    to trust the edge instead of taking the graph's word for it.
    """
    ioc_id = ioc.get("id") or ""
    groups: list[dict] = []
    # +1 on every limit so a group whose only member is the indicator itself
    # (filtered out in _rows) does not come back one short.
    fetch = limit + 1

    if ioc.get("report_id"):
        where = "report_id = ? AND id != ?"
        params = (ioc["report_id"], ioc_id)
        items = _rows(conn, _SELECT + where + _ORDER, params + (fetch,), ioc_id)
        if items:
            title = None
            row = conn.execute("SELECT title FROM intel_reports WHERE id=?",
                               (ioc["report_id"],)).fetchone()
            if row:
                title = row["title"]
            groups.append({
                "key": "report", "label": "From the same report",
                "why": f"arrived in the same intel report{f' ({title})' if title else ''} - "
                       "a curator grouped these deliberately",
                "total": _count(conn, where, params), "items": items[:limit],
                "pivot": {"kind": "report", "value": ioc["report_id"]},
            })

    actor = (ioc.get("actor") or "").strip()
    if actor:
        where = "actor = ? AND id != ?"
        params = (actor, ioc_id)
        items = _rows(conn, _SELECT + where + _ORDER, params + (fetch,), ioc_id)
        if items:
            groups.append({
                "key": "actor", "label": f"Attributed to {actor}",
                "why": f"the same adversary ({actor}) is named on both",
                "total": _count(conn, where, params), "items": items[:limit],
                "pivot": {"kind": "actor", "value": actor},
            })

    # The strongest link a bulk feed can give us, and until the family trails
    # landed no indicator in this store had one. A shared family says the two
    # values belong to the SAME named thing - the same loader, the same stealer,
    # the same C2 framework - which is what turns a domain into a piece of
    # infrastructure with a write-up behind it rather than a line on a blocklist.
    #
    # Placed above `host` because it is a claim about what the value IS, not
    # about where it happens to live: two names on one server can be unrelated
    # tenants, two Emotet C2s cannot.
    family = (ioc.get("malware_family") or "").strip().lower()
    if family:
        where = "malware_family = ? AND id != ?"
        params = (family, ioc_id)
        items = _rows(conn, _SELECT + where + _ORDER, params + (fetch,), ioc_id)
        if items:
            total = _count(conn, where, params)
            groups.append({
                "key": "malware", "label": f"{family.title()} infrastructure",
                # The count is the point. "One of 15,034 values this source
                # attributes to Emotet" is a different statement from "another
                # bad domain", and an analyst can act on the first.
                "why": f"the source lists both under the same malware family "
                       f"({family}) - {total + 1:,} values in this store carry it",
                "total": total, "items": items[:limit],
                "pivot": {"kind": "malware", "value": family},
            })

    host = _host_of_row(ioc)
    if host:
        # Both directions in one group: the URLs hosted on this domain, and - if
        # this IS a URL - the domain itself and its siblings.
        where = "(host = ? OR (type = 'domain' AND value = ?)) AND id != ?"
        params = (host, host, ioc_id)
        items = _rows(conn, _SELECT + where + _ORDER, params + (fetch,), ioc_id)
        if items:
            groups.append({
                "key": "host", "label": f"On {host}",
                "why": f"the same host ({host}) - a domain and what is served from it",
                "total": _count(conn, where, params), "items": items[:limit],
                "pivot": {"kind": "host", "value": host},
            })

        reg = registrable_domain(host)
        if reg and reg != host:
            # Indexed EQUALITY on the stored registrable domain. Expressed as
            # `host LIKE '%.x.test'` this is a leading wildcard no index can
            # serve - measured at 512 ms over 315k rows, on a query the drawer
            # runs every single time it opens.
            #
            # The exact host is excluded here rather than filtered afterwards,
            # so `total` counts siblings only. Filtering in Python would have
            # left URLs on the anchor host in both groups (their value is
            # `http://host/x`, not `host`) and inflated the count. COALESCE
            # because `host` is NULL on domain rows and NULL != ? is NULL, which
            # would silently drop every domain sibling.
            where = ("reg_domain = ? AND COALESCE(host,'') != ? "
                     "AND (type != 'domain' OR value != ?) AND id != ?")
            params = (reg, host, host, ioc_id)
            items = _rows(conn, _SELECT + where + _ORDER, params + (fetch,), ioc_id)[:limit]
            if items:
                groups.append({
                    "key": "sibling", "label": f"Siblings under {reg}",
                    "why": f"another name registered under {reg} - how phishing kits "
                           "and generated-domain clusters surface",
                    "total": _count(conn, where, params), "items": items,
                    "pivot": {"kind": "domain", "value": reg},
                })

    groups.extend(_resolution_group(conn, ioc, ioc_id, limit))
    groups.extend(_network_group(conn, ioc, ioc_id, limit))
    groups.extend(_subnet_group(conn, ioc, ioc_id, limit))
    return groups


# Adjacent address space. /24 for IPv4 because that is the smallest block
# routinely allocated to a single customer, so neighbours are usually the same
# tenant; /64 for IPv6 for the same reason (one LAN / one assignment).
_SUBNET_PREFIX = {8: (6, 24), 32: (16, 64)}     # hex key length -> (prefix hex chars, bits)


def _subnet_group(conn, ioc: dict, ioc_id: str, limit: int) -> list[dict]:
    """Other known-bad addresses in the same /24.

    The `network` group above is strictly better evidence - it knows who
    ANNOUNCES the range - but it needs the BGP table synced, and on a deployment
    that has never reached iptoasn it produces nothing at all. That leaves every
    IP indicator with no pivot whatsoever: measured on a 327,984-indicator store,
    68,457 IPs with `network` dead and no other group that applies to them.

    This needs nothing external. `ip_hex` is fixed-width, so "same /24" is a
    prefix, and a prefix on a fixed-width key is a BETWEEN the existing index
    serves - no decoding every address in Python.

    It is weaker evidence and says so: adjacency in a cloud provider's space
    means two unrelated tenants. What makes it worth showing anyway is that both
    ends are ALREADY known-bad, and the density is the actual finding - measured
    on the same store, 5,147 /24s hold more than one listed address and the
    densest hold 253 of 256, which is not a set of addresses to block but a
    subnet.
    """
    if (ioc.get("type") or "").lower() != "ip":
        return []
    key = ip_hex_of(str(ioc.get("value") or ""), "ip")
    if not key or len(key) not in _SUBNET_PREFIX:
        return []
    chars, bits = _SUBNET_PREFIX[len(key)]
    prefix = key[:chars]
    lo, hi = prefix + "0" * (len(key) - chars), prefix + "f" * (len(key) - chars)
    where = "ip_hex IS NOT NULL AND ip_hex BETWEEN ? AND ? AND id != ?"
    params = (lo, hi, ioc_id)
    items = _rows(conn, _SELECT + where + _ORDER, params + (limit + 1,), ioc_id)
    if not items:
        return []
    total = _count(conn, where, params)
    # The block in dotted form, for a label an analyst can paste into a firewall.
    if len(key) == 8:
        o = [int(prefix[i:i + 2], 16) for i in (0, 2, 4)]
        block = f"{o[0]}.{o[1]}.{o[2]}.0/{bits}"
        capacity = 256
    else:                                        # IPv6 /64
        block = ":".join(prefix[i:i + 4] for i in range(0, chars, 4)) + "::/64"
        capacity = None
    density = (f" - {total + 1} of {capacity} addresses in it are listed"
               if capacity and total + 1 > capacity // 8 else "")
    return [{
        "key": "subnet", "label": f"Same subnet - {block}",
        "why": f"another listed address in {block}{density}. Adjacency is weaker "
               "evidence than a shared AS - in cloud space neighbours can be "
               "unrelated tenants - but both ends are already known-bad, and a "
               "dense block is a subnet to act on rather than a list of hosts",
        "total": total, "items": items[:limit],
        "pivot": {"kind": "subnet", "value": block},
    }]


def _resolution_group(conn, ioc: dict, ioc_id: str, limit: int) -> list[dict]:
    """Indicators tied together by a resolution THIS deployment observed.

    The classic passive-DNS pivot, and the strongest kind of link here because it
    is our own observation rather than a third party's assertion. For an IP:
    every indicator whose name we saw resolving to it. For a domain/URL: every
    indicator sharing one of its observed addresses.

    Uses only what has already been recorded - it never resolves anything, so
    opening a drawer cannot turn into a burst of DNS traffic.
    """
    from dashboard_api import passive_dns

    itype = (ioc.get("type") or "").lower()
    value = str(ioc.get("value") or "")
    if itype == "ip":
        addresses = [value.strip()]
    else:
        host = _host_of_row(ioc)
        if not host:
            return []
        addresses = [o["address"] for o in passive_dns.for_name(conn, host)]
    if not addresses:
        return []

    names, seen_addr = [], []
    for addr in addresses[:8]:
        obs = passive_dns.for_address(conn, addr)
        if obs:
            seen_addr.append(addr)
        for o in obs:
            if o["name"] not in names:
                names.append(o["name"])
    if not names:
        return []

    # Match those names back onto indicators we actually hold: a resolution to a
    # name we have never seen as an indicator is real, but it is not a pivot to
    # anything in this store.
    ph = ",".join("?" * len(names[:_LOOKUP_CAP]))
    where = (f"(value IN ({ph}) OR host IN ({ph})) AND id != ?")
    params = tuple(names[:_LOOKUP_CAP]) * 2 + (ioc_id,)
    items = _rows(conn, _SELECT + where + _ORDER, params + (limit + 1,), ioc_id)
    if not items:
        return []
    where_label = ", ".join(seen_addr[:2]) or addresses[0]
    return [{
        "key": "resolution", "label": f"Resolved to {where_label}",
        "why": f"this deployment observed these names resolving to the same "
               f"address - our own observation, not a third party's claim",
        "total": _count(conn, where, params), "items": items[:limit],
        "pivot": {"kind": "address", "value": seen_addr[0] if seen_addr else addresses[0]},
    }]


# Names per resolution pivot fed into an IN (...) probe. Kept well under
# SQLite's 999-bind ceiling, doubled because the clause binds them twice.
_LOOKUP_CAP = 200


def _network_group(conn, ioc: dict, ioc_id: str, limit: int) -> list[dict]:
    """Everything we hold on the same autonomous system.

    Only produced when the BGP table has actually been synced - an unsynced
    deployment gets no group rather than an empty-looking "AS unknown" one. This
    is the pivot that separates one bulletproof host from 40 unrelated networks.
    """
    from dashboard_api import asn as asn_mod

    if (ioc.get("type") or "").lower() != "ip":
        return []
    st = asn_mod.status(conn)
    if not st["available"]:
        return []
    hit = asn_mod.lookup(conn, str(ioc.get("value") or ""))
    if not hit or hit.get("asn") is None:
        return []
    # The specific range this address sits in, not every range the AS announces:
    # the question is "what else is in THIS neighbourhood", and a large AS
    # announces thousands of prefixes.
    key = ip_hex_of(str(ioc.get("value") or ""), "ip")
    if not key:
        return []
    span = conn.execute(
        "SELECT start_hex, end_hex FROM asn_ranges WHERE family=? AND start_hex <= ? "
        "ORDER BY start_hex DESC LIMIT 1", (4 if len(key) == 8 else 6, key)).fetchone()
    if span is None or not (span["start_hex"] <= key <= span["end_hex"]):
        return []
    # Exact, and index-only: ip_hex is stored with the same encoding as
    # asn_ranges, so containment is a BETWEEN rather than decoding every address
    # in Python and guessing at the total from a truncated sample.
    where = "ip_hex IS NOT NULL AND ip_hex BETWEEN ? AND ? AND id != ?"
    params = (span["start_hex"], span["end_hex"], ioc_id)
    items = _rows(conn, _SELECT + where + _ORDER, params + (limit + 1,), ioc_id)
    if not items:
        return []
    org = hit["description"] or f"AS{hit['asn']}"
    return [{
        "key": "network", "label": f"Same network - AS{hit['asn']} {org}",
        "why": f"announced from the same range by AS{hit['asn']} ({org}) - shared "
               "infrastructure rather than a shared name",
        "total": _count(conn, where, params), "items": items[:limit],
        "pivot": {"kind": "asn", "value": str(hit["asn"])},
    }]
