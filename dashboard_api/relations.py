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

    groups.extend(_network_group(conn, ioc, ioc_id, limit))
    return groups


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
