"""Network ownership for an IP: which AS announces it, and from where.

An IP address on its own is barely intelligence. "203.0.113.7" tells an analyst
nothing; "203.0.113.7, announced by AS14061 DigitalOcean, US" tells them it is
cheap rented infrastructure, and "AS4134 CHINANET, CN" tells them something else
again. It is also the cheapest pivot in threat intel: everything else this
deployment knows about that same AS becomes reachable from any single indicator.

**This is a local dataset, not a per-query API.** iptoasn.com publishes the full
BGP-derived table as one hourly file
(<https://iptoasn.com/>, public domain / PDDL, no key, no rate limit). Proxying a
lookup service per indicator would be slower, would leak which indicators this
deployment is investigating to a third party, and would stop working the moment
the network did. Loading the table locally answers in microseconds, works
air-gapped once synced, and tells nobody what we looked up.

Addresses are stored as zero-padded lowercase hex - 8 characters for IPv4, 32 for
IPv6 - because that makes lexicographic comparison identical to numeric
comparison in both SQLite and Postgres. Storing them as integers would have
worked for IPv4 and silently overflowed for IPv6, whose addresses do not fit in
a 64-bit column.
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import logging

from dashboard_api.db import get_conn

log = logging.getLogger(__name__)

# The combined (IPv4 + IPv6) table. Ranges are inclusive and non-overlapping,
# with unannounced space present as AS0 rows - which we drop, since "not
# announced" is not ownership information.
DATASET_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

# Refresh cadence. The upstream file is rebuilt hourly, but AS allocations move
# on a scale of days, so pulling it hourly would be a lot of bandwidth for
# almost no change. Overridable for operators who want it fresher.
SYNC_INTERVAL_HOURS = 24

# Rows per executemany. The combined table is ~700k rows; inserting it as one
# statement would hold the write lock for the whole load and spike memory.
_BATCH = 20_000

# The upstream file is ~10 MB gzipped / ~90 MB raw today. The cap is generous
# enough for years of growth but still bounded, so a hostile or broken mirror
# cannot stream us to death.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024

# How long to wait after a FAILED refresh before trying again. Without this the
# scheduler would re-attempt a ~90 MB download on every tick for as long as the
# network was down, because an unsynced table is never "fresh" and so never
# skips - the freshness check alone only paces the success path.
RETRY_INTERVAL_MINUTES = 15

_SETTING_SYNCED = "asn_last_synced"
_SETTING_COUNT = "asn_range_count"
_SETTING_ATTEMPT = "asn_last_attempt"


def hex_key(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Zero-padded hex, wide enough that lexicographic order == numeric order."""
    width = 8 if ip.version == 4 else 32
    return format(int(ip), "0%dx" % width)


def _parse_line(line: str) -> tuple | None:
    """One iptoasn row -> an insertable tuple, or None if it carries no ownership.

    Format is `range_start \t range_end \t AS_number \t country_code \t AS_description`.
    """
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 5:
        return None
    start_s, end_s, asn_s, country, desc = parts[0], parts[1], parts[2], parts[3], parts[4]
    try:
        asn = int(asn_s)
    except ValueError:
        return None
    # AS0 is iptoasn's marker for space that is allocated but not announced.
    # Keeping those rows would turn "we know nothing about this IP" into a
    # confident-looking record owned by "Not routed".
    if asn == 0:
        return None
    try:
        start = ipaddress.ip_address(start_s)
        end = ipaddress.ip_address(end_s)
    except ValueError:
        return None
    if start.version != end.version:
        return None
    return (start.version, hex_key(start), hex_key(end), asn,
            (country or "").strip().upper()[:2] or None, (desc or "").strip()[:200] or None)


def parse_dataset(raw: bytes | str):
    """Yield insertable rows from the (already decompressed) TSV.

    Malformed lines are skipped rather than aborting the load: this is a
    third-party file refreshed hourly, and discarding 700,000 good rows because
    one is broken is the wrong trade.
    """
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        row = _parse_line(line)
        if row is not None:
            yield row


def load_rows(conn, rows) -> int:
    """Replace the table with `rows`. Returns how many were stored.

    Replace, not merge: the upstream file is a complete snapshot, and merging
    would leave withdrawn allocations behind forever, so an IP that changed hands
    would match two owners and the query would return whichever sorted first.
    """
    batch, total = [], 0
    conn.execute("DELETE FROM asn_ranges")
    for row in rows:
        batch.append(row)
        if len(batch) >= _BATCH:
            conn.executemany(
                "INSERT INTO asn_ranges (family,start_hex,end_hex,asn,country,description) "
                "VALUES (?,?,?,?,?,?)", batch)
            total += len(batch)
            batch = []
    if batch:
        conn.executemany(
            "INSERT INTO asn_ranges (family,start_hex,end_hex,asn,country,description) "
            "VALUES (?,?,?,?,?,?)", batch)
        total += len(batch)
    return total


def lookup(conn, value: str) -> dict | None:
    """Which AS announces `value`. None when it is not an IP, or not announced.

    The query finds the last range that STARTS at or before the address and
    checks the address is inside it. `ORDER BY start_hex DESC LIMIT 1` over the
    (family, start_hex) index makes this an index seek rather than a scan of
    700k rows.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # Private/loopback/link-local space is not in any public BGP table; saying
    # so is more useful than an empty result the caller has to interpret.
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return {"asn": None, "country": None, "description": None,
                "note": "private or reserved address - not announced in public BGP"}
    key = hex_key(ip)
    row = conn.execute(
        "SELECT asn, country, description, start_hex, end_hex FROM asn_ranges "
        "WHERE family=? AND start_hex <= ? ORDER BY start_hex DESC LIMIT 1",
        (ip.version, key)).fetchone()
    if row is None or not (row["start_hex"] <= key <= row["end_hex"]):
        return None
    return {"asn": row["asn"], "country": row["country"],
            "description": row["description"], "note": None}


def status(conn) -> dict:
    """What the local table holds, for the UI. Never guesses: an unsynced
    deployment reports zero rows and no timestamp rather than an empty AS."""
    rows = conn.execute(
        "SELECT key, value FROM settings WHERE key IN (?,?,?)",
        (_SETTING_SYNCED, _SETTING_COUNT, _SETTING_ATTEMPT)).fetchall()
    got = {r["key"]: r["value"] for r in rows}
    count = int(got.get(_SETTING_COUNT) or 0)
    return {"synced": got.get(_SETTING_SYNCED), "ranges": count,
            "lastAttempt": got.get(_SETTING_ATTEMPT),
            "available": count > 0, "source": DATASET_URL}


def _record_sync(conn, count: int, when: str):
    for key, val in ((_SETTING_SYNCED, when), (_SETTING_COUNT, str(count))):
        conn.execute("INSERT INTO settings (key,value) VALUES (?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=?", (key, val, val))


def fetch_dataset() -> bytes:
    """Download and decompress the upstream table. Raises on any failure -
    callers record the error; nothing is ever substituted for missing data."""
    from dashboard_api.connectors import _read_capped

    body = _read_capped("GET", DATASET_URL, headers={}, params={},
                        truncate_at=MAX_DOWNLOAD_BYTES)
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    # gzip by URL, but tolerate a mirror that already decompressed it rather
    # than failing on a file we could actually read.
    if body[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as fh:
            return fh.read()
    return body


def sync(conn, *, force: bool = False) -> dict:
    """Refresh the local table if it is stale. Returns what happened.

    Skipping when fresh is what makes this safe to call from a scheduler tick:
    the cadence lives here rather than in every caller.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    st = status(conn)
    if not force and st["synced"] and st["ranges"]:
        try:
            age = now - datetime.fromisoformat(st["synced"])
            if age < timedelta(hours=SYNC_INTERVAL_HOURS):
                return {"skipped": "fresh", "ranges": st["ranges"], "synced": st["synced"]}
        except ValueError:
            pass                                  # unparseable timestamp -> resync
    # Back off after a failed attempt. The freshness check above only paces the
    # SUCCESS path: with no table at all, every tick would otherwise re-attempt
    # the download for as long as the network stayed down.
    if not force and st.get("lastAttempt"):
        try:
            if now - datetime.fromisoformat(st["lastAttempt"]) < timedelta(
                    minutes=RETRY_INTERVAL_MINUTES):
                return {"skipped": "backoff", "ranges": st["ranges"],
                        "lastAttempt": st["lastAttempt"]}
        except ValueError:
            pass
    # Recorded BEFORE the download, so a fetch that hangs or crashes the process
    # still counts as an attempt and cannot become a hot retry loop.
    conn.execute("INSERT INTO settings (key,value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=?",
                 (_SETTING_ATTEMPT, now.replace(microsecond=0).isoformat(),
                  now.replace(microsecond=0).isoformat()))
    conn.commit()
    raw = fetch_dataset()
    count = load_rows(conn, parse_dataset(raw))
    when = now.replace(microsecond=0).isoformat()
    _record_sync(conn, count, when)
    log.info("ASN table synced: %d ranges", count)
    return {"ranges": count, "synced": when}


def sync_if_due() -> dict:
    """Scheduler entry point. Never raises: a failed refresh must not take the
    tick down, and a stale table still answers lookups."""
    try:
        with get_conn() as conn:
            res = sync(conn)
            conn.commit()
        return res
    except Exception as e:                         # noqa: BLE001
        log.warning("ASN table refresh failed (%s); keeping the existing table",
                    e.__class__.__name__)
        return {"error": str(e)[:200]}
