"""IOC lifecycle — confidence decay, sightings, known-good, expiry.

Threat indicators are not static: a malicious IP this week is often reassigned
next month, while a malware hash stays bad for years. This module models that:

  * **Decay** — the *effective* confidence of an indicator falls off from its
    asserted confidence as it ages since it was last seen, at a per-type
    half-life (IPs decay fast, hashes slowly). `confidence` stays the asserted
    value; `effective_confidence()` is the decayed, presentational figure.
  * **Expiry** — when effective confidence drops below a floor (or age exceeds
    a hard ceiling), the indicator is marked `expired` and stops matching, so
    stale intel can't raise alerts.
  * **Sightings** — every fresh observation (a SIEM event matching the IOC, a
    connector re-import, a manual confirmation) is recorded in `ioc_sightings`,
    bumps the sighting count, refreshes `last_seen`, nudges asserted confidence
    back up, and reactivates an expired indicator.
  * **Known-good** — an analyst can whitelist an indicator; it never matches
    and reads back as benign, regardless of confidence.
"""
import uuid
from datetime import datetime, timezone

# Per-type confidence half-life in days (how fast effective confidence decays).
DECAY_HALFLIFE_DAYS = {
    "ip": 14, "url": 21, "domain": 45, "email": 60,
    "hash": 180, "sha256": 180, "md5": 180, "sha1": 180, "cve": 365,
}
DEFAULT_HALFLIFE = 30
EXPIRY_FLOOR = 15          # effective confidence below this → expired
MAX_AGE_HALFLIVES = 4      # age beyond this many half-lives → expired regardless
SIGHTING_BOOST = 8         # asserted-confidence bump per fresh sighting
CONFIDENCE_CAP = 100


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse(ts) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def age_days(last_seen, now: datetime | None = None) -> float:
    now = now or datetime.now(timezone.utc)
    dt = _parse(last_seen)
    if dt is None:
        return 0.0
    return max(0.0, (now - dt).total_seconds() / 86400.0)


def half_life(ioc_type: str | None) -> int:
    return DECAY_HALFLIFE_DAYS.get((ioc_type or "").lower(), DEFAULT_HALFLIFE)


def effective_confidence(confidence: int, last_seen, ioc_type: str | None,
                         now: datetime | None = None) -> int:
    """Asserted confidence decayed by age since last seen (half-life per type)."""
    hl = half_life(ioc_type)
    age = age_days(last_seen, now)
    factor = 0.5 ** (age / hl) if hl > 0 else 1.0
    return max(0, round((confidence or 0) * factor))


def lifecycle_of(ioc: dict, now: datetime | None = None) -> dict:
    """Presentational lifecycle block for an IOC row."""
    eff = effective_confidence(ioc.get("confidence", 0), ioc.get("last_seen"),
                               ioc.get("type"), now)
    hl = half_life(ioc.get("type"))
    age = age_days(ioc.get("last_seen"), now)
    status = ioc.get("status") or "active"
    if status != "known-good":
        status = "expired" if (eff < EXPIRY_FLOOR or age > hl * MAX_AGE_HALFLIVES) else "active"
    return {
        "effectiveConfidence": eff,
        "assertedConfidence": ioc.get("confidence", 0),
        "ageDays": round(age, 1),
        "halfLifeDays": hl,
        "sightings": ioc.get("sightings", 1),
        "status": status,
        "expiresInDays": _expires_in_days(ioc.get("confidence", 0), age, hl),
    }


def _expires_in_days(confidence: int, age: float, hl: int) -> float | None:
    """Days until effective confidence reaches the expiry floor (None if already)."""
    if not confidence or confidence <= EXPIRY_FLOOR:
        return 0.0
    import math
    # confidence * 0.5^(t/hl) = FLOOR  →  t = hl * log2(confidence/FLOOR)
    t_floor = hl * math.log2(confidence / EXPIRY_FLOOR)
    remaining = min(t_floor, hl * MAX_AGE_HALFLIVES) - age
    return round(max(0.0, remaining), 1)


def decay_iocs(conn, now: datetime | None = None) -> dict:
    """Recompute lifecycle status across the store: expire decayed indicators,
    reactivate ones a sighting has refreshed. Known-good is left untouched.
    Returns {scanned, expired, reactivated}."""
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT id, type, confidence, last_seen, status FROM iocs "
        "WHERE status != 'known-good'").fetchall()
    expired = reactivated = 0
    for r in rows:
        eff = effective_confidence(r["confidence"], r["last_seen"], r["type"], now)
        age = age_days(r["last_seen"], now)
        should_expire = eff < EXPIRY_FLOOR or age > half_life(r["type"]) * MAX_AGE_HALFLIVES
        target = "expired" if should_expire else "active"
        if target != r["status"]:
            conn.execute("UPDATE iocs SET status=? WHERE id=?", (target, r["id"]))
            if target == "expired":
                expired += 1
            else:
                reactivated += 1
    return {"scanned": len(rows), "expired": expired, "reactivated": reactivated}


def record_sighting(conn, *, ioc_id: str | None = None, value: str | None = None,
                    source: str = "manual", context: str | None = None,
                    boost: int = SIGHTING_BOOST) -> dict | None:
    """Record a fresh observation of an indicator: append to ioc_sightings,
    bump the count, refresh last_seen, nudge asserted confidence up, and
    reactivate if it had expired (known-good stays known-good). Returns the
    updated IOC row, or None if not found."""
    if ioc_id:
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
    elif value:
        row = conn.execute("SELECT * FROM iocs WHERE value=?", (value,)).fetchone()
    else:
        return None
    if not row:
        return None
    now = _now()
    conn.execute(
        "INSERT INTO ioc_sightings (id,ioc_id,ts,source,context) VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), row["id"], now, source, (context or "")[:500]))
    new_conf = min(CONFIDENCE_CAP, (row["confidence"] or 0) + boost)
    keep_known_good = row["status"] == "known-good"
    conn.execute(
        "UPDATE iocs SET sightings=sightings+1, last_seen=?, confidence=?, "
        "status=CASE WHEN status='known-good' THEN 'known-good' ELSE 'active' END WHERE id=?",
        (now, new_conf, row["id"]))
    updated = conn.execute("SELECT * FROM iocs WHERE id=?", (row["id"],)).fetchone()
    return dict(updated) if updated else None


def set_known_good(conn, ioc_id: str, known_good: bool) -> bool:
    """Whitelist (or un-whitelist) an indicator. Returns False if not found."""
    if known_good:
        cur = conn.execute("UPDATE iocs SET status='known-good' WHERE id=?", (ioc_id,))
    else:
        cur = conn.execute(
            "UPDATE iocs SET status='active' WHERE id=? AND status='known-good'", (ioc_id,))
        if cur.rowcount == 0:
            cur = conn.execute("UPDATE iocs SET status='active' WHERE id=?", (ioc_id,))
    return cur.rowcount > 0
