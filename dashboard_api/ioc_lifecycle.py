"""IOC lifecycle - confidence decay, sightings, known-good, expiry.

Threat indicators are not static: a malicious IP this week is often reassigned
next month, while a malware hash stays bad for years. This module models that:

  * **Decay** - the *effective* confidence of an indicator falls off from its
    asserted confidence as it ages since it was last seen, at a per-type
    half-life (IPs decay fast, hashes slowly). `confidence` stays the asserted
    value; `effective_confidence()` is the decayed, presentational figure.
  * **Expiry** - when effective confidence drops below a floor (or age exceeds
    a hard ceiling), the indicator is marked `expired` and stops matching, so
    stale intel can't raise alerts.
  * **Sightings** - every fresh observation (a SIEM event matching the IOC, a
    connector re-import, a manual confirmation) is recorded in `ioc_sightings`,
    bumps the sighting count, refreshes `last_seen`, nudges asserted confidence
    back up, and reactivates an expired indicator.
  * **Known-good** - an analyst can whitelist an indicator; it never matches
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


def half_life(ioc_type: str | None, rule: dict | None = None) -> int:
    """Half-life for a type. `rule` wins when the caller has already looked it up.

    The constants remain the fallback, and the seeded records hold exactly these
    numbers - so a deployment that has not been tuned decays identically whether
    the rule table is reachable or not.
    """
    if rule:
        return rule.get("halfLifeDays") or DEFAULT_HALFLIFE
    return DECAY_HALFLIFE_DAYS.get((ioc_type or "").lower(), DEFAULT_HALFLIFE)


def effective_confidence(confidence: int, last_seen, ioc_type: str | None,
                         now: datetime | None = None, rule: dict | None = None) -> int:
    """Asserted confidence decayed by age since last seen (half-life per type).

    `rule` is the decay record when the caller already has it. Deliberately NOT
    looked up here: this is called once per indicator, and the decay pass makes
    315k of those - a rule query per call would turn a 24-second maintenance job
    into an outage. Callers in a loop resolve the rule once and pass it down.
    """
    hl = half_life(ioc_type, rule)
    age = age_days(last_seen, now)
    factor = 0.5 ** (age / hl) if hl > 0 else 1.0
    return max(0, round((confidence or 0) * factor))


def lifecycle_of(ioc: dict, now: datetime | None = None, rule: dict | None = None) -> dict:
    """Presentational lifecycle block for an IOC row.

    `rule` is the governing decay record when the caller has it. Without one this
    falls back to the constants, which the seeded rules match exactly - so the
    numbers an analyst sees never depend on whether the lookup happened.
    """
    conf = ioc.get("confidence", 0)
    eff = effective_confidence(conf, ioc.get("last_seen"), ioc.get("type"), now, rule)
    hl = half_life(ioc.get("type"), rule)
    revoke = rule["revokeScore"] if rule else EXPIRY_FLOOR
    ceiling = (rule["maxAgeHalfLives"] if rule else MAX_AGE_HALFLIVES)
    age = age_days(ioc.get("last_seen"), now)
    status = ioc.get("status") or "active"
    if status != "known-good":
        status = "expired" if (eff < revoke or age > hl * ceiling) else "active"
    out = {
        "effectiveConfidence": eff,
        "assertedConfidence": conf,
        "ageDays": round(age, 1),
        "halfLifeDays": hl,
        "sightings": ioc.get("sightings", 1),
        "status": status,
        "expiresInDays": _expires_in_days(conf, age, hl, revoke, ceiling),
        "revokeScore": revoke,
    }
    if rule:
        # The policy that governs this indicator, named. "Expires in 12 days" is
        # a fact an analyst cannot argue with; "expires in 12 days under the
        # 14-day IP rule" is one they can go and change.
        from dashboard_api import decay as decay_mod
        out["rule"] = {"id": rule["id"], "name": rule["name"]}
        out["validUntil"] = ioc.get("valid_until") or decay_mod.valid_until(
            conf, ioc.get("last_seen"), rule)
        out["nextReaction"] = decay_mod.next_reaction(conf, age, rule)
    return out


def _expires_in_days(confidence: int, age: float, hl: int,
                     revoke: int = EXPIRY_FLOOR,
                     ceiling: int = MAX_AGE_HALFLIVES) -> float | None:
    """Days until effective confidence reaches the revoke score (0 if already)."""
    if not confidence or confidence <= revoke:
        return 0.0
    import math
    # confidence * 0.5^(t/hl) = revoke  →  t = hl * log2(confidence/revoke)
    t_floor = hl * math.log2(confidence / revoke)
    remaining = min(t_floor, hl * ceiling) - age
    return round(max(0.0, remaining), 1)


def decay_iocs(conn, now: datetime | None = None) -> dict:
    """Recompute lifecycle status across the store: expire decayed indicators,
    reactivate ones a sighting has refreshed. Known-good is left untouched.
    Returns {scanned, expired, reactivated}."""
    from dashboard_api.intel_scoring import DEFAULT_RELIABILITY, score_indicator

    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT id, type, value, confidence, last_seen, status, sightings, "
        "source, actor, report_id, intel_score, valid_until FROM iocs "
        "WHERE status != 'known-good'").fetchall()

    # Corroboration and reliability for the whole pass, read once rather than
    # per row: at 315k indicators a query per row is the difference between a
    # maintenance job and an outage.
    #
    # MIN(reliability) is the BEST grade asserting the value ("A" < "B" < ...),
    # which is what the API scores with. Persisting a score computed from a
    # different grade would mean sorting by one number and displaying another.
    corr = {r["value"]: (r["n"], r["g"]) for r in conn.execute(
        "SELECT o.value AS value, COUNT(*) AS n, MIN(COALESCE(s.reliability,?)) AS g "
        "FROM observable_sources o LEFT JOIN intel_sources s ON s.id = o.source_id "
        "GROUP BY o.value", (DEFAULT_RELIABILITY,)).fetchall()}
    grades = {r["id"]: r["reliability"] for r in conn.execute(
        "SELECT id, reliability FROM intel_sources").fetchall()}

    # Decay rules resolved ONCE per indicator type, not per row. There are a
    # handful of types and 315k rows; the ratio is the whole reason this is a
    # maintenance job rather than an outage.
    from dashboard_api import decay as decay_mod
    rule_cache: dict[str, dict] = {}

    def rule_of(t):
        key = (t or "").lower()
        if key not in rule_cache:
            rule_cache[key] = decay_mod.rule_for(conn, key)
        return rule_cache[key]

    expired = reactivated = rescored = 0
    status_updates, score_updates, valid_updates = [], [], []
    for r in rows:
        rule = rule_of(r["type"])
        eff = effective_confidence(r["confidence"], r["last_seen"], r["type"], now, rule)
        age = age_days(r["last_seen"], now)
        should_expire = (eff < rule["revokeScore"]
                         or age > rule["halfLifeDays"] * rule["maxAgeHalfLives"])
        target = "expired" if should_expire else "active"
        # Stored so "what expires this week?" is an indexed range scan instead of
        # a decay computation over the whole store.
        vu = decay_mod.valid_until(r["confidence"], r["last_seen"], rule)
        if vu != r["valid_until"]:
            valid_updates.append((vu, r["id"]))
        if target != r["status"]:
            status_updates.append((target, r["id"]))
            if target == "expired":
                expired += 1
            else:
                reactivated += 1
        # The score decays with the indicator and moves as new sources
        # corroborate it, so this pass is also where it is kept honest.
        row = dict(r)
        n, best = corr.get(r["value"], (1, None))
        own = grades.get(r["source"] or "")
        if own and (best is None or own < best):
            best = own
        fresh = score_indicator(
            row, source_count=n, reliability=best or DEFAULT_RELIABILITY,
            local_sightings=max(0, (r["sightings"] or 1) - 1), now=now)["score"]
        if fresh != (r["intel_score"] or 0):
            score_updates.append((fresh, r["id"]))
            rescored += 1
    if status_updates:
        conn.executemany("UPDATE iocs SET status=? WHERE id=?", status_updates)
    if score_updates:
        conn.executemany("UPDATE iocs SET intel_score=? WHERE id=?", score_updates)
    if valid_updates:
        conn.executemany("UPDATE iocs SET valid_until=? WHERE id=?", valid_updates)
    return {"scanned": len(rows), "expired": expired, "reactivated": reactivated,
            "rescored": rescored, "dated": len(valid_updates)}


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
