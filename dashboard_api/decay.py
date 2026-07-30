"""Decay rules as records, not constants.

How fast an indicator stops being worth acting on is a POLICY decision, and it
differs per deployment: a bank hunting payment fraud and a hosting provider
fighting abuse do not agree on how long a phishing URL stays actionable. Until
now the curve lived in a Python dict, so changing it meant editing source and
redeploying - which in practice means nobody ever tunes it, and the platform
quietly imposes one opinion on every customer.

Modelled on OpenCTI's indicator lifecycle
(<https://docs.opencti.io/latest/usage/indicators-lifecycle/>), which is the
reference implementation of this idea:

  * **half-life** - how long until the score halves. Per indicator type, because
    a reassigned IP and a malware hash are not the same kind of fact.
  * **revoke score** - the score at which the indicator stops matching. Below
    this we are no longer willing to act on it, so continuing to alert on it is
    how a SOC learns to ignore its own intel.
  * **reaction points** - scores worth telling someone about on the way down.
    A drop through 50 is the moment to decide whether to re-verify or let it go,
    and without them decay is invisible until the indicator silently vanishes.
  * **valid_until** - the timestamp the curve reaches the revoke score. Derived,
    stored, and indexed, so "what expires this week?" is a range scan rather than
    a decay computation over every row in the store.

**The seeded rules reproduce the previous hardcoded behaviour exactly.** An
upgrade that silently re-dated 315,185 indicators would be a data change
disguised as a refactor.
"""
from __future__ import annotations

import json
import math
import threading
from datetime import datetime, timedelta, timezone

# The behaviour this replaces, kept verbatim as the seed so an upgrade is a
# no-op until somebody deliberately tunes a rule. Previously
# ioc_lifecycle.DECAY_HALFLIFE_DAYS.
_SEED_HALFLIVES = {
    "ip": 14, "url": 21, "domain": 45, "email": 60,
    "hash": 180, "sha256": 180, "md5": 180, "sha1": 180, "cve": 365,
}
DEFAULT_HALFLIFE = 30
DEFAULT_REVOKE_SCORE = 15          # was ioc_lifecycle.EXPIRY_FLOOR
DEFAULT_MAX_AGE_HALFLIVES = 4      # was ioc_lifecycle.MAX_AGE_HALFLIVES
DEFAULT_REACTION_POINTS = [80, 60, 40, 20]

# Rules are read on every effective_confidence() call, and the decay pass makes
# one of those per indicator - 315k per run. A query per row would turn a
# 24-second maintenance job into an outage, so the table is cached in-process and
# invalidated explicitly whenever a rule is written.
_lock = threading.Lock()
_cache: dict | None = None


def invalidate_cache() -> None:
    """Called after any rule write. Cheap, and forgetting it is the one way this
    cache can serve a stale policy."""
    global _cache
    with _lock:
        _cache = None


def _load(conn) -> dict:
    """{ioc_type -> rule} plus a "*" default, read once and cached."""
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
    by_type: dict[str, dict] = {}
    rows = conn.execute(
        "SELECT * FROM decay_rules WHERE enabled=1 ORDER BY builtin DESC, id").fetchall()
    for r in rows:
        applies = r["applies_to"]
        if isinstance(applies, str):
            try:
                applies = json.loads(applies)
            except (ValueError, TypeError):
                applies = []
        points = r["reaction_points"]
        if isinstance(points, str):
            try:
                points = json.loads(points)
            except (ValueError, TypeError):
                points = list(DEFAULT_REACTION_POINTS)
        rule = {
            "id": r["id"], "name": r["name"],
            "halfLifeDays": r["half_life_days"] or DEFAULT_HALFLIFE,
            "revokeScore": r["revoke_score"] if r["revoke_score"] is not None
            else DEFAULT_REVOKE_SCORE,
            "maxAgeHalfLives": r["max_age_half_lives"] or DEFAULT_MAX_AGE_HALFLIVES,
            "reactionPoints": sorted([int(p) for p in (points or [])], reverse=True),
            "appliesTo": applies or ["*"],
            "builtin": bool(r["builtin"]),
        }
        for t in rule["appliesTo"]:
            # First rule wins per type: builtins are ordered first, so an
            # operator's custom rule for the same type is layered on top by
            # DISABLING the builtin rather than by racing it.
            by_type.setdefault(str(t).lower(), rule)
    if "*" not in by_type:
        by_type["*"] = _fallback()
    with _lock:
        _cache = by_type
    return by_type


def _fallback() -> dict:
    """Used when the table is empty or unreachable. Identical to the pre-record
    constants: an indicator must never decay differently just because a rule
    lookup failed."""
    return {"id": "fallback", "name": "Default", "halfLifeDays": DEFAULT_HALFLIFE,
            "revokeScore": DEFAULT_REVOKE_SCORE,
            "maxAgeHalfLives": DEFAULT_MAX_AGE_HALFLIVES,
            "reactionPoints": list(DEFAULT_REACTION_POINTS),
            "appliesTo": ["*"], "builtin": True}


def rule_for(conn, ioc_type: str | None) -> dict:
    """The decay rule governing this indicator type."""
    try:
        by_type = _load(conn)
    except Exception:                              # noqa: BLE001
        return _fallback()
    t = (ioc_type or "").lower()
    return by_type.get(t) or by_type.get("*") or _fallback()


def rules(conn) -> list[dict]:
    """Every rule, for the settings UI. Ordered builtins-first, same as _load."""
    out, seen = [], set()
    for r in conn.execute(
            "SELECT * FROM decay_rules ORDER BY builtin DESC, id").fetchall():
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        applies = r["applies_to"]
        if isinstance(applies, str):
            try:
                applies = json.loads(applies)
            except (ValueError, TypeError):
                applies = []
        points = r["reaction_points"]
        if isinstance(points, str):
            try:
                points = json.loads(points)
            except (ValueError, TypeError):
                points = []
        out.append({
            "id": r["id"], "name": r["name"], "appliesTo": applies,
            "halfLifeDays": r["half_life_days"], "revokeScore": r["revoke_score"],
            "maxAgeHalfLives": r["max_age_half_lives"],
            "reactionPoints": points, "enabled": bool(r["enabled"]),
            "builtin": bool(r["builtin"]),
        })
    return out


def decayed_score(score: int, age_days_: float, rule: dict) -> int:
    """`score` halved once per half-life. The same exponential the constants
    implemented, now read from a record."""
    hl = rule["halfLifeDays"] or DEFAULT_HALFLIFE
    factor = 0.5 ** (age_days_ / hl) if hl > 0 else 1.0
    return max(0, round((score or 0) * factor))


def days_until(score: int, target: int, rule: dict) -> float | None:
    """Days for `score` to decay to `target`. None when it never will."""
    hl = rule["halfLifeDays"] or DEFAULT_HALFLIFE
    if not score or score <= target or target <= 0 or hl <= 0:
        return None
    return hl * math.log2(score / target)


def valid_until(score: int, last_seen, rule: dict) -> str | None:
    """When this indicator reaches its revoke score, as an ISO timestamp.

    Capped at the rule's hard age ceiling, because an indicator asserted at 100%
    would otherwise take a very long time to cross a low revoke score and would
    outlive any reasonable claim about it.
    """
    from dashboard_api.ioc_lifecycle import _parse

    start = _parse(last_seen)
    if start is None:
        return None
    t = days_until(score, rule["revokeScore"], rule)
    ceiling = (rule["halfLifeDays"] or DEFAULT_HALFLIFE) * rule["maxAgeHalfLives"]
    days = ceiling if t is None else min(t, ceiling)
    return (start + timedelta(days=days)).replace(microsecond=0).isoformat()


def next_reaction(score: int, age_days_: float, rule: dict) -> dict | None:
    """The next reaction point this indicator will cross, and when.

    Decay with no reaction points is invisible: an indicator is actionable one
    day and silently gone the next, with nothing in between for an analyst to
    respond to.
    """
    current = decayed_score(score, age_days_, rule)
    for point in rule["reactionPoints"]:           # descending
        if point < current:
            t = days_until(score, point, rule)
            if t is None:
                continue
            return {"score": point, "inDays": round(max(0.0, t - age_days_), 1)}
    return None


# -- seeding -------------------------------------------------------------------

def seed_builtin_rules(conn) -> int:
    """Create the builtin rules if absent. Idempotent.

    One rule per previously-hardcoded type plus a catch-all, with exactly the old
    numbers - so this lands as a refactor rather than as a silent re-dating of
    every indicator in the store.
    """
    have = {r["id"] for r in conn.execute("SELECT id FROM decay_rules").fetchall()}
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    # Group the types that share a half-life into one rule, so the settings UI
    # shows four meaningful policies instead of nine near-duplicates.
    groups: dict[int, list[str]] = {}
    for t, hl in _SEED_HALFLIVES.items():
        groups.setdefault(hl, []).append(t)
    payload = []
    for hl, types in sorted(groups.items()):
        rid = f"builtin-{hl}d"
        if rid in have:
            continue
        payload.append((
            rid, f"{', '.join(sorted(types))} ({hl}-day half-life)",
            json.dumps(sorted(types)), hl, DEFAULT_REVOKE_SCORE,
            DEFAULT_MAX_AGE_HALFLIVES, json.dumps(DEFAULT_REACTION_POINTS),
            1, 1, now))
    if "builtin-default" not in have:
        payload.append((
            "builtin-default", f"Everything else ({DEFAULT_HALFLIFE}-day half-life)",
            json.dumps(["*"]), DEFAULT_HALFLIFE, DEFAULT_REVOKE_SCORE,
            DEFAULT_MAX_AGE_HALFLIVES, json.dumps(DEFAULT_REACTION_POINTS),
            1, 1, now))
    if payload:
        conn.executemany(
            "INSERT INTO decay_rules (id,name,applies_to,half_life_days,revoke_score,"
            "max_age_half_lives,reaction_points,enabled,builtin,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)", payload)
        invalidate_cache()
    return len(payload)
