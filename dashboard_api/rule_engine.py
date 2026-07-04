"""Detection rule engine.

A rule is a real, evaluable query over the raw `events` stream:

  definition = {
    "conditions": [{"field": "event_type", "op": "equals", "value": "failed_login"}],
    "logic": "and",                                   # and | or
    "aggregation": {"groupBy": "src_ip", "threshold": 20, "windowMinutes": 5},  # optional
    "throttleMinutes": 10                             # optional, non-aggregated rules
  }

Without aggregation, every matching event raises an alert (throttled per
group so a noisy source can't flood). With aggregation, a group whose matching
event count reaches the threshold inside the window raises one alert - this is
how brute-force/beaconing style detections work.

`evaluate()` is pure: given a rule + events it returns matches; the caller
decides whether to persist alerts (live detection) or just preview (backtest).
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone

FIELDS = ["event_type", "category", "src_ip", "dest_ip", "dest_port", "username",
          "hostname", "process_name", "action", "country", "bytes_out", "severity_hint",
          "mitre_tech_id", "raw"]
OPERATORS = ["equals", "not_equals", "contains", "in", "gt", "lt", "gte", "lte", "regex", "cidr"]

# Elastic Common Schema (ECS) field aliases → ThreatOrbit's native event fields.
# This makes detection rules and searches vendor-neutral: an analyst can write
# `source.ip` / `user.name` / `destination.port` and it resolves to the stored
# field, so rules ported from Elastic/Splunk content work unchanged.
ECS_ALIASES = {
    "source.ip": "src_ip",
    "source.address": "src_ip",
    "client.ip": "src_ip",
    "destination.ip": "dest_ip",
    "server.ip": "dest_ip",
    "destination.port": "dest_port",
    "user.name": "username",
    "user.id": "username",
    "host.name": "hostname",
    "host.hostname": "hostname",
    "observer.hostname": "hostname",
    "process.name": "process_name",
    "process.executable": "process_name",
    "event.action": "action",
    "event.category": "category",
    "event.type": "event_type",
    "event.kind": "event_type",
    "network.bytes": "bytes_out",
    "source.bytes": "bytes_out",
    "destination.bytes": "bytes_out",
    "source.geo.country_name": "country",
    "threat.technique.id": "mitre_tech_id",
    "message": "raw",
    "event.original": "raw",
}

# Every field name a rule/search may legitimately reference (native + ECS).
ALL_FIELDS = FIELDS + sorted(ECS_ALIASES)


def canonical_field(field: str | None) -> str | None:
    """Resolve an ECS field alias to the native event field (identity otherwise)."""
    if field is None:
        return None
    return ECS_ALIASES.get(field, field)


def suppression_active(s: dict, now: datetime | None = None) -> bool:
    """Whether a suppression applies right now.

    Two independent time boxes (both optional, both must pass):
      * `expires_at` - absolute ISO expiry; NULL/empty means permanent.
      * `window_start`/`window_end` - a recurring daily HH:MM UTC window
        (e.g. a 02:00-04:00 maintenance window); supports overnight wrap
        (22:00-06:00). Only consulted when both ends are set.
    """
    now = now or datetime.now(timezone.utc)
    exp = s.get("expires_at")
    if exp:
        try:
            if now >= datetime.fromisoformat(str(exp)):
                return False
        except (ValueError, TypeError):
            pass  # unparseable expiry never deactivates a rule silently
    start, end = s.get("window_start"), s.get("window_end")
    if start and end:
        hhmm = now.strftime("%H:%M")
        if start <= end:  # same-day window
            return start <= hhmm < end
        return hhmm >= start or hhmm < end  # overnight wrap
    return True


def _coerce_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ── ReDoS guard ──────────────────────────────────────────────────────────────
# Detection rules accept analyst-authored `regex` conditions, and Python's `re`
# has no match timeout. A catastrophic-backtracking pattern (e.g. `(a+)+$`) run
# against a crafted field can hang the detection thread for seconds→minutes —
# freezing the engine tick and, on the ingest path, the HTTP request. Since
# rules run synchronously per event over every batch, one bad pattern is a
# denial of service for the whole deployment.
#
# ReDoS detection is undecidable in general, so we use a conservative
# heuristic: reject nested quantifiers (a quantified group whose body is itself
# quantified) and over-long patterns, and cap the input a regex is run against.
# These stop the patterns that actually hang `re` without a new dependency.
_NESTED_QUANT = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*]|\([^()]*[+*][^()]*\)\s*\{\d")
_REGEX_MAX_PATTERN = 512      # reject absurdly long patterns outright
_REGEX_INPUT_CAP = 8192       # bound the input a regex evaluates (defence in depth)


def is_safe_regex(pattern: str) -> bool:
    """Whether `pattern` is safe to run: syntactically valid, not too long, and
    free of the nested-quantifier shape that drives catastrophic backtracking."""
    if not isinstance(pattern, str) or len(pattern) > _REGEX_MAX_PATTERN:
        return False
    if _NESTED_QUANT.search(pattern):
        return False
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def unsafe_regex_in(definition: dict | None) -> str | None:
    """First unsafe `regex` condition value in a rule definition, or None. Used
    at rule-authoring time to reject a dangerous pattern with clear feedback,
    rather than silently dropping it at evaluation."""
    for cond in (definition or {}).get("conditions") or []:
        if cond.get("op") == "regex":
            val = str(cond.get("value", ""))
            if not is_safe_regex(val):
                return val
    return None


def invalid_aggregation_in(definition: dict | None) -> str | None:
    """Return a human-readable reason if the rule's aggregation is un-evaluable
    (non-numeric / non-positive threshold or window), else None.

    Used at rule-authoring time to reject a broken aggregated rule with clear
    feedback. `evaluate` is separately tolerant of already-stored bad values (it
    fires nothing rather than crash), but catching it at authoring stops the typo
    reaching the engine at all."""
    agg = (definition or {}).get("aggregation")
    if not agg or not agg.get("threshold"):
        return None
    thr = _coerce_num(agg.get("threshold"))
    if thr is None or thr < 1:
        return f"aggregation.threshold must be a positive number (got {agg.get('threshold')!r})"
    wm = agg.get("windowMinutes")
    if wm not in (None, "") and (_coerce_num(wm) is None or _coerce_num(wm) <= 0):
        return f"aggregation.windowMinutes must be a positive number (got {wm!r})"
    return None


def _match_condition(event: dict, cond: dict) -> bool:
    field = canonical_field(cond.get("field"))
    op = cond.get("op")
    expected = cond.get("value")
    actual = event.get(field)
    if op == "equals":
        return str(actual) == str(expected)
    if op == "not_equals":
        return str(actual) != str(expected)
    if op == "contains":
        return actual is not None and str(expected).lower() in str(actual).lower()
    if op == "in":
        opts = expected if isinstance(expected, list) else [s.strip() for s in str(expected).split(",")]
        return str(actual) in [str(o) for o in opts]
    if op in ("gt", "lt", "gte", "lte"):
        a, e = _coerce_num(actual), _coerce_num(expected)
        if a is None or e is None:
            return False
        return {"gt": a > e, "lt": a < e, "gte": a >= e, "lte": a <= e}[op]
    if op == "regex":
        pat = str(expected)
        # An unsafe/invalid pattern never runs — it can't match, and more
        # importantly can't hang the detection thread (ReDoS guard).
        if not is_safe_regex(pat):
            return False
        try:
            return actual is not None and re.search(pat, str(actual)[:_REGEX_INPUT_CAP]) is not None
        except re.error:
            return False
    if op == "cidr":
        try:
            return actual is not None and ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    return False


def matches_event(event: dict, definition: dict) -> bool:
    conds = definition.get("conditions") or []
    if not conds:
        return False
    logic = (definition.get("logic") or "and").lower()
    results = [_match_condition(event, c) for c in conds]
    return all(results) if logic == "and" else any(results)


def evaluate(rule: dict, events: list[dict], now: datetime | None = None) -> list[dict]:
    """Return a list of match dicts. Each match → one alert.

    Non-aggregated: {"entity", "event", "count": 1}
    Aggregated:     {"entity", "count", "event"(representative)}  per qualifying group
    """
    definition = rule.get("definition") or {}
    matching = [e for e in events if matches_event(e, definition)]
    if not matching:
        return []

    agg = definition.get("aggregation")
    if not agg or not agg.get("threshold"):
        # one alert per matching event (caller throttles)
        return [{"entity": e.get("src_ip") or e.get("hostname") or e.get("username") or "-",
                 "event": e, "count": 1} for e in matching]

    # Aggregation is configured. Coerce its numerics defensively: a rule stored
    # with a non-numeric threshold/window (e.g. "high", "5m" — analyst typo or a
    # malformed imported rule) must NOT raise here, or the exception propagates
    # out of the per-batch detection loop and blinds the SIEM for every rule and
    # event in the tick. A broken threshold → this rule fires nothing (it can't
    # be evaluated), rather than crashing the batch or flooding per-event alerts.
    threshold = _coerce_num(agg.get("threshold"))
    if threshold is None or threshold < 1:
        return []
    threshold = int(threshold)
    now = now or datetime.now(timezone.utc)
    window_min = _coerce_num(agg.get("windowMinutes"))
    window = timedelta(minutes=int(window_min) if window_min and window_min > 0 else 60)
    group_by = agg.get("groupBy") or "src_ip"
    groups: dict[str, list[dict]] = {}
    for e in matching:
        try:
            ts = datetime.fromisoformat(e["ts"])
        except (ValueError, KeyError):
            continue
        if now - ts > window:
            continue
        key = str(e.get(group_by) or "-")
        groups.setdefault(key, []).append(e)
    out = []
    for key, evs in groups.items():
        if len(evs) >= threshold:
            out.append({"entity": key, "count": len(evs), "event": evs[-1]})
    return out
