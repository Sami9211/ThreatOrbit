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
event count reaches the threshold inside the window raises one alert — this is
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


def _coerce_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _match_condition(event: dict, cond: dict) -> bool:
    field = cond.get("field")
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
        try:
            return actual is not None and re.search(str(expected), str(actual)) is not None
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
        return [{"entity": e.get("src_ip") or e.get("hostname") or e.get("username") or "—",
                 "event": e, "count": 1} for e in matching]

    now = now or datetime.now(timezone.utc)
    window = timedelta(minutes=int(agg.get("windowMinutes") or 60))
    group_by = agg.get("groupBy") or "src_ip"
    threshold = int(agg["threshold"])
    groups: dict[str, list[dict]] = {}
    for e in matching:
        try:
            ts = datetime.fromisoformat(e["ts"])
        except (ValueError, KeyError):
            continue
        if now - ts > window:
            continue
        key = str(e.get(group_by) or "—")
        groups.setdefault(key, []).append(e)
    out = []
    for key, evs in groups.items():
        if len(evs) >= threshold:
            out.append({"entity": key, "count": len(evs), "event": evs[-1]})
    return out
