"""Hunt query engine: run analyst queries against the live alert/IOC stores.

The dashboard's hunt pages accept free-form KQL-ish text. Rather than parse a
full query grammar, the engine extracts the discriminating tokens analysts
actually pivot on - MITRE technique ids, IPv4 addresses, severities, and
quoted/bare keywords - and matches them against stored alerts (SIEM domain)
or IOCs (CTI domain). Every result row is a real stored record.
"""
import os
import re
import shlex
import time
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn, rows_to_dicts
from dashboard_api.rule_engine import ALL_FIELDS, canonical_field, matches_event

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
QUOTED_RE = re.compile(r'"([^"]{3,64})"')
SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Two-letter terms that mean something in this domain and would otherwise be
# dropped by the minimum-length rule. Kept as an explicit allowlist rather than
# lowering the floor, which would let every English preposition through.
_SHORT_TERMS = {"c2"}

# Query-language keywords that carry no hunt meaning and should not become
# free-text search terms.
_STOPWORDS = {
    "where", "and", "or", "not", "in", "by", "stats", "count", "avg", "sum",
    "event", "events", "network", "process", "source", "destination", "host",
    "user", "index", "stddev", "diff", "between", "like", "dcount", "countif",
    "bucket", "window", "true", "false", "type", "name", "code", "dataset",
    "action", "direction", "outbound", "inbound", "connection", "start",
    "timestamp", "lookup", "hour",
}

# How often to check whether a saved hunt's schedule is due. A minute is the
# finest cadence the schedule API accepts, so a one-minute check honours any of
# them; 0 disables scheduled hunts entirely.
HUNT_TICK_SECONDS = int(os.environ.get("DASHBOARD_HUNT_TICK_SECONDS", "60"))

RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}


def extract_tokens(query: str) -> dict:
    """Pull techniques, IPs, severities, and keywords out of a query string.

    Keywords used to come from QUOTED strings only. Nobody types quotes, so a
    hunt for `emotet` extracted nothing, produced no WHERE clause, and matched
    the ENTIRE store - then showed the top fifty, which look exactly like
    results. Measured on the live 530,238-indicator store, `cobaltstrike`,
    `emotet` and `phishing` each "found" all 530,238. The capped hit count hid
    it: every hunt reported the page size, so every hunt looked reasonable.

    Bare words are keywords now. Quotes still mean "this phrase", which is the
    only thing they ever usefully meant here.
    """
    techniques = sorted(set(TECHNIQUE_RE.findall(query)))
    ips = sorted(set(IPV4_RE.findall(query)))
    quoted = [q for q in QUOTED_RE.findall(query) if not q.startswith("0x")]
    severities = sorted({w for w in re.findall(r"[a-z]+", query.lower()) if w in SEVERITIES})

    def _keep(t: str) -> bool:
        long_enough = len(t) >= 3 or t in _SHORT_TERMS
        return (long_enough and t not in _STOPWORDS and t not in SEVERITIES
                and not IPV4_RE.fullmatch(t) and not TECHNIQUE_RE.fullmatch(t.upper()))

    keywords: list[str] = []
    for term in quoted:
        t = term.strip().lower()
        if t and t not in _STOPWORDS and not IPV4_RE.fullmatch(t):
            keywords.append(t)
    # Everything the quotes did not already claim. Field-operator syntax
    # (`event_type=beacon`) is the event-search language's job, not this one's,
    # so split on non-word characters and take the words.
    rest = QUOTED_RE.sub(" ", query).lower()
    for t in re.split(r"[^\w.:-]+", rest):
        t = t.strip(" .:-")
        if _keep(t) and t not in keywords:
            keywords.append(t)
    return {"techniques": techniques, "ips": ips, "severities": severities,
            "keywords": keywords[:8]}


def _window_start(time_range: str) -> str:
    hours = RANGE_HOURS.get(time_range, 24)
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(microsecond=0).isoformat()


def run_alert_hunt(query: str, time_range: str = "24h", limit: int = 50) -> dict:
    """Match extracted tokens against the alerts store. Returns real alerts."""
    started = time.perf_counter()
    tokens = extract_tokens(query)
    since = _window_start(time_range)
    window_sec = RANGE_HOURS.get(time_range, 24) * 3600

    clauses, params = ["ts >= ?"], [since]
    token_clauses, token_params = [], []
    for tech in tokens["techniques"]:
        # T1071 should also match stored T1071.001
        token_clauses.append("mitre_tech_id LIKE ?")
        token_params.append(f"{tech}%")
    for ip in tokens["ips"]:
        token_clauses.append("(src_ip = ? OR dest_ip = ?)")
        token_params.extend([ip, ip])
    for kw in tokens["keywords"]:
        token_clauses.append(
            "(LOWER(title) LIKE ? OR LOWER(rule_name) LIKE ? OR LOWER(process_name) LIKE ? "
            "OR LOWER(hostname) LIKE ? OR LOWER(username) LIKE ?)"
        )
        token_params.extend([f"%{kw}%"] * 5)
    if token_clauses:
        clauses.append("(" + " OR ".join(token_clauses) + ")")
        params.extend(token_params)
    if tokens["severities"]:
        clauses.append(f"severity IN ({','.join('?' * len(tokens['severities']))})")
        params.extend(tokens["severities"])

    with get_conn() as conn:
        scanned = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE ts >= ?", (since,)).fetchone()["n"]
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE {' AND '.join(clauses)} "
            f"ORDER BY risk_score DESC, ts DESC LIMIT ?",
            params + [limit],
        ).fetchall()

    results = []
    for a in rows_to_dicts(rows):
        event_count = max(a.get("event_count") or 1, 1)
        results.append({
            "alert_id": a["id"],
            "ts": a["ts"],
            "src_ip": a.get("src_ip"),
            "dest_ip": a.get("dest_ip"),
            "dest_port": a.get("dest_port"),
            "protocol": (a.get("dest_service") or "tcp").upper(),
            "bytes": a.get("bytes_out") or 0,
            # observed mean spacing between correlated events inside the window
            "interval": max(30, min(600, window_sec // event_count)),
            "host": a.get("hostname") or a.get("src_hostname") or "-",
            "title": a["title"],
            "severity": a["severity"],
            "technique": a.get("mitre_tech_id"),
            "risk_score": a.get("risk_score"),
        })

    return {
        "scanned": scanned,
        "hits": len(results),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "tokens": tokens,
        "results": results,
    }


_HUNT_COLS = ("id, name, description AS hypothesis, author AS analyst, query, technique, "
              "last_run, hit_count AS artifacts, status, progress, domain")


def create_saved_hunt(domain: str, name: str, description: str | None,
                      query: str | None, technique: str | None, author: str,
                      org_id: str | None = None) -> dict:
    """Insert a saved hunt row and return it in the API shape."""
    import uuid
    from dashboard_api import tenancy
    from dashboard_api.db import audit, row_to_dict
    hid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO saved_hunts (id,domain,name,description,query,technique,last_run,"
            "hit_count,author,status,progress,created,org_id) "
            "VALUES (?,?,?,?,?,?,NULL,0,?, 'idle',0,?,?)",
            (hid, domain, name, description, query, technique, author, now,
             org_id or tenancy.DEFAULT_ORG_ID),
        )
        audit(conn, author, "hunt.create", hid, f"domain={domain} name={name}")
        conn.commit()
        row = conn.execute(f"SELECT {_HUNT_COLS} FROM saved_hunts WHERE id=?", (hid,)).fetchone()
    return row_to_dict(row)


def run_saved_hunt(domain: str, hunt_id: str, actor: str) -> dict | None:
    """Execute a saved hunt against the live store and persist the outcome.

    Returns {hunt, run} or None when the hunt does not exist in this domain.
    """
    from dashboard_api.db import audit, row_to_dict
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM saved_hunts WHERE id=? AND domain=?", (hunt_id, domain)
        ).fetchone()
    if not row:
        return None
    query_text = " ".join(filter(None, [row["query"], row["technique"], row["name"]]))
    run = run_alert_hunt(query_text, "7d") if domain == "siem" else run_ioc_hunt(query_text)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE saved_hunts SET last_run=?, hit_count=?, status='complete', progress=100 WHERE id=?",
            (now, run["hits"], hunt_id),
        )
        audit(conn, actor, "hunt.run", hunt_id, f"domain={domain} hits={run['hits']}")
        conn.commit()
        updated = conn.execute(f"SELECT {_HUNT_COLS} FROM saved_hunts WHERE id=?", (hunt_id,)).fetchone()
    return {"hunt": row_to_dict(updated), "run": run}


# -- Event-stream search language ------------------------------------------------
# A real, compact field-operator query over the raw `events` stream - the data a
# hunter actually searches (not just alerts). Splunk/KQL-flavoured:
#
#   src_ip=10.0.0.5 event_type=failed_login        implicit AND of conditions
#   bytes_out>=104857600                            numeric comparison
#   username in svc-backup,svc-deploy               membership
#   raw~"OR 1=1"                                     regex over the raw line
#   host:web                                         contains (substring)
#   powershell                                       bare token → full-text over raw
#   event_type=beacon | stats count by dest_ip      group-by aggregation
#   event_type=login_success | join src_ip event_type=failed_login
#                                                    correlate across sources:
#                                                    keep left rows whose field
#                                                    value also matches the right
#
# Each term compiles to the SAME condition shape the detection rule engine
# evaluates (rule_engine.matches_event), so search and detection stay consistent.

# Recognise native AND ECS field names (longest first so dotted ECS names and
# multi-word natives win over shorter prefixes). Escaped: ECS names contain dots.
_RECOGNISED = set(ALL_FIELDS)
_FIELD_ALT = "|".join(re.escape(f) for f in sorted(ALL_FIELDS, key=len, reverse=True))
_TERM_RE = re.compile(rf"^({_FIELD_ALT})(>=|<=|!=|=|>|<|~|:)(.*)$", re.I)
_SYM_OP = {">=": "gte", "<=": "lte", "!=": "not_equals", "=": "equals",
           ">": "gt", "<": "lt", "~": "regex", ":": "contains"}
_IN_RE = re.compile(r"\b([a-z_.]+)\s+in\s+([^\s|]+)", re.I)
_STATS_RE = re.compile(r"stats\s+count\s+by\s+([a-z_.]+)", re.I)
_JOIN_RE = re.compile(r"^join\s+([a-z_.]+)\s+(.+)$", re.I)


def parse_query(q: str) -> dict:
    """Parse a search string into {conditions, freetext, stats, join}.

    `conditions` use the rule-engine field/op/value shape; `freetext` are bare
    tokens matched as substrings of the raw line; `stats` is an optional
    {"by": field} group-by; `join` is an optional cross-source correlation -
    `| join <field> <subquery>` keeps left-side rows whose <field> value also
    appears in the subquery's matches (e.g. successful logins from IPs that
    also produced failed logins). Pipes compose: join runs first, stats after.
    """
    stats = None
    join = None
    segments = [s.strip() for s in (q or "").split("|")]
    search = segments[0]
    for seg in segments[1:]:
        jm = _JOIN_RE.match(seg)
        if jm and jm.group(1).lower() in _RECOGNISED:
            join = {"field": canonical_field(jm.group(1).lower()), "query": jm.group(2).strip()}
            continue
        m = _STATS_RE.search(seg)
        if m and m.group(1).lower() in _RECOGNISED:
            # group on the native field even when an ECS alias was used
            stats = {"by": canonical_field(m.group(1).lower())}
    conditions: list[dict] = []

    # word operator first: `field in a,b,c`
    def _in_sub(m):
        f = m.group(1).lower()
        if f in _RECOGNISED:
            conditions.append({"field": f, "op": "in", "value": m.group(2)})
            return " "
        return m.group(0)
    search = _IN_RE.sub(_in_sub, search)

    try:
        tokens = shlex.split(search)
    except ValueError:
        tokens = search.split()
    freetext: list[str] = []
    for tok in tokens:
        m = _TERM_RE.match(tok)
        if m:
            conditions.append({"field": m.group(1).lower(), "op": _SYM_OP[m.group(2)], "value": m.group(3)})
        elif tok.strip():
            freetext.append(tok)
    return {"conditions": conditions, "freetext": freetext, "stats": stats, "join": join}


def event_search(query: str, time_range: str = "24h", limit: int = 200,
                 since_iso: str | None = None) -> dict:
    """Run a field-operator search over the raw event stream. Returns matching
    events, or grouped counts when the query ends in `| stats count by <field>`.

    `since_iso` adds a `newHits` count: how many of the matches are newer than
    that timestamp. A scheduled hunt needs the difference between "this query
    matches twelve things" and "twelve things matched that were not there when I
    last looked" - the first is true every time it runs and is not news.
    """
    started = time.perf_counter()
    parsed = parse_query(query)
    conds = list(parsed["conditions"])
    for ft in parsed["freetext"]:
        conds.append({"field": "raw", "op": "contains", "value": ft})
    definition = {"conditions": conds, "logic": "and"}
    since = _window_start(time_range)

    with get_conn() as conn:
        scanned = conn.execute("SELECT COUNT(*) AS n FROM events WHERE ts >= ?", (since,)).fetchone()["n"]
        rows = conn.execute(
            "SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT 5000", (since,)
        ).fetchall()
    events = [dict(e) for e in rows]
    matched = [e for e in events if (not conds) or matches_event(e, definition)]

    # Cross-source join: keep left rows whose join-field value also appears in
    # the right-hand subquery's matches over the same window. The subquery is
    # conditions/freetext only (no nested pipes).
    join_meta = None
    if parsed.get("join"):
        jfield, jquery = parsed["join"]["field"], parsed["join"]["query"]
        sub = parse_query(jquery)
        sub_conds = list(sub["conditions"]) + [
            {"field": "raw", "op": "contains", "value": ft} for ft in sub["freetext"]]
        sub_def = {"conditions": sub_conds, "logic": "and"}
        right = [e for e in events if sub_conds and matches_event(e, sub_def)]
        keys = {str(e.get(jfield)) for e in right if e.get(jfield) not in (None, "")}
        matched = [e for e in matched
                   if e.get(jfield) not in (None, "") and str(e.get(jfield)) in keys]
        join_meta = {"field": jfield, "query": jquery,
                     "rightHits": len(right), "keyCount": len(keys)}

    interpreted = {"conditions": parsed["conditions"], "freetext": parsed["freetext"],
                   "stats": parsed["stats"], "join": join_meta}
    elapsed = round((time.perf_counter() - started) * 1000, 1)

    if parsed["stats"]:
        by = parsed["stats"]["by"]
        groups: dict[str, int] = {}
        for e in matched:
            v = e.get(by)
            key = "-" if v in (None, "") else str(v)
            groups[key] = groups.get(key, 0) + 1
        agg = sorted(({"value": k, "count": v} for k, v in groups.items()), key=lambda x: -x["count"])
        return {"scanned": scanned, "hits": len(matched), "groupCount": len(agg),
                "elapsed_ms": elapsed, "interpreted": interpreted,
                "stats": {"by": by, "groups": agg[:50]}, "results": []}

    keep = ("id", "ts", "category", "event_type", "src_ip", "dest_ip", "dest_port",
            "username", "hostname", "process_name", "action", "bytes_out", "mitre_tech_id", "raw")
    results = [{k: e.get(k) for k in keep} for e in matched[:limit]]
    out = {"scanned": scanned, "hits": len(matched), "elapsed_ms": elapsed,
           "interpreted": interpreted, "stats": None, "results": results}
    if since_iso:
        # Counted over the FULL match list rather than the capped `results`, so
        # "new" is a real count and not an artefact of the display limit.
        fresh = [e for e in matched if str(e.get("ts") or "") > since_iso]
        out["newHits"] = len(fresh)
        out["newResults"] = [{k: e.get(k) for k in keep} for e in fresh[:limit]]
    return out


def run_due_scheduled_hunts(conn, *, now: datetime | None = None) -> dict:
    """Run any saved SIEM hunt whose schedule is due, and raise an alert when it
    NEWLY matches. Returns a summary.

    Two things this used to get wrong, both of which made the feature a control
    that lies:

    **It alerted on every run with hits.** A hunt matching the same twelve events
    raised an identical alert every fifteen minutes forever. A saved hunt is a
    standing hypothesis; the news is that something matched it that was not there
    last time, not that the query still returns rows. So the alert now fires on
    matches newer than the last scheduled run, and says both numbers - what is
    new, and what the window holds in total.

    **It only ran inside the synthetic telemetry loop.** `process_tick` is gated
    on SYNTHETIC_ALLOWED, so on a real deployment - the one with real logs and
    real hunts - the schedule was accepted by the API, displayed in the UI, and
    never honoured by anything. It is driven by its own loop now (`main._hunt_loop`),
    which runs in every mode.
    """
    from dashboard_api.detections import _insert_alert
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT * FROM saved_hunts WHERE schedule_minutes > 0").fetchall()
    ran = alerts = 0
    for h in rows:
        last = h["last_scheduled"]
        due = True
        if last:
            try:
                lt = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                if lt.tzinfo is None:
                    lt = lt.replace(tzinfo=timezone.utc)
                due = (now - lt) >= timedelta(minutes=int(h["schedule_minutes"]))
            except (ValueError, TypeError):
                due = True
        if not due:
            continue
        query = " ".join(filter(None, [h["query"], h["technique"]]))
        if h["domain"] == "cti":
            ran += _run_cti_watchlist(conn, h, query, last, now)
            continue
        # The first scheduled run has no previous look to compare against, so
        # everything the window holds counts as new. That is deliberate: an
        # analyst who has just put a hunt on a schedule should be told if it
        # matches something NOW rather than waiting a cadence to find out, and it
        # costs exactly one alert ever. Every run after it compares against the
        # last look, which is where the repetition came from.
        result = event_search(query, "24h", limit=200, since_iso=str(last) if last else None)
        new_hits = result.get("newHits", 0) if last else result["hits"]
        nowiso = now.replace(microsecond=0).isoformat()
        conn.execute(
            "UPDATE saved_hunts SET last_scheduled=?, last_run=?, hit_count=?, status='scheduled' "
            "WHERE id=?", (nowiso, nowiso, result["hits"], h["id"]))
        ran += 1
        if new_hits > 0 and h["auto_alert"]:
            fresh = result.get("newResults") or result.get("results") or []
            ev = fresh[0] if fresh else {}
            first = not last
            _insert_alert(
                conn,
                title=(f"Scheduled hunt matched: {h['name']} ({new_hits} hits)" if first
                       else f"Scheduled hunt newly matched: {h['name']} ({new_hits} new)"),
                severity="medium", risk=52, rule_name=f"Hunt · {h['name']}",
                src_ip=ev.get("src_ip"), hostname=ev.get("hostname"), username=ev.get("username"),
                mitre_tech_id=h["technique"] or ev.get("mitre_tech_id"),
                description=(
                    f"Saved hunt '{h['name']}' ({query}) returned {new_hits} event(s) "
                    f"on its first scheduled run." if first else
                    f"Saved hunt '{h['name']}' ({query}) matched {new_hits} event(s) "
                    f"that were not there at the last check, out of {result['hits']} "
                    f"in the last 24h."),
                raw_log=ev.get("raw"), event_count=new_hits)
            conn.execute("UPDATE alerts SET rule_id='R-HUNT' WHERE id=(SELECT id FROM alerts "
                         "ORDER BY ts DESC LIMIT 1)")
            alerts += 1
    return {"ran": ran, "alerts": alerts}


def _strip_total(rows) -> list[dict]:
    """Drop the window-function count so it never looks like an indicator field."""
    return [{k: v for k, v in r.items() if k != "_total"} for r in rows_to_dicts(rows)]


def _run_cti_watchlist(conn, h, query: str, last, now: datetime) -> int:
    """A saved CTI hunt on a schedule is a watchlist over the indicator store.

    It gets a NOTIFICATION rather than a SIEM alert, and that distinction is the
    point. A SIEM alert says something happened on this network; a new indicator
    matching a standing hypothesis says the world changed, and filing the second
    as the first puts intel into the queue an analyst triages as detections.

    Grouped under one key per hunt, so a feed sync that lands two hundred
    matching indicators at once is one line that says two hundred - the same
    treatment every other burst in this platform gets.
    """
    from dashboard_api.routers.platform import notify
    result = run_ioc_hunt(query, limit=50, since_iso=str(last) if last else None)
    nowiso = now.replace(microsecond=0).isoformat()
    # A watchlist reports what is NEW. Unlike the SIEM path there is no
    # first-run alert: the indicator store is half a million rows deep, so
    # "everything matching, ever" is a backlog rather than news.
    new_hits = result.get("newHits", 0) if last else 0
    conn.execute(
        "UPDATE saved_hunts SET last_scheduled=?, last_run=?, hit_count=?, "
        "status='scheduled' WHERE id=?", (nowiso, nowiso, result["hits"], h["id"]))
    if new_hits > 0 and h["auto_alert"]:
        top = (result.get("newResults") or [{}])[0]
        notify(conn, type="cti.watchlist", severity="info",
               title=f"Watchlist matched: {h['name']} ({new_hits} new)",
               detail=(f"{new_hits} new indicator(s) entered the store matching "
                       f"'{query}'; {result['hits']:,} match in total. "
                       f"Most recent: {top.get('value', '-')}"),
               link=f"/dashboard/cti/hunts?hunt={h['id']}",
               group_key=f"watchlist:{h['id']}",
               rollup_title="{n} new matches for " + str(h["name"]),
               rollup_link=f"/dashboard/cti/hunts?hunt={h['id']}",
               org_id=h["org_id"] or "org-default")
    return 1


def run_ioc_hunt(query: str, limit: int = 50, since_iso: str | None = None) -> dict:
    """Match extracted tokens against the IOC store. Returns real IOCs.

    `hits` is a real COUNT over the whole store, not the length of the page.
    It used to be `len(rows)` AFTER the `LIMIT`, so every hunt reported exactly
    the page size and no more: measured on a 530,238-indicator store, a hunt for
    "phishing" reported **50 hits against 149,747 matches**, and the saved hunt
    carried that 50 forward as its recorded result. A number that is the page
    size dressed up as a finding is worse than no number.

    `since_iso` adds `newHits`: matches that entered THIS store after that
    moment. Keyed on `imported_at`, not `first_seen` - the latter is the
    source's claim about the wider world and is routinely backdated by years, so
    a feed publishing a 2019 address today would never count as new to a
    watchlist that trusted it.
    """
    started = time.perf_counter()
    tokens = extract_tokens(query)

    token_clauses, token_params = [], []
    for ip in tokens["ips"]:
        token_clauses.append("value LIKE ?")
        token_params.append(f"%{ip}%")
    for kw in tokens["keywords"]:
        token_clauses.append(
            "(LOWER(value) LIKE ? OR LOWER(threat_type) LIKE ? OR LOWER(actor) LIKE ? OR LOWER(source) LIKE ?)"
        )
        token_params.extend([f"%{kw}%"] * 4)
    clauses, params = [], []
    if token_clauses:
        clauses.append("(" + " OR ".join(token_clauses) + ")")
        params.extend(token_params)
    if tokens["severities"]:
        clauses.append(f"severity IN ({','.join('?' * len(tokens['severities']))})")
        params.extend(tokens["severities"])
    if not clauses:
        # Nothing searchable was typed. Returning the whole store here is how a
        # hunt for a term this tokeniser could not use came back looking like a
        # confident answer; an empty result is the honest one.
        with get_conn() as conn:
            scanned = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
        out = {"scanned": scanned, "hits": 0, "shown": 0,
               "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
               "tokens": tokens, "results": []}
        if since_iso:
            out["newHits"], out["newResults"] = 0, []
        return out
    where = "WHERE " + " AND ".join(clauses)

    with get_conn() as conn:
        scanned = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
        # One scan, not two. A leading-wildcard LIKE cannot use an index, so a
        # separate COUNT doubles the cost of every hunt over a half-million-row
        # store; `COUNT(*) OVER ()` rides the scan the page is already paying
        # for and is supported by both backends.
        #
        # Ordered by the composite intel score, not raw confidence: "the ones
        # worth opening" is what a hunt is for, and a feed's own confidence says
        # nothing about corroboration, local sightings or decay.
        rows = conn.execute(
            f"SELECT *, COUNT(*) OVER () AS _total FROM iocs {where} "
            f"ORDER BY intel_score DESC, confidence DESC LIMIT ?",
            params + [limit]).fetchall()
        hits = rows[0]["_total"] if rows else 0
        new_rows, new_hits = [], 0
        if since_iso:
            # The same predicate, narrowed to what arrived since the caller last
            # looked. A separate query rather than a filter over `rows`: that is
            # one page ordered by score, and a new arrival is not necessarily on
            # it.
            new_rows = conn.execute(
                f"SELECT *, COUNT(*) OVER () AS _total FROM iocs {where} "
                f"AND imported_at > ? ORDER BY imported_at DESC LIMIT ?",
                params + [since_iso, limit]).fetchall()
            new_hits = new_rows[0]["_total"] if new_rows else 0

    return {
        "scanned": scanned,
        "hits": hits,
        "shown": len(rows),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "tokens": tokens,
        # `_total` is the window-function column, not part of an indicator.
        "results": _strip_total(rows),
        **({"newHits": new_hits, "newResults": _strip_total(new_rows)}
           if since_iso else {}),
    }
