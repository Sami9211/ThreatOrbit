"""Hunt query engine: run analyst queries against the live alert/IOC stores.

The dashboard's hunt pages accept free-form KQL-ish text. Rather than parse a
full query grammar, the engine extracts the discriminating tokens analysts
actually pivot on — MITRE technique ids, IPv4 addresses, severities, and
quoted/bare keywords — and matches them against stored alerts (SIEM domain)
or IOCs (CTI domain). Every result row is a real stored record.
"""
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

RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}


def extract_tokens(query: str) -> dict:
    """Pull techniques, IPs, severities, and keywords out of a query string."""
    techniques = sorted(set(TECHNIQUE_RE.findall(query)))
    ips = sorted(set(IPV4_RE.findall(query)))
    quoted = [q for q in QUOTED_RE.findall(query) if not q.startswith("0x")]
    severities = sorted({w for w in re.findall(r"[a-z]+", query.lower()) if w in SEVERITIES})
    keywords = []
    for term in quoted:
        t = term.strip().lower()
        if t and t not in _STOPWORDS and not IPV4_RE.fullmatch(t) and len(keywords) < 8:
            keywords.append(t)
    return {"techniques": techniques, "ips": ips, "severities": severities, "keywords": keywords}


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


# ── Event-stream search language ────────────────────────────────────────────────
# A real, compact field-operator query over the raw `events` stream — the data a
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
    {"by": field} group-by; `join` is an optional cross-source correlation —
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


def event_search(query: str, time_range: str = "24h", limit: int = 200) -> dict:
    """Run a field-operator search over the raw event stream. Returns matching
    events, or grouped counts when the query ends in `| stats count by <field>`."""
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
            key = "—" if v in (None, "") else str(v)
            groups[key] = groups.get(key, 0) + 1
        agg = sorted(({"value": k, "count": v} for k, v in groups.items()), key=lambda x: -x["count"])
        return {"scanned": scanned, "hits": len(matched), "groupCount": len(agg),
                "elapsed_ms": elapsed, "interpreted": interpreted,
                "stats": {"by": by, "groups": agg[:50]}, "results": []}

    keep = ("id", "ts", "category", "event_type", "src_ip", "dest_ip", "dest_port",
            "username", "hostname", "process_name", "action", "bytes_out", "mitre_tech_id", "raw")
    results = [{k: e.get(k) for k in keep} for e in matched[:limit]]
    return {"scanned": scanned, "hits": len(matched), "elapsed_ms": elapsed,
            "interpreted": interpreted, "stats": None, "results": results}


def run_due_scheduled_hunts(conn, *, now: datetime | None = None) -> dict:
    """Run any saved SIEM hunt whose schedule is due (event-stream search), and
    raise a SIEM alert when it has hits and auto_alert is on. Returns a summary.
    Called by the live engine; the hunt becomes a real detection-over-time."""
    from dashboard_api.detections import _insert_alert
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT * FROM saved_hunts WHERE domain='siem' AND schedule_minutes > 0").fetchall()
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
        result = event_search(query, "24h", limit=200)
        nowiso = now.replace(microsecond=0).isoformat()
        conn.execute(
            "UPDATE saved_hunts SET last_scheduled=?, last_run=?, hit_count=?, status='scheduled' "
            "WHERE id=?", (nowiso, nowiso, result["hits"], h["id"]))
        ran += 1
        if result["hits"] > 0 and h["auto_alert"]:
            ev = result["results"][0] if result["results"] else {}
            _insert_alert(
                conn, title=f"Scheduled hunt matched: {h['name']} ({result['hits']} hits)",
                severity="medium", risk=52, rule_name=f"Hunt · {h['name']}",
                src_ip=ev.get("src_ip"), hostname=ev.get("hostname"), username=ev.get("username"),
                mitre_tech_id=h["technique"] or ev.get("mitre_tech_id"),
                description=f"Saved hunt '{h['name']}' ({query}) returned {result['hits']} events on its schedule.",
                raw_log=ev.get("raw"), event_count=result["hits"])
            conn.execute("UPDATE alerts SET rule_id='R-HUNT' WHERE id=(SELECT id FROM alerts "
                         "ORDER BY ts DESC LIMIT 1)")
            alerts += 1
    return {"ran": ran, "alerts": alerts}


def run_ioc_hunt(query: str, limit: int = 50) -> dict:
    """Match extracted tokens against the IOC store. Returns real IOCs."""
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
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    with get_conn() as conn:
        scanned = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
        rows = conn.execute(
            f"SELECT * FROM iocs {where} ORDER BY confidence DESC LIMIT ?", params + [limit]
        ).fetchall()

    return {
        "scanned": scanned,
        "hits": len(rows),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "tokens": tokens,
        "results": rows_to_dicts(rows),
    }
