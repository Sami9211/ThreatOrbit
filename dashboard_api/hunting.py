"""Hunt query engine: run analyst queries against the live alert/IOC stores.

The dashboard's hunt pages accept free-form KQL-ish text. Rather than parse a
full query grammar, the engine extracts the discriminating tokens analysts
actually pivot on — MITRE technique ids, IPv4 addresses, severities, and
quoted/bare keywords — and matches them against stored alerts (SIEM domain)
or IOCs (CTI domain). Every result row is a real stored record.
"""
import re
import time
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn, rows_to_dicts

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
                      query: str | None, technique: str | None, author: str) -> dict:
    """Insert a saved hunt row and return it in the API shape."""
    import uuid
    from dashboard_api.db import audit, row_to_dict
    hid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO saved_hunts (id,domain,name,description,query,technique,last_run,"
            "hit_count,author,status,progress,created) VALUES (?,?,?,?,?,?,NULL,0,?, 'idle',0,?)",
            (hid, domain, name, description, query, technique, author, now),
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
