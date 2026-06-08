"""WAL-mode SQLite layer for the dashboard API.

A single file database keeps the service zero-dependency and easy to run.
WAL mode allows concurrent reads while a write is in progress, which matters
for an API that serves many read requests against a periodically-seeded store.

Row access uses ``sqlite3.Row`` so callers get dict-like rows; the ``row_to_dict``
helper plus ``json_cols`` decoding turns a row into a JSON-ready dict, expanding
columns that hold serialized JSON (lists/objects) back into real structures.
"""
import json
import sqlite3
from contextlib import contextmanager

from dashboard_api.config import DB_PATH

# Columns that store JSON-encoded text and should be decoded on read.
JSON_COLUMNS = {
    "tags", "open_ports", "cves", "steps", "actions", "aliases", "motivations",
    "motivation", "sectors", "ttps", "malware", "campaigns", "iocs", "entities",
    "war_room", "tasks", "evidence", "data_sources", "techniques", "related_iocs",
    "hypotheses", "meta", "config", "scopes",
}


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def get_conn():
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a Row to a dict, decoding known JSON columns."""
    if row is None:
        return None
    out = {}
    for key in row.keys():
        val = row[key]
        if key in JSON_COLUMNS and isinstance(val, str):
            try:
                val = json.loads(val)
            except (ValueError, TypeError):
                pass
        out[key] = val
    return out


def rows_to_dicts(rows) -> list:
    return [row_to_dict(r) for r in rows]


def dumps(value) -> str:
    """JSON-encode a value for storage in a JSON column."""
    return json.dumps(value, separators=(",", ":"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',   -- admin | manager | analyst | viewer
    status        TEXT NOT NULL DEFAULT 'active',     -- active | invited | disabled
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    avatar_color  TEXT NOT NULL DEFAULT '#7A3CFF',
    mfa_enabled   INTEGER NOT NULL DEFAULT 0,
    last_login    TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,        -- domain|ip|server|cloud|database|endpoint
    value        TEXT NOT NULL,
    criticality  TEXT NOT NULL,        -- critical|high|medium|low
    status       TEXT NOT NULL,        -- clean|scanning|at-risk|critical|unscanned
    risk_score   INTEGER NOT NULL DEFAULT 0,
    last_scan    TEXT,
    alerts       INTEGER NOT NULL DEFAULT 0,
    cves         TEXT NOT NULL DEFAULT '{}',  -- {critical,high,medium,low}
    open_ports   TEXT NOT NULL DEFAULT '[]',
    os           TEXT,
    owner        TEXT,
    patch_age    INTEGER NOT NULL DEFAULT 0,
    tags         TEXT NOT NULL DEFAULT '[]',
    uptime       REAL NOT NULL DEFAULT 100.0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,    -- critical|high|medium|low|info
    status          TEXT NOT NULL,    -- new|assigned|in-progress|pending|resolved|closed
    disposition     TEXT NOT NULL DEFAULT 'undetermined',
    owner           TEXT,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    rule_id         TEXT,
    rule_name       TEXT,
    mitre_tactic    TEXT,
    mitre_tactic_id TEXT,
    mitre_tech      TEXT,
    mitre_tech_id   TEXT,
    src_ip          TEXT,
    src_country     TEXT,
    src_port        INTEGER,
    src_hostname    TEXT,
    src_asn         TEXT,
    dest_ip         TEXT,
    dest_port       INTEGER,
    dest_service    TEXT,
    username        TEXT,
    hostname        TEXT,
    host_criticality TEXT,
    process_name    TEXT,
    cmd_line        TEXT,
    description     TEXT,
    raw_log         TEXT,
    event_count     INTEGER NOT NULL DEFAULT 1,
    ti_hits         INTEGER NOT NULL DEFAULT 0,
    bytes_out       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    category          TEXT NOT NULL,
    severity          TEXT NOT NULL,
    mitre_tactic      TEXT,
    mitre_tech_id     TEXT,
    mitre_tech        TEXT,
    hits_24h          INTEGER NOT NULL DEFAULT 0,
    fired_last_7d     INTEGER NOT NULL DEFAULT 0,
    fp_rate           REAL NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'enabled',  -- enabled|disabled|suppressed
    source            TEXT,
    last_fired        TEXT,
    created           TEXT,
    updated_by        TEXT,
    description       TEXT,
    kql               TEXT,
    suppression_window INTEGER NOT NULL DEFAULT 0,
    severity_override TEXT,
    tags              TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS log_sources (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    host            TEXT,
    status          TEXT NOT NULL,   -- healthy|degraded|offline|paused
    eps_avg         REAL NOT NULL DEFAULT 0,
    eps_peak        REAL NOT NULL DEFAULT 0,
    last_event      TEXT,
    total_events_24h INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    parse_success   REAL NOT NULL DEFAULT 100,
    format          TEXT,
    tags            TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS saved_hunts (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL DEFAULT 'siem',  -- siem|cti
    name        TEXT NOT NULL,
    description TEXT,
    query       TEXT,
    technique   TEXT,
    last_run    TEXT,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    author      TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    type        TEXT,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    owner       TEXT,
    playbook    TEXT,
    sla_hours   INTEGER NOT NULL DEFAULT 24,
    created     TEXT NOT NULL,
    updated     TEXT NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    entities    TEXT NOT NULL DEFAULT '[]',
    war_room    TEXT NOT NULL DEFAULT '[]',
    tasks       TEXT NOT NULL DEFAULT '[]',
    evidence    TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS playbooks (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    category          TEXT,
    trigger           TEXT,
    trigger_type      TEXT NOT NULL DEFAULT 'auto',  -- auto|manual
    description       TEXT,
    runs              INTEGER NOT NULL DEFAULT 0,
    success_rate      REAL NOT NULL DEFAULT 0,
    avg_time          INTEGER NOT NULL DEFAULT 0,
    last_run          TEXT,
    last_run_status   TEXT NOT NULL DEFAULT 'idle',
    status            TEXT NOT NULL DEFAULT 'idle',
    enabled           INTEGER NOT NULL DEFAULT 1,
    steps             TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS integrations (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    vendor          TEXT,
    category        TEXT,
    status          TEXT NOT NULL,   -- connected|degraded|disconnected|pending
    last_sync       TEXT,
    actions_run     INTEGER NOT NULL DEFAULT 0,
    avg_response_ms INTEGER NOT NULL DEFAULT 0,
    description     TEXT,
    actions         TEXT NOT NULL DEFAULT '[]',
    enabled         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS threat_actors (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    aliases        TEXT NOT NULL DEFAULT '[]',
    origin         TEXT,
    flag           TEXT,
    type           TEXT,
    motivations    TEXT NOT NULL DEFAULT '[]',
    active         INTEGER NOT NULL DEFAULT 1,
    first_seen     TEXT,
    last_seen      TEXT,
    sophistication INTEGER NOT NULL DEFAULT 3,
    threat_level   TEXT,
    sectors        TEXT NOT NULL DEFAULT '[]',
    ttps           TEXT NOT NULL DEFAULT '[]',
    malware        TEXT NOT NULL DEFAULT '[]',
    ioc_count      INTEGER NOT NULL DEFAULT 0,
    campaign_count INTEGER NOT NULL DEFAULT 0,
    recent_activity TEXT,
    description    TEXT,
    campaigns      TEXT NOT NULL DEFAULT '[]',
    iocs           TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS iocs (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,   -- ip|domain|url|hash|email
    value       TEXT NOT NULL,
    threat_type TEXT,
    confidence  INTEGER NOT NULL DEFAULT 50,
    severity    TEXT,
    source      TEXT,
    actor       TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    tags        TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS feeds (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    provider    TEXT,
    type        TEXT,            -- commercial|opensource|community|internal
    status      TEXT NOT NULL,   -- active|paused|error
    enabled     INTEGER NOT NULL DEFAULT 1,
    indicators  INTEGER NOT NULL DEFAULT 0,
    last_sync   TEXT,
    sync_interval INTEGER NOT NULL DEFAULT 3600,
    reliability TEXT,            -- A|B|C
    url         TEXT,
    format      TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    prefix     TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT 'read',  -- read|write|admin
    last_used  TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL,   -- queued|running|completed|failed
    progress    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor      TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
"""


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        conn.commit()
