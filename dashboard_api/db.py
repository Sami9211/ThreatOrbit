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
    "hypotheses", "meta", "config", "scopes", "events", "field_map", "definition", "filters",
    "context", "trigger_match", "data", "actors", "software", "linked_cases",
}


def _connect() -> sqlite3.Connection:
    # Backend seam (see db_backend.py): SQLite is the default and unchanged;
    # the Postgres path is staged and only taken when explicitly selected.
    from dashboard_api.db_backend import is_postgres
    if is_postgres():  # pragma: no cover - opt-in, requires psycopg + DSN
        from dashboard_api.db_backend import connect_postgres
        return connect_postgres()
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
    created_at    TEXT NOT NULL,
    org_id        TEXT                                -- workspace membership (multi-tenancy foundation)
);

-- Workspaces / organizations (multi-tenancy foundation). Data tables are not
-- yet org-scoped - see dashboard_api/tenancy.py for the staged isolation seam.
CREATE TABLE IF NOT EXISTS orgs (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,
    plan       TEXT NOT NULL DEFAULT 'enterprise',
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

-- Custom RBAC roles (additive): the four built-in roles stay code-authoritative
-- in permissions.py; rows here are operator-defined roles whose `capabilities`
-- (JSON array drawn from permissions.CAPABILITIES) extend the model without code.
CREATE TABLE IF NOT EXISTS roles (
    id           TEXT PRIMARY KEY,             -- slug, also stored in users.role
    name         TEXT NOT NULL,
    description  TEXT,
    capabilities TEXT NOT NULL DEFAULT '[]',   -- JSON array of capability strings
    created_at   TEXT,
    org_id       TEXT NOT NULL DEFAULT 'org-default'
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
    created_at   TEXT NOT NULL,
    software     TEXT NOT NULL DEFAULT '[]'        -- installed [{product,version}] for vuln scanning
);

-- CVE catalogue rows synced from the NVD connector (configurations → CPE
-- product/version ranges); merged with the built-in catalogue at scan time.
CREATE TABLE IF NOT EXISTS cve_catalogue (
    cve         TEXT NOT NULL,
    product     TEXT NOT NULL,
    cvss        REAL NOT NULL DEFAULT 0,
    severity    TEXT NOT NULL DEFAULT 'medium',
    vstart      TEXT,                              -- affected-from (NULL = no lower bound)
    vstart_incl INTEGER NOT NULL DEFAULT 1,
    vend        TEXT,                              -- affected-to (NULL = no upper bound)
    vend_incl   INTEGER NOT NULL DEFAULT 0,
    fixed       TEXT,
    summary     TEXT,
    kev         INTEGER NOT NULL DEFAULT 0,
    exploit     INTEGER NOT NULL DEFAULT 0,
    source      TEXT NOT NULL DEFAULT 'nvd',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (cve, product)
);

-- Genuine per-asset CVE findings from the vulnerability scanner.
CREATE TABLE IF NOT EXISTS vuln_findings (
    id         TEXT PRIMARY KEY,
    asset_id   TEXT NOT NULL,
    cve        TEXT NOT NULL,
    product    TEXT,
    version    TEXT,
    severity   TEXT NOT NULL,
    cvss       REAL NOT NULL DEFAULT 0,
    fixed_in   TEXT,
    summary    TEXT,
    status     TEXT NOT NULL DEFAULT 'open',     -- open|fixed|accepted
    found_at   TEXT NOT NULL,
    kev        INTEGER NOT NULL DEFAULT 0,       -- CISA Known Exploited Vulnerabilities
    exploit    INTEGER NOT NULL DEFAULT 0        -- public exploit exists
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
    bytes_out       INTEGER NOT NULL DEFAULT 0,
    detect_latency_sec  INTEGER,   -- event→detection latency (drives MTTD)
    ack_latency_sec     INTEGER,   -- detection→acknowledge latency (drives MTTA)
    respond_latency_sec INTEGER    -- acknowledge→containment latency (drives MTTR)
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    category          TEXT NOT NULL,
    severity          TEXT NOT NULL,
    mitre_tactic      TEXT,
    mitre_tactic_id   TEXT,
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
    author      TEXT,
    status      TEXT NOT NULL DEFAULT 'idle',   -- idle|running|scheduled|complete
    progress    INTEGER NOT NULL DEFAULT 0,
    created     TEXT
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
    steps             TEXT NOT NULL DEFAULT '[]',
    trigger_match     TEXT NOT NULL DEFAULT '{}'   -- auto-run criteria {severities,techniques,rule}
);

-- Versioned snapshots of a playbook's step definition (visual builder history).
CREATE TABLE IF NOT EXISTS playbook_versions (
    id            TEXT PRIMARY KEY,
    playbook_id   TEXT NOT NULL,
    version       INTEGER NOT NULL,
    steps         TEXT NOT NULL DEFAULT '[]',
    trigger_match TEXT NOT NULL DEFAULT '{}',
    author        TEXT,
    note          TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id            TEXT PRIMARY KEY,
    playbook_id   TEXT NOT NULL,
    playbook_name TEXT,
    ts            TEXT NOT NULL,
    finished      TEXT,
    status        TEXT NOT NULL DEFAULT 'running',  -- success|failed|awaiting-approval|rejected
    trigger       TEXT NOT NULL DEFAULT 'manual',   -- manual|auto
    actor         TEXT,
    alert_id      TEXT,
    current_step  INTEGER NOT NULL DEFAULT 0,
    context       TEXT NOT NULL DEFAULT '{}',
    steps         TEXT NOT NULL DEFAULT '[]'
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
    enabled         INTEGER NOT NULL DEFAULT 1,
    base_url        TEXT,                          -- vendor API endpoint (real calls)
    api_key         TEXT                           -- credential (never returned to the client)
);

-- Action audit trail: every response action attempted on an integration, with
-- its real request target + outcome (real call when credentialled, else logged).
CREATE TABLE IF NOT EXISTS integration_actions (
    id             TEXT PRIMARY KEY,
    integration_id TEXT NOT NULL,
    action         TEXT NOT NULL,
    target         TEXT,
    status         TEXT NOT NULL,   -- success|failed|simulated|not-configured
    mode           TEXT NOT NULL,   -- live|simulated
    detail         TEXT,
    actor          TEXT,
    ts             TEXT NOT NULL
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
    tags        TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL DEFAULT 'active',   -- active|expired|known-good
    sightings   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ioc_sightings (
    id      TEXT PRIMARY KEY,
    ioc_id  TEXT NOT NULL,
    ts      TEXT NOT NULL,
    source  TEXT,
    context TEXT
);

-- IOC import history (feeds → Import page).
CREATE TABLE IF NOT EXISTS ioc_imports (
    id        TEXT PRIMARY KEY,
    source    TEXT NOT NULL,
    method    TEXT NOT NULL DEFAULT 'manual',   -- manual|misp|connector
    imported  INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    skipped   INTEGER NOT NULL DEFAULT 0,
    status    TEXT NOT NULL DEFAULT 'completed', -- completed|partial|failed
    actor     TEXT,
    ts        TEXT NOT NULL
);

-- Analyst-authored CTI intel reports (campaign & report management).
CREATE TABLE IF NOT EXISTS intel_reports (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    tlp         TEXT NOT NULL DEFAULT 'amber',   -- white|green|amber|red
    status      TEXT NOT NULL DEFAULT 'draft',   -- draft|published
    summary     TEXT,
    body        TEXT,
    actors      TEXT NOT NULL DEFAULT '[]',      -- referenced actor names
    iocs        TEXT NOT NULL DEFAULT '[]',      -- referenced indicator values
    tags        TEXT NOT NULL DEFAULT '[]',
    author      TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Cached per-IOC enrichment results + history (enrichment pipeline).
CREATE TABLE IF NOT EXISTS ioc_enrichments (
    id        TEXT PRIMARY KEY,
    ioc_value TEXT NOT NULL,
    provider  TEXT NOT NULL,
    verdict   TEXT,
    summary   TEXT,
    data      TEXT NOT NULL DEFAULT '{}',
    ts        TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS scans (
    id         TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    target     TEXT NOT NULL,
    type       TEXT NOT NULL,       -- url|ip|hash|domain|file
    verdict    TEXT NOT NULL,       -- malicious|suspicious|clean
    score      REAL NOT NULL DEFAULT 0,
    engines    TEXT,                -- display ratio e.g. "41/90"
    actor      TEXT
);

CREATE TABLE IF NOT EXISTS suppressions (
    id         TEXT PRIMARY KEY,
    rule_id    TEXT NOT NULL DEFAULT '*',   -- specific rule id, or '*' for any
    field      TEXT NOT NULL DEFAULT 'src_ip',  -- src_ip|username|hostname
    value      TEXT NOT NULL,
    mode       TEXT NOT NULL DEFAULT 'suppress',  -- suppress (drop) | allow (auto-benign)
    reason     TEXT,
    hits       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    created_by TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id        TEXT PRIMARY KEY,
    ts        TEXT NOT NULL,
    type      TEXT NOT NULL,   -- alert|case|darkweb|connector|report|system
    severity  TEXT,            -- critical|high|medium|low|info
    title     TEXT NOT NULL,
    detail    TEXT,
    link      TEXT,
    read      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_notif_ts ON notifications(ts DESC);

CREATE TABLE IF NOT EXISTS report_schedules (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,            -- executive|siem|soar|cti|assets|darkweb
    period      TEXT NOT NULL DEFAULT 'weekly',
    cadence     TEXT NOT NULL DEFAULT 'weekly',  -- daily|weekly
    webhook_url TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run    TEXT,
    created_at  TEXT NOT NULL,
    created_by  TEXT
);

CREATE TABLE IF NOT EXISTS saved_views (
    id         TEXT PRIMARY KEY,
    section    TEXT NOT NULL,   -- siem|cti|assets|soar|darkweb
    name       TEXT NOT NULL,
    filters    TEXT NOT NULL DEFAULT '{}',
    owner      TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    ts           TEXT NOT NULL,
    category     TEXT,            -- auth|network|endpoint|web|cloud|identity
    event_type   TEXT,            -- failed_login|connection|process_start|…
    src_ip       TEXT,
    dest_ip      TEXT,
    dest_port    INTEGER,
    username     TEXT,
    hostname     TEXT,
    process_name TEXT,
    action       TEXT,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    country      TEXT,
    severity_hint TEXT,
    mitre_tech_id TEXT,
    raw          TEXT,
    processed    INTEGER NOT NULL DEFAULT 0   -- 0 until the detection pass evaluates it
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_proc ON events(processed);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname);

CREATE TABLE IF NOT EXISTS dark_web_findings (
    id        TEXT PRIMARY KEY,
    ts        TEXT NOT NULL,
    category  TEXT NOT NULL,   -- credential-leak|data-for-sale|brand-mention|actor-chatter|infrastructure
    severity  TEXT NOT NULL,   -- critical|high|medium|low
    source    TEXT,            -- forum/market/paste/telegram name
    title     TEXT NOT NULL,
    entity    TEXT,            -- affected email/domain/org
    actor     TEXT,
    detail    TEXT,
    url       TEXT,
    status    TEXT NOT NULL DEFAULT 'new'   -- new|investigating|mitigated|dismissed
);

CREATE TABLE IF NOT EXISTS connectors (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,                 -- threatorbit|otx|nvd|json|csv|stix
    url              TEXT,
    api_key          TEXT,
    auth_header      TEXT,                          -- header carrying api_key (kind default)
    enabled          INTEGER NOT NULL DEFAULT 1,
    interval_minutes INTEGER NOT NULL DEFAULT 60,
    field_map        TEXT NOT NULL DEFAULT '{}',    -- json/csv field→column mapping
    status           TEXT NOT NULL DEFAULT 'idle',  -- idle|running|ok|error
    last_run         TEXT,
    last_error       TEXT,
    indicator_count  INTEGER NOT NULL DEFAULT 0,
    builtin          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    created_by       TEXT
);

CREATE TABLE IF NOT EXISTS webhooks (
    id            TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    events        TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'active',  -- active|paused|failing
    last_delivery TEXT,
    created_at    TEXT NOT NULL,
    created_by    TEXT
);

-- Active login sessions (per-device): the JWT carries this row's id as `sid`,
-- so a single session can be listed and individually revoked without signing
-- the user out everywhere (the coarse kill-switch is users.token_epoch).
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    user_agent  TEXT,
    ip          TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);

-- Hot-path indexes: these columns are filtered/joined on every dashboard
-- refresh (queue sorts, entity lookups, TI value matching, run history).
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev_status ON alerts(severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(hostname);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(username);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status);
CREATE INDEX IF NOT EXISTS idx_iocs_actor ON iocs(actor);
CREATE INDEX IF NOT EXISTS idx_pbruns_alert ON playbook_runs(alert_id);
CREATE INDEX IF NOT EXISTS idx_pbruns_pb ON playbook_runs(playbook_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vuln_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_dw_url ON dark_web_findings(url);
CREATE INDEX IF NOT EXISTS idx_dw_cat ON dark_web_findings(category);
CREATE INDEX IF NOT EXISTS idx_sightings_ioc ON ioc_sightings(ioc_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_enrich_value ON ioc_enrichments(ioc_value, provider, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, revoked);
"""


def audit(conn: sqlite3.Connection, actor: str | None, action: str,
          target: str | None = None, detail: str | None = None):
    """Write a row to audit_log inside an open connection (caller must commit).
    Also mirrors the event to an external tamper-evident sink when configured."""
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
        (ts, actor, action, target, detail),
    )
    try:
        from dashboard_api.audit_sink import ship
        ship({"ts": ts, "actor": actor, "action": action, "target": target, "detail": detail})
    except Exception:  # the external mirror must never break an audited action
        pass


def record_job(conn: sqlite3.Connection, kind: str, status: str, meta: dict | None = None) -> str:
    """Insert a jobs row inside an open connection (caller must commit)."""
    import datetime
    import uuid
    ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    jid = str(uuid.uuid4())
    progress = 100 if status == "completed" else 0
    conn.execute(
        "INSERT INTO jobs (id, kind, status, progress, created_at, updated_at, meta) "
        "VALUES (?,?,?,?,?,?,?)",
        (jid, kind, status, progress, ts, ts, dumps(meta or {})),
    )
    return jid


# Columns added after the initial schema shipped. CREATE TABLE IF NOT EXISTS
# never alters an existing table, so additive columns are applied here for
# databases created before the column existed. (table, column, DDL type/default)
_MIGRATIONS = [
    ("saved_hunts", "status", "TEXT NOT NULL DEFAULT 'idle'"),
    ("saved_hunts", "progress", "INTEGER NOT NULL DEFAULT 0"),
    ("saved_hunts", "created", "TEXT"),
    ("alerts", "detect_latency_sec", "INTEGER"),
    ("alerts", "ack_latency_sec", "INTEGER"),
    ("alerts", "respond_latency_sec", "INTEGER"),
    ("detection_rules", "definition", "TEXT NOT NULL DEFAULT '{}'"),
    ("detection_rules", "mitre_tactic_id", "TEXT"),
    ("playbooks", "trigger_match", "TEXT NOT NULL DEFAULT '{}'"),
    ("iocs", "status", "TEXT NOT NULL DEFAULT 'active'"),
    ("iocs", "sightings", "INTEGER NOT NULL DEFAULT 1"),
    ("users", "org_id", "TEXT"),
    ("assets", "software", "TEXT NOT NULL DEFAULT '[]'"),
    ("dark_web_findings", "matched_user", "TEXT"),
    ("integrations", "base_url", "TEXT"),
    ("integrations", "api_key", "TEXT"),
    ("cases", "linked_cases", "TEXT NOT NULL DEFAULT '[]'"),
    ("saved_hunts", "schedule_minutes", "INTEGER NOT NULL DEFAULT 0"),
    ("saved_hunts", "last_scheduled", "TEXT"),
    ("saved_hunts", "auto_alert", "INTEGER NOT NULL DEFAULT 1"),
    ("report_schedules", "email", "TEXT"),
    ("vuln_findings", "kev", "INTEGER NOT NULL DEFAULT 0"),
    ("vuln_findings", "exploit", "INTEGER NOT NULL DEFAULT 0"),
    # Multi-tenancy isolation (reference pattern, alerts first): the column
    # defaults to the bootstrap workspace so single-tenant data is unchanged;
    # reads scope by it only when DASHBOARD_MULTI_TENANT is on.
    ("alerts", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("cases", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("iocs", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("assets", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("dark_web_findings", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("detection_rules", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    # …and the secondary stores (completes tenancy.TENANT_TABLES coverage).
    ("events", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("threat_actors", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("log_sources", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("feeds", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("connectors", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("playbooks", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("playbook_runs", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("saved_hunts", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("scans", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("suppressions", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("notifications", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("saved_views", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("report_schedules", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    # Per-user Slack notification routing (personal incoming-webhook URL +
    # the minimum severity that should reach it).
    ("users", "slack_webhook", "TEXT"),
    ("users", "slack_min_severity", "TEXT NOT NULL DEFAULT 'high'"),
    # Time-boxed / recurring suppression windows: an absolute expiry and an
    # optional daily HH:MM-HH:MM UTC window in which the suppression applies.
    # TOTP MFA: the user's enrolled secret (encrypted at rest via secretstore).
    ("users", "mfa_secret", "TEXT"),
    ("suppressions", "expires_at", "TEXT"),
    ("suppressions", "window_start", "TEXT"),
    ("suppressions", "window_end", "TEXT"),
    # Event-queue lease (event_queue.py): a detection worker claims a batch of
    # pending events by stamping its id + time, so a future worker POOL can split
    # the load without double-processing. NULL = unclaimed; a stale claim is
    # re-queued after the lease window.
    ("events", "claimed_by", "TEXT"),
    ("events", "claimed_at", "TEXT"),
    # Session revocation (auth.py): a monotonic counter embedded in each JWT as
    # `ep`. Bumping it invalidates every token issued earlier, so "sign out
    # everywhere" + auto-logout-on-password-change work over stateless JWTs.
    ("users", "token_epoch", "INTEGER NOT NULL DEFAULT 0"),
    # MFA recovery codes (auth.py): JSON array of SHA-256 hashes of one-time
    # backup codes, so a user who loses their authenticator can still get in.
    ("users", "mfa_recovery_codes", "TEXT"),
    # Outbound webhook signing secret (webhooks.py): each delivery is HMAC-signed
    # with this so subscribers can verify it genuinely came from ThreatOrbit.
    ("webhooks", "secret", "TEXT"),
    # Per-rule noise rating (content metadata, distinct from the observed fp_rate):
    # an authored low|medium|high expectation of how chatty a rule is, so analysts
    # can prioritise tuning before any real false-positive data accrues.
    ("detection_rules", "noise", "TEXT"),
]


def _apply_migrations(conn: sqlite3.Connection):
    from dashboard_api.db_backend import is_postgres, table_columns_sql
    for table, column, ddl in _MIGRATIONS:
        if is_postgres():  # pragma: no cover - opt-in backend
            rows = conn.execute(table_columns_sql(), (table,)).fetchall()
        else:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        cols = {r["name"] for r in rows}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _safe_schema(conn: sqlite3.Connection):
    """Apply the schema, tolerating index statements that reference columns a
    migration hasn't added yet (re-applied after migrations below)."""
    try:
        conn.executescript(SCHEMA)
    except sqlite3.OperationalError:
        # An index on a migrated column against a pre-migration table - run the
        # statements individually so everything else still applies.
        for stmt in SCHEMA.split(";"):
            s = stmt.strip()
            if not s:
                continue
            try:
                conn.execute(s)
            except sqlite3.OperationalError:
                pass


def init_db():
    with get_conn() as conn:
        _safe_schema(conn)
        _apply_migrations(conn)
        # second pass: indexes that needed migrated columns now succeed
        _safe_schema(conn)
        # Multi-tenancy foundation: ensure the default workspace exists and every
        # user belongs to one (non-breaking; single-tenant installs are unchanged).
        from dashboard_api.tenancy import ensure_default_org
        ensure_default_org(conn)
        conn.commit()
