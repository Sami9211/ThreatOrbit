"""WAL-mode SQLite layer for the dashboard API.

A single file database keeps the service zero-dependency and easy to run.
WAL mode allows concurrent reads while a write is in progress, which matters
for an API that serves many read requests against a periodically-seeded store.

Row access uses ``sqlite3.Row`` so callers get dict-like rows; the ``row_to_dict``
helper plus ``json_cols`` decoding turns a row into a JSON-ready dict, expanding
columns that hold serialized JSON (lists/objects) back into real structures.
"""
import json
import os
import sqlite3
from contextlib import contextmanager

from dashboard_api.config import DB_PATH

# Schema version for migration-gating on upgrade (HA/DR rollback safety). Bump
# this by 1 whenever a migration is added to `_MIGRATIONS` / the schema. The DB
# records the version it was last migrated to; on boot the code refuses to run
# against a DB that is NEWER than it understands (an older binary rolled back
# onto a newer schema) unless DASHBOARD_ALLOW_SCHEMA_DOWNGRADE is set. Migrations
# are additive-only, so a normal upgrade just applies the new columns and bumps.
SCHEMA_VERSION = 20


class SchemaVersionError(RuntimeError):
    """Raised at startup when the database schema is newer than this code."""

    def __init__(self, db_version: int, code_version: int):
        self.db_version, self.code_version = db_version, code_version
        super().__init__(
            f"Database schema version {db_version} is newer than this build "
            f"(supports {code_version}). This binary was likely rolled back onto a "
            f"newer schema. Deploy a build that supports schema {db_version}, or - "
            f"only if you have verified the schema is compatible - set "
            f"DASHBOARD_ALLOW_SCHEMA_DOWNGRADE=1 to override.")

# Columns that store JSON-encoded text and should be decoded on read.
JSON_COLUMNS = {
    "source_refs", "attack_ids", "malware_families", "targeted_countries", "industries",
    "tags", "open_ports", "cves", "steps", "actions", "aliases", "motivations",
    "motivation", "sectors", "ttps", "malware", "campaigns", "iocs", "entities",
    "war_room", "tasks", "evidence", "data_sources", "techniques", "related_iocs",
    "hypotheses", "meta", "config", "scopes", "events", "field_map", "definition", "filters",
    # Without this the aliases came back as a JSON STRING while `aliases` beside
    # it came back as a list, so the client would have rendered one of them as
    # `["Mummy Spider","Gold Crestwood"]` in quotes.
    "operator_aliases",
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
    ti_value        TEXT,             -- the indicator value that matched, whatever
                                      -- its type. `src_ip` only ever held it for IP
                                      -- indicators, so a domain match had nothing
                                      -- identifying it but its title - and the
                                      -- duplicate-suppression that reads it could
                                      -- never see one.
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

-- Tier hand-offs. A SOC is tiered - L1 triages, L2 investigates, L3 does
-- attribution and threat research - and the moment that matters is the hand-off:
-- who passed this on, to whom, and WHY. Without a record, an escalation is just
-- an owner field changing, and the receiving analyst starts from nothing.
--
-- Append-only history, kept separate from `cases` so a case carries its own
-- chain of custody rather than only its current state.
CREATE TABLE IF NOT EXISTS case_escalations (
    id         TEXT PRIMARY KEY,
    case_id    TEXT NOT NULL,
    from_tier  INTEGER,
    to_tier    INTEGER NOT NULL,
    from_owner TEXT,
    to_owner   TEXT,
    note       TEXT,               -- what the receiving analyst needs to know
    actor      TEXT NOT NULL,      -- who performed the hand-off
    ts         TEXT NOT NULL
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
    sightings   INTEGER NOT NULL DEFAULT 1,
    -- Hostname of a `url` indicator, extracted at insert. Lets "is this domain
    -- known-bad?" find URLs hosted on it with an indexed equality match instead
    -- of three leading-wildcard LIKEs over the whole table.
    host        TEXT
);

-- Which SOURCES asserted a given indicator value, one row per (value, source).
--
-- The import used to collapse this: an indicator carried a single `source`
-- string, and when a second feed listed the same value it was counted as a
-- duplicate and discarded. The platform pulls from 16 curated feeds and threw
-- away 15 opinions out of every 16. Corroboration - "how many independent
-- sources say this, and which" - is the single most useful signal a multi-feed
-- aggregator can produce, and it was not merely unshown but unrecorded.
--
-- Keyed on the value rather than an ioc id so the record survives an indicator
-- being expired, re-imported or garbage-collected: the assertion "feed X listed
-- this value on date Y" is true independently of our row for it.
CREATE TABLE IF NOT EXISTS observable_sources (
    value       TEXT NOT NULL,
    source_id   TEXT NOT NULL,      -- intel_sources.id
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    raw_label   TEXT,               -- what THIS source called it (threat type)
    confidence  INTEGER,            -- what THIS source claimed
    PRIMARY KEY (value, source_id)
);

-- Feeds as first-class records rather than free text repeated on every row.
-- `reliability` is the Admiralty grade (A most reliable .. F unassessable),
-- which is what turns a raw count of sources into a weighted judgement.
CREATE TABLE IF NOT EXISTS intel_sources (
    id           TEXT PRIMARY KEY,  -- stable slug, e.g. "osint:Maltrail malware domains"
    name         TEXT NOT NULL,
    kind         TEXT,              -- connector kind that produced it
    reliability  TEXT NOT NULL DEFAULT 'C',   -- Admiralty A..F; see connectors._FEED_RELIABILITY
    reliability_reason TEXT,        -- why, in words an analyst can argue with
    reliability_set_by TEXT,        -- NULL = shipped default, else the operator's email
    url          TEXT,
    served_via   TEXT,              -- mirror that answered when the origin would not
    last_status  TEXT,              -- ok | unchanged | mirrored | failed
    last_status_detail TEXT,        -- the error, in the words the exception used
    last_ok      TEXT,              -- when this source last actually answered
    first_seen   TEXT,
    last_seen    TEXT,
    value_count  INTEGER NOT NULL DEFAULT 0
);

-- Network ownership (which AS announces an address, and from where), loaded
-- from iptoasn.com's hourly BGP-derived table. See dashboard_api/asn.py.
--
-- Addresses are zero-padded hex, NOT integers: 8 chars for IPv4, 32 for IPv6.
-- That makes lexicographic comparison identical to numeric comparison on both
-- backends, where an integer column would have worked for IPv4 and silently
-- overflowed for IPv6.
CREATE TABLE IF NOT EXISTS asn_ranges (
    family      INTEGER NOT NULL,     -- 4 or 6
    start_hex   TEXT NOT NULL,
    end_hex     TEXT NOT NULL,
    asn         INTEGER NOT NULL,
    country     TEXT,
    description TEXT
);

-- Analyst conclusions, fed back into the intel store so the platform LEARNS.
--
-- Distinct from `iocs.status = 'known-good'`, which is a hard global whitelist
-- that switches matching off. A verdict is EVIDENCE: it carries a reason, an
-- author, a timestamp and a tenant, it accumulates as history, and it moves the
-- intel score rather than overriding it. Two analysts disagreeing is a real
-- state that the store should be able to represent.
--
-- Scoped per org on purpose: one tenant concluding "false positive in our
-- environment" must never silently suppress another tenant's intel.
CREATE TABLE IF NOT EXISTS ioc_verdicts (
    id         TEXT PRIMARY KEY,
    ioc_value  TEXT NOT NULL,          -- the VALUE, not the row id: verdicts
                                       -- outlive re-imports of the same value
    org_id     TEXT NOT NULL DEFAULT 'org-default',
    verdict    TEXT NOT NULL,          -- confirmed | false-positive | benign-here
    reason     TEXT,
    analyst    TEXT NOT NULL,
    ts         TEXT NOT NULL
);

-- First-party passive DNS: resolutions THIS deployment has actually observed.
-- Every other enrichment is somebody else's opinion; this is a fact observed
-- here, and no public CTI library can hold it for a given customer's
-- environment. See dashboard_api/passive_dns.py.
CREATE TABLE IF NOT EXISTS dns_observations (
    name         TEXT NOT NULL,
    address      TEXT NOT NULL,
    -- Same fixed-width hex as asn_ranges/iocs.ip_hex, so an observation can be
    -- range-matched against a BGP prefix without decoding it again.
    addr_hex     TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    times_seen   INTEGER NOT NULL DEFAULT 1,
    -- 'forward' | 'ptr' | 'both'. Both directions agreeing means the mapping is
    -- actually configured, which is a stronger claim than either alone.
    observed_via TEXT NOT NULL DEFAULT 'forward',
    PRIMARY KEY (name, address)
);

-- Decay policy as RECORDS rather than a Python dict, so how fast intel stops
-- being actionable is tunable per deployment instead of being one opinion baked
-- into the source. See dashboard_api/decay.py; the seeded rules reproduce the
-- previous hardcoded numbers exactly.
CREATE TABLE IF NOT EXISTS decay_rules (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    applies_to         TEXT NOT NULL DEFAULT '["*"]',  -- JSON list of ioc types, "*" = any
    half_life_days     INTEGER NOT NULL,
    revoke_score       INTEGER NOT NULL,               -- stops matching below this
    max_age_half_lives INTEGER NOT NULL DEFAULT 4,     -- hard ceiling regardless of score
    reaction_points    TEXT NOT NULL DEFAULT '[]',     -- JSON list of scores worth reporting
    enabled            INTEGER NOT NULL DEFAULT 1,
    builtin            INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL
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

-- In-flight import "work" (OpenCTI's model). An import used to be atomic and
-- invisible: nothing to see until it finished, so a running sync was
-- indistinguishable from a broken one. A work row is created when a sync starts
-- and UPDATED as each sub-batch lands, so the UI can show counts climbing live
-- and an operator can tell "ingesting 40k" from "hung".
CREATE TABLE IF NOT EXISTS connector_works (
    id           TEXT PRIMARY KEY,
    connector_id TEXT,
    connector    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running',  -- running|completed|failed
    expected     INTEGER NOT NULL DEFAULT 0,       -- indicators fetched, to process
    processed    INTEGER NOT NULL DEFAULT 0,
    imported     INTEGER NOT NULL DEFAULT 0,
    duplicates   INTEGER NOT NULL DEFAULT 0,
    skipped      INTEGER NOT NULL DEFAULT 0,
    message      TEXT,
    started_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_works_status ON connector_works(status, started_at DESC);

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
    updated_at  TEXT NOT NULL,
    org_id      TEXT NOT NULL DEFAULT 'org-default'
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

-- The `feeds` table held the same idea as `connectors`, and it was the loser of
-- the two: a row in it never imported anything. The scheduler reads
-- `connectors`; nothing has ever read `feeds` to fetch an indicator. So a feed
-- an operator added reported a reliability grade and a sync interval and did
-- nothing at all, for ever - and because live mode seeded no rows, the Threat
-- Feeds page read "from 0 sources · Total IOCs 0" over a store of 315,185.
--
-- Dropped rather than left in place. Rows in it were decoration: losing
-- decoration costs nothing, and continuing to show it as a configured source
-- costs the operator their trust in the page. /feeds is now a view over
-- connectors (see routers/feeds.py).
DROP TABLE IF EXISTS feeds;

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

-- Per-key request telemetry, day-bucketed (drives the real "requests today"/
-- totals in Config → API; incremented on every authenticated key request).
CREATE TABLE IF NOT EXISTS api_key_usage (
    key_id  TEXT NOT NULL,
    day     TEXT NOT NULL,     -- ISO date (UTC)
    count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, day)
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL
);

-- Leader election: a node holds a named lease (integer epoch expiry) and renews
-- it each tick, so singleton background loops run on exactly one app replica.
CREATE TABLE IF NOT EXISTS leader_lease (
    name        TEXT PRIMARY KEY,
    holder      TEXT NOT NULL DEFAULT '',
    expires_at  INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS malware_families (
    name             TEXT PRIMARY KEY,          -- normalised, matches iocs.malware_family
    label            TEXT NOT NULL,             -- display name ("AsyncRAT")
    role             TEXT NOT NULL,             -- what it DOES: loader, stealer, RAT...
    aliases          TEXT NOT NULL DEFAULT '[]',
    description      TEXT,
    -- Set on three of thirty-five. A family is what a source published; an
    -- operator is a claim somebody has to defend, and most of this catalogue is
    -- commodity - sold, leaked, open-source or cracked. `operator_reason` is
    -- filled either way: why we name one, or why we will not.
    operator         TEXT,
    operator_aliases TEXT NOT NULL DEFAULT '[]',
    operator_reason  TEXT,
    commodity        INTEGER NOT NULL DEFAULT 1,
    since            TEXT,
    -- Set when an operator rewrites an entry. The boot-time refresh skips those,
    -- so a corrected default reaches every install without overwriting anyone's
    -- own words. Same contract as the Admiralty grades.
    edited_by        TEXT,
    edited_at        TEXT
);

-- MITRE ATT&CK, reduced to the answers the family and actor pages ask of it.
-- See dashboard_api/attack.py; the full release is ~26,000 STIX objects and this
-- keeps a few thousand. Replaced wholesale on refresh rather than merged,
-- because ATT&CK revokes and deprecates in place: merging leaves retired
-- techniques attached to families forever, indistinguishable from current ones.
CREATE TABLE IF NOT EXISTS attack_technique (
    id             TEXT PRIMARY KEY,   -- T1055, T1055.011
    name           TEXT NOT NULL,
    tactics        TEXT NOT NULL DEFAULT '',  -- comma-separated kill-chain phases
    url            TEXT,               -- attack.mitre.org, so nothing here is unsourced
    description    TEXT,
    is_subtechnique INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attack_group (
    id          TEXT PRIMARY KEY,      -- G0008
    name        TEXT NOT NULL,
    aliases     TEXT NOT NULL DEFAULT '[]',
    url         TEXT,
    description TEXT
);

-- The bridge from what a feed told us (a family name) to what MITRE tracks.
-- Matched by name and alias; 20 of the 35 imported families resolve, and the
-- other fifteen are told they are untracked rather than shown a blank panel.
CREATE TABLE IF NOT EXISTS attack_software (
    family      TEXT PRIMARY KEY,      -- our key, matches iocs.malware_family
    id          TEXT NOT NULL,         -- S0154
    name        TEXT NOT NULL,
    url         TEXT,
    kind        TEXT NOT NULL DEFAULT 'malware',  -- ATT&CK files Cobalt Strike as a tool
    description TEXT
);

CREATE TABLE IF NOT EXISTS attack_family_technique (
    family       TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (family, technique_id)
);

-- Every group ATT&CK reports using a family. Deliberately NOT written to
-- `iocs.actor`: thirty groups use Cobalt Strike, so the family supports no claim
-- about who is behind a given indicator. The list is shown as the argument
-- against attributing from a family, not as an attribution.
CREATE TABLE IF NOT EXISTS attack_family_group (
    family   TEXT NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (family, group_id)
);

CREATE TABLE IF NOT EXISTS attack_group_technique (
    group_id     TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (group_id, technique_id)
);

-- Tactic display names and kill-chain order, from the matrix object rather than
-- hardcoded anywhere. ATT&CK renames tactics between releases (v19 replaced
-- "Defense Evasion" with "Stealth"), so a hardcoded list renders last year's
-- kill chain while claiming to quote MITRE.
CREATE TABLE IF NOT EXISTS attack_tactic (
    shortname TEXT PRIMARY KEY,       -- command-and-control
    name      TEXT NOT NULL,          -- Command and Control
    position  INTEGER NOT NULL DEFAULT 99
);

-- Which ATT&CK release is on the page. One row.
CREATE TABLE IF NOT EXISTS attack_release (
    version    TEXT,
    url        TEXT,
    fetched_at TEXT
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
-- Roll-up lookup: every grouped notification asks "is there an open bucket for
-- this key inside the window?" before writing, so that question must not be a
-- table scan. Added by migration, so it is created on the second schema pass.
CREATE INDEX IF NOT EXISTS idx_notif_group ON notifications(group_key, ts DESC);

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
    hostname     TEXT,            -- the REPORTING device (Computer/devname/observer)
    dest_host    TEXT,            -- the network name the event TARGETED: DNS query
                                  -- name, HTTP Host, proxy destination, TLS SNI.
                                  -- Distinct from `hostname`, which is the box
                                  -- that wrote the log. Without this there is no
                                  -- channel by which a domain or URL indicator can
                                  -- ever match local telemetry.
    url          TEXT,            -- full URL when the source carries one
    process_name TEXT,
    action       TEXT,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    country      TEXT,
    severity_hint TEXT,
    mitre_tech_id TEXT,
    raw          TEXT,
    source       TEXT,            -- ingest source name (collector|syslog-udp|…); 'engine' for synthetic
    processed    INTEGER NOT NULL DEFAULT 0,  -- 0 until the detection pass evaluates it
    ti_checked   INTEGER NOT NULL DEFAULT 0   -- 0 until threat-intel matching has
                                  -- examined it. Its OWN marker, because the
                                  -- detection queue owns `processed`: sharing one
                                  -- flag meant TI matching re-scanned the same
                                  -- events on every ingest, re-recording sightings
                                  -- and inflating the score term that outranks
                                  -- every feed.
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_proc ON events(processed);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_dest_host ON events(dest_host);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_ti ON events(ti_checked);

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

CREATE TABLE IF NOT EXISTS break_glass (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    reason         TEXT NOT NULL,
    activated_by   TEXT NOT NULL,
    activated_at   TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    deactivated_at TEXT,
    org_id         TEXT NOT NULL DEFAULT 'org-default'
);

CREATE TABLE IF NOT EXISTS user_org_roles (
    user_id    TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    role       TEXT NOT NULL,
    granted_by TEXT,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, org_id)
);

-- One-time-use cache for SAML assertion IDs (replay protection). DB-backed so
-- the check is shared across workers/replicas and survives a restart, not a
-- per-process in-memory set. Rows are pruned once past their validity window.
CREATE TABLE IF NOT EXISTS saml_replay (
    assertion_id TEXT PRIMARY KEY,
    expires_at   REAL NOT NULL
);

-- Delivery cursor for the external audit sink (outbox pattern). The committed
-- audit_log IS the durable queue; this single row records the last audit_log id
-- successfully delivered, so a sink outage or process restart replays the
-- undelivered tail instead of losing it (at-least-once, in id order).
CREATE TABLE IF NOT EXISTS audit_sink_cursor (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    last_id  INTEGER NOT NULL DEFAULT 0,
    updated  TEXT
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
-- Duplicate suppression for threat-intel matches runs on every ingest; a
-- beaconing host asks the same question every few seconds.
CREATE INDEX IF NOT EXISTS idx_alerts_ti_value ON alerts(ti_value);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status);
CREATE INDEX IF NOT EXISTS idx_iocs_actor ON iocs(actor);
-- Browse order. The CTI list pages with ORDER BY last_seen, id; without a
-- matching index every request built a temp B-tree over the WHOLE table, so
-- paging a 310k-indicator store cost ~1.6s per page and got worse with every
-- sync. Indexed, the same query is an index walk (~30ms at the far end). The id
-- tie-breaker is part of the key so the index satisfies the full order.
--
-- Only the default order is indexed, deliberately. The API also offers
-- sort=first_seen/confidence/severity, but nothing requests them and each extra
-- index is paid for on every insert: covering all of them halved bulk import
-- throughput at a million rows (18k -> 10k indicators/sec). Those sorts fall
-- back to a sort, which is fine for the filtered result sets they are used with.
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen DESC, id DESC);
-- Recency order for the rolling-history tables. Read by the jobs / import-history
-- views, and by the trim that keeps them bounded - without these the trim sorts
-- the whole table on every insert, and an insert happens on every sync. These
-- live down here with the other indexes because every table they name must
-- already exist: declared beside connector_works they referenced `jobs` and
-- `ioc_imports` before those tables were created, which aborted the rest of the
-- schema and left the database without an `events` table at all.
CREATE INDEX IF NOT EXISTS idx_works_started ON connector_works(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_imports_ts ON ioc_imports(ts DESC);
-- Covering index for the list's total. Given only the ordering index, the
-- planner answered `WHERE severity=? AND confidence>=?` from a non-covering
-- index and fetched a quarter-million rows purely to re-check severity (365ms
-- for one COUNT). With both columns in one index it is answered from the index
-- alone (~10ms).
CREATE INDEX IF NOT EXISTS idx_iocs_sev_conf ON iocs(severity, confidence);
-- Relevance order. Same rationale as the browse-order index: without it, sorting
-- 315k rows by score rebuilds a temp B-tree on every page.
-- Includes last_seen because the score list breaks its (very large) ties on
-- recency: without it that ORDER BY is a sort of the whole table. A new NAME
-- rather than a redefinition, because CREATE INDEX IF NOT EXISTS is a no-op
-- against the two-column index an upgraded database already has - the change
-- would silently never apply.
CREATE INDEX IF NOT EXISTS idx_iocs_score_recent
    ON iocs(intel_score DESC, last_seen DESC, id DESC);
DROP INDEX IF EXISTS idx_iocs_score;
-- "What else belongs to this family?" turns one domain into a piece of named
-- infrastructure, and it is the pivot an analyst reaches for first once an
-- indicator has a family at all. Added by migration, so the second schema pass
-- creates it.
CREATE INDEX IF NOT EXISTS idx_iocs_family ON iocs(malware_family);
CREATE INDEX IF NOT EXISTS idx_iocs_host ON iocs(host);
-- Pivots from one indicator to everything that shares its provenance. Without
-- this, "what else came from this report?" scans the whole table, and the
-- indicator drawer that asks the question on every open becomes unusable at
-- 315k rows.
CREATE INDEX IF NOT EXISTS idx_iocs_report ON iocs(report_id);
-- Network-range pivot: "everything we hold inside this AS's announced range",
-- as an indexed BETWEEN over the same hex encoding asn_ranges uses.
CREATE INDEX IF NOT EXISTS idx_iocs_ip_hex ON iocs(ip_hex);
-- Sibling clustering: every name registered under the same domain.
CREATE INDEX IF NOT EXISTS idx_iocs_reg_domain ON iocs(reg_domain);
-- "What is about to be revoked?" as a range scan over stored timestamps.
CREATE INDEX IF NOT EXISTS idx_iocs_valid_until ON iocs(valid_until);
-- The passive-DNS pivot: every name observed resolving to one address. The
-- (name,address) primary key already serves the forward direction.
-- The scoring path reads verdicts per value, per tenant, on every rescore.
CREATE INDEX IF NOT EXISTS idx_verdicts_value ON ioc_verdicts(ioc_value, org_id);
-- A case's chain of custody, read every time its detail is opened.
CREATE INDEX IF NOT EXISTS idx_escalations_case ON case_escalations(case_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_address ON dns_observations(address);
CREATE INDEX IF NOT EXISTS idx_dns_addr_hex ON dns_observations(addr_hex);
-- Only the reverse direction needs its own index. Corroboration looks up
-- value -> sources, which the PRIMARY KEY (value, source_id) already serves as
-- its leading column; a second index on value alone is pure insert cost -
-- measured at 157k -> 220k rows/s once removed.
CREATE INDEX IF NOT EXISTS idx_obs_src_source ON observable_sources(source_id);
-- Range lookup: "last range starting at or before this address". Without it,
-- every enrichment of an IP scans ~700k rows.
CREATE INDEX IF NOT EXISTS idx_asn_start ON asn_ranges(family, start_hex);
-- Pivot the other way: every indicator this deployment holds in one AS.
CREATE INDEX IF NOT EXISTS idx_asn_asn ON asn_ranges(asn);
CREATE INDEX IF NOT EXISTS idx_pbruns_alert ON playbook_runs(alert_id);
CREATE INDEX IF NOT EXISTS idx_pbruns_pb ON playbook_runs(playbook_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vuln_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_dw_url ON dark_web_findings(url);
CREATE INDEX IF NOT EXISTS idx_dw_cat ON dark_web_findings(category);
CREATE INDEX IF NOT EXISTS idx_sightings_ioc ON ioc_sightings(ioc_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_enrich_value ON ioc_enrichments(ioc_value, provider, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, revoked);
CREATE INDEX IF NOT EXISTS idx_break_glass_user ON break_glass(user_id, deactivated_at);
CREATE INDEX IF NOT EXISTS idx_user_org_roles_org ON user_org_roles(org_id);
CREATE INDEX IF NOT EXISTS idx_saml_replay_exp ON saml_replay(expires_at);
-- The actor page asks "what does this group do?", which is a scan of
-- 4,628 rows by group without it.
CREATE INDEX IF NOT EXISTS idx_attack_group_tech ON attack_group_technique(group_id);
CREATE INDEX IF NOT EXISTS idx_attack_family_group ON attack_family_group(group_id);
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


# Operational history is a rolling window, not an archive. One row lands per
# connector sync in each of jobs / ioc_imports / connector_works, and connector
# cadences are settable down to one second - so three sources on a 1s cadence
# write ~260k rows a day between them, forever. These tables answer "what
# happened recently"; the UI reads at most a couple of hundred rows from any of
# them. Caps are generous enough to cover a long look-back and env-tunable.
HISTORY_KEEP_JOBS = int(os.environ.get("DASHBOARD_KEEP_JOBS", "2000"))
HISTORY_KEEP_IMPORTS = int(os.environ.get("DASHBOARD_KEEP_IMPORTS", "2000"))
HISTORY_KEEP_WORKS = int(os.environ.get("DASHBOARD_KEEP_WORKS", "500"))


def trim_history(conn, table: str, keep: int, order_col: str, protect: str | None = None) -> int:
    """Keep only the newest `keep` rows of a rolling-history table.

    `protect` is an SQL condition for rows that must survive regardless of age -
    an in-flight work record must never be deleted out from under the import
    that is still writing progress to it.

    Table/column names here are module constants, never user input."""
    if keep <= 0:
        return 0
    guard = f" AND NOT ({protect})" if protect else ""
    return conn.execute(
        f"DELETE FROM {table} WHERE id NOT IN "
        f"(SELECT id FROM {table} ORDER BY {order_col} DESC LIMIT ?){guard}",
        (keep,)).rowcount


def record_ioc_import(conn, source: str, method: str, imported: int, duplicates: int,
                      skipped: int, actor: str, error: str | None = None,
                      duration_ms: int = 0) -> str:
    """Insert an `ioc_imports` row (caller commits) - the Feeds → Import log.

    EVERY path that puts indicators into the store must call this, not just the
    manual/MISP routes: connector syncs used to write only a `jobs` row, so an
    OTX or NVD pull of thousands of indicators left the import history empty and
    the operator saw "no imports" no matter how much real intel had landed.
    Failures are recorded too (imported=0 + the error), because a sync that
    failed is exactly what an operator needs to see."""
    import datetime
    import uuid
    status = ("failed" if error else
              "completed" if imported and not skipped else
              "partial" if imported else "failed")
    iid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO ioc_imports (id,source,method,imported,duplicates,skipped,status,actor,ts,"
        "duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (iid, (source or "unknown")[:120], method, imported, duplicates, skipped, status, actor,
         datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
         max(0, int(duration_ms))),
    )
    trim_history(conn, "ioc_imports", HISTORY_KEEP_IMPORTS, "ts")
    return iid


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
    trim_history(conn, "jobs", HISTORY_KEEP_JOBS, "created_at")
    return jid


# Columns added after the initial schema shipped. CREATE TABLE IF NOT EXISTS
# never alters an existing table, so additive columns are applied here for
# databases created before the column existed. (table, column, DDL type/default)
_MIGRATIONS = [
    # Sub-minute connector cadence. `interval_seconds` is the source of truth;
    # `interval_minutes` is kept in sync for backward compatibility. 0/NULL means
    # "fall back to interval_minutes * 60".
    ("connectors", "interval_seconds", "INTEGER NOT NULL DEFAULT 0"),
    # How long an import took, so the UI can show real throughput
    # (indicators/sec) instead of only a count - what an analyst needs to
    # judge whether a feed is healthy or degrading.
    ("ioc_imports", "duration_ms", "INTEGER NOT NULL DEFAULT 0"),
    # Per-connector state (OpenCTI calls this the connector "state"): HTTP
    # validators per feed URL so a re-sync can ask "changed since last time?"
    # instead of re-downloading and re-parsing an identical list every cycle.
    ("connectors", "state", "TEXT NOT NULL DEFAULT '{}'"),
    # Pulse-shaped intel import (the AlienVault OTX / OpenCTI model). An
    # indicator is not a free-floating value: it belongs to a REPORT that carries
    # the attribution and TTPs. Imports populate intel_reports and link each
    # indicator back to it, so an analyst can answer "what campaign is this part
    # of, who is behind it, which ATT&CK techniques, and where is the source
    # reporting" instead of seeing a bare IP with a feed name.
    ("intel_reports", "source", "TEXT"),              # otx | osint | misp | manual
    ("intel_reports", "external_id", "TEXT"),         # upstream pulse id (upsert key)
    # `references` is a reserved word in SQL - use an unambiguous name so no
    # statement needs quoting on either backend.
    ("intel_reports", "source_refs", "TEXT NOT NULL DEFAULT '[]'"),
    ("intel_reports", "attack_ids", "TEXT NOT NULL DEFAULT '[]'"),
    ("intel_reports", "malware_families", "TEXT NOT NULL DEFAULT '[]'"),
    ("intel_reports", "targeted_countries", "TEXT NOT NULL DEFAULT '[]'"),
    ("intel_reports", "industries", "TEXT NOT NULL DEFAULT '[]'"),
    ("iocs", "report_id", "TEXT"),                    # the pulse/report it came from
    ("iocs", "host", "TEXT"),                         # host of a url indicator (see _backfill_ioc_hosts)
    # Fixed-width hex of an `ip` indicator's address, so "what else do we hold in
    # this network range?" is an indexed BETWEEN instead of a scan that decodes
    # every address in Python. Same encoding as asn_ranges (see asn.hex_key), so
    # the two compare directly.
    ("iocs", "ip_hex", "TEXT"),                       # see _backfill_ioc_ip_hex
    # Registrable domain of a domain/url indicator, so sibling clustering
    # (`login.x.test` next to `mail.x.test`) is an indexed equality match rather
    # than a leading-wildcard LIKE no index can serve. See _backfill_ioc_reg_domain.
    ("iocs", "reg_domain", "TEXT"),
    # When this indicator reaches its decay rule's revoke score. Derived and
    # stored so "what expires this week?" is a range scan rather than a decay
    # computation over every row. See decay.valid_until.
    ("iocs", "valid_until", "TEXT"),
    # SOC tier currently working the case: 1 triage, 2 investigation, 3 threat
    # research / attribution. Defaults to 1 so every existing case is where a
    # case starts, rather than silently appearing to have been escalated.
    ("cases", "tier", "INTEGER NOT NULL DEFAULT 1"),
    # What the investigation actually FOUND. A case that closes with a status and
    # no finding teaches nobody anything, and the next analyst who meets the same
    # infrastructure starts from scratch.
    ("cases", "conclusion", "TEXT"),
    ("cases", "outcome", "TEXT"),          # true-positive | false-positive | benign | inconclusive
    ("cases", "closed_at", "TEXT"),
    # The network name an event TARGETED, and the URL it carried. `hostname` is
    # the reporting device, so before these there was no field a domain or URL
    # indicator could ever match against - which left 79% of the intel store
    # structurally unable to fire on local telemetry no matter how good it was.
    ("events", "dest_host", "TEXT"),
    ("events", "url", "TEXT"),
    # Threat-intel matching's own progress marker. `processed` belongs to the
    # detection queue and is set to 1 the moment detection completes, so a TI
    # pass keyed off it re-examined the same events on every ingest, recording
    # a fresh sighting each time. Sightings feed the score term that outranks
    # any amount of third-party agreement, so that inflation went straight into
    # the ranking.
    ("events", "ti_checked", "INTEGER NOT NULL DEFAULT 0"),
    # The indicator value a threat-intel alert matched, whatever its type.
    ("alerts", "ti_value", "TEXT"),
    # Why a source carries the Admiralty grade it does, and who decided. The
    # grade is a MULTIPLIER on every score that source contributes, so a number
    # nobody can interrogate is one they are right to distrust. NULL `set_by`
    # means the shipped default is in force and may be revised on upgrade; an
    # operator's own grading is never overwritten.
    # The URL that actually served this source's data, when it was not the
    # source's own. Set when a feed's origin is unreachable from this host and a
    # mirror republishing the same list was used instead - the source_id is
    # deliberately unchanged, so without this the operator would be told the
    # origin is healthy while it is refusing the connection. NULL = fetched
    # directly, which is also what a recovered origin resets it to.
    ("intel_sources", "served_via", "TEXT"),
    # How this source's LAST fetch actually went, and when it last answered.
    # A feed that dies is otherwise invisible: it logs a warning nobody reads and
    # contributes an empty list, which at the tally is indistinguishable from a
    # feed with nothing new. Thirty-five malware-family trails 404ed for days
    # that way. `last_ok` only moves forward, so a failing feed keeps the
    # timestamp that turns "failing" into "failing since Tuesday".
    ("intel_sources", "last_status", "TEXT"),
    ("intel_sources", "last_status_detail", "TEXT"),
    ("intel_sources", "last_ok", "TEXT"),
    ("intel_sources", "reliability_reason", "TEXT"),
    ("intel_sources", "reliability_set_by", "TEXT"),
    # Earliest time a rate-limited provider will accept us again. Set from a 429
    # (Retry-After); the scheduler skips the connector until it passes, so we
    # stop retrying into a limit we have already been told about.
    ("connectors", "next_allowed_at", "TEXT"),
    # Composite intel score, persisted so the store can be SORTED by it. Ranking
    # 315k indicators by relevance is the whole point; computing the score per
    # page would only re-order the page, leaving page one whatever arrived last.
    ("iocs", "intel_score", "INTEGER NOT NULL DEFAULT 0"),
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
    # Event→source attribution: lets the sources page compute a LIVE per-source
    # events/24h instead of the registration-time total_events_24h snapshot.
    ("events", "source", "TEXT"),
    # …and the secondary stores (completes tenancy.TENANT_TABLES coverage).
    ("events", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("threat_actors", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("log_sources", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("connectors", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("playbooks", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("playbook_runs", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("saved_hunts", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("scans", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("suppressions", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("notifications", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    # Notification roll-up. The bell is a DIGEST, not a mirror of the alert
    # queue: one detection pass over a busy batch raises dozens of alerts, and a
    # run that wrote one notification each filled all thirty rows of the bell
    # with alerts and pushed everything else - a playbook completing, a
    # connector failing - off the page entirely. `group_key` names the bucket a
    # notification belongs to and `rollup_count` how many landed in it, so a
    # burst reads "7 critical alerts" on one row instead of burying the bell.
    # NULL group_key = ungrouped, which is every notification that existed
    # before this and every one-off since.
    # The malware family a source ASSERTED for this indicator. Distinct from
    # `actor`, which several call sites were quietly using for it - a family is
    # not a group. AsyncRAT is sold to anyone who wants it; naming the family is
    # a fact the feed states, naming the operator is an assessment somebody has
    # to be able to defend. Keeping them in one column made the second look like
    # the first.
    #
    # Measured before this existed: of 322,421 indicators in a live store, 0%
    # carried an actor and 0% carried a report. Not a code gap - the nine feeds
    # reachable from that deployment are bulk blocklists that genuinely publish
    # neither. The families do publish one, per file.
    ("iocs", "malware_family", "TEXT"),
    ("notifications", "group_key", "TEXT"),
    ("notifications", "rollup_count", "INTEGER NOT NULL DEFAULT 1"),
    ("saved_views", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    ("report_schedules", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    # Org-scoped API keys: a service principal authenticating with this key acts
    # in this workspace, so a non-interactive collector ingests per-tenant.
    ("api_keys", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
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
    # Webhook tenant ownership: deliveries + CRUD scope to this org when isolation
    # is on, so one org's webhook can't receive (or be managed across) another's.
    ("webhooks", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
    # MFA anti-replay: the last accepted TOTP time-step counter at login, so a
    # still-valid code can't be reused inside its ±1-step window.
    ("users", "mfa_last_counter", "INTEGER"),
    # Intel-report tenant ownership: reports were missed from the tenancy pass, so
    # under multi-tenancy every workspace could read every other's reports. Scope
    # them like the rest of TENANT_TABLES (default keeps single-tenant unchanged).
    ("intel_reports", "org_id", "TEXT NOT NULL DEFAULT 'org-default'"),
]


def _apply_migrations(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    """Add any missing columns. Returns the (table, column) pairs actually added.

    The return value matters for migrations whose correct one-time action depends
    on the column having JUST appeared - `events.ti_checked` marks the existing
    backlog as already examined, which is right exactly once and wrong on every
    boot after."""
    from dashboard_api.db_backend import is_postgres, table_columns_sql
    added: set[tuple[str, str]] = set()
    for table, column, ddl in _MIGRATIONS:
        if is_postgres():  # pragma: no cover - opt-in backend
            rows = conn.execute(table_columns_sql(), (table,)).fetchall()
        else:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        cols = {r["name"] for r in rows}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            added.add((table, column))
    return added


def split_statements(sql: str) -> list[str]:
    """Split a SQL script into statements, ignoring `;` inside comments/strings.

    `sql.split(";")` is not a SQL parser, and the schema is full of prose
    comments. One of them - `-- ingest source name (collector|syslog-udp|…;
    'engine' for synthetic)` - contains a semicolon, which split the `events`
    CREATE TABLE in half; Postgres then reported `syntax error at end of input`
    and the table was never created. 25 of the 89 fragments the naive split
    produced were not statements at all. SQLite hid this because it takes the
    whole script through executescript(); only the per-statement fallback (used
    on Postgres, and on SQLite whenever the script errors) went through here."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    in_squote = in_dquote = in_line_comment = in_block_comment = False
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                buf.append(ch)
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_squote:
            buf.append(ch)
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            buf.append(ch)
            if ch == '"':
                in_dquote = False
            i += 1
            continue
        if ch == "-" and nxt == "-":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == "'":
            in_squote = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dquote = True
            buf.append(ch)
            i += 1
            continue
        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def _safe_schema(conn: sqlite3.Connection):
    """Apply the schema, tolerating index statements that reference columns a
    migration hasn't added yet (re-applied after migrations below).

    Backend note: the tolerant path must catch the *backend's* error type (a
    psycopg UndefinedColumn is not a sqlite3.OperationalError), and on Postgres
    a failed statement aborts the whole transaction - so the fallback commits
    each successful statement and rolls back after each failure, otherwise every
    statement after the first bad index would fail with InFailedSqlTransaction
    and an existing deployment could not boot across this upgrade."""
    def _rollback():
        try:
            conn.rollback()
        except Exception:
            pass

    try:
        conn.executescript(SCHEMA)
    except Exception:
        # An index on a migrated column against a pre-migration table - run the
        # statements individually so everything else still applies.
        _rollback()
        for stmt in split_statements(SCHEMA):
            try:
                conn.execute(stmt)
                conn.commit()
            except Exception:
                _rollback()


def host_of(value: str, ioc_type: str = "") -> str | None:
    """Hostname of a URL indicator, for the indexed `iocs.host` column.

    Only URLs get one: for ip/domain rows the value IS the host, and storing it
    twice would just double the index for no lookup we make."""
    v = (value or "").strip()
    if "://" not in v:
        return None
    if ioc_type and ioc_type != "url":
        return None
    from urllib.parse import urlparse
    try:
        return (urlparse(v).hostname or "").strip(".").lower() or None
    except (ValueError, TypeError):
        return None


# Where the registrable boundary sits for multi-label suffixes. A partial Public
# Suffix List: getting `co.uk` wrong would make every `*.co.uk` a "sibling" of
# every other, which is a fabricated relationship presented as evidence. Anything
# unlisted falls back to the last two labels, which is right for the
# overwhelming majority of TLDs.
#
# TWO kinds of entry, both needed for the same reason:
#
#  * registry suffixes (`co.uk`) - the registry sells the level below.
#  * PLATFORM suffixes (`vercel.app`, `github.io`) - free hosting, where every
#    subdomain is a DIFFERENT tenant. These matter as much as the ccTLDs: in the
#    real store, `000webhostapp.com` has 4,912 subdomains and `vercel.app` 2,837.
#    Without them, opening any one of those indicators claimed 4,911 "siblings
#    under the same registration" - 4,911 unrelated people abusing one free host,
#    presented to an analyst as a single actor's cluster. Meanwhile a genuine DGA
#    cluster like `corolain.ru` (1,940 generated subdomains, one registration)
#    is exactly what the pivot SHOULD surface, and still does.
#
# This list is deliberately partial and cannot be otherwise without shipping the
# real PSL: a platform not listed here will over-cluster. The entries below are
# the ones actually observed in this deployment's feeds, highest-volume first.
_MULTI_LABEL_SUFFIXES = frozenset({
    # Free hosting / dynamic DNS / preview platforms - one tenant per subdomain.
    "000webhostapp.com", "vercel.app", "appspot.com", "r.appspot.com",
    "github.io", "xsph.ru",
    "blogspot.com", "pages.dev", "weebly.com", "duckdns.org", "ddns.net",
    "wcomhost.com", "repl.co", "cprapid.com", "netlify.app", "web.app",
    "firebaseapp.com", "workers.dev", "herokuapp.com", "azurewebsites.net",
    "glitch.me", "surge.sh", "neocities.org", "wixsite.com", "myshopify.com",
    "trycloudflare.com", "ngrok.io", "ngrok-free.app", "r2.dev", "loca.lt",
    "hopto.org", "no-ip.org", "serveo.net", "onrender.com", "fleek.co",
    # Registry suffixes.
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "web.za",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw",
    "co.kr", "or.kr", "go.kr",
    "com.pl", "com.ua", "com.ru", "co.il", "com.my", "co.id", "com.ph",
})


def registrable_domain(host: str) -> str | None:
    """The part someone registered: `login.mail.x.co.uk` -> `x.co.uk`.

    None for anything that is not a multi-label hostname, so no caller can build
    a "sibling" group out of a bare TLD or a dotted-quad.
    """
    h = (host or "").strip().strip(".").lower()
    if not h or "/" in h or ":" in h:
        return None
    labels = h.split(".")
    if len(labels) < 2 or any(not part for part in labels):
        return None
    if labels[-1].isdigit():                  # dotted-quad, not a domain
        return None
    # LONGEST suffix wins. `r.appspot.com` is itself a platform suffix, and
    # testing only the last two labels would match `appspot.com` first and
    # resolve `x.r.appspot.com` to `r.appspot.com` - the platform again, which is
    # the exact over-clustering the list exists to prevent.
    for take in (3, 2):
        if len(labels) > take and ".".join(labels[-take:]) in _MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-(take + 1):])
    return ".".join(labels[-2:])


def reg_domain_of(value: str, ioc_type: str = "") -> str | None:
    """Registrable domain for the indexed `iocs.reg_domain` column.

    Sibling clustering - `login.x.test` next to `mail.x.test`, which is how
    phishing kits and generated-domain families surface - needs an EQUALITY
    match. Done as `host LIKE '%.x.test'` it is a leading wildcard, which no
    index can serve: measured at 512 ms per lookup over 315k rows, on a query
    the indicator drawer runs every time it opens.
    """
    t = (ioc_type or "").lower()
    if t == "url":
        host = host_of(value, "url")
    elif t == "domain":
        host = (value or "").strip().strip(".").lower()
    else:
        return None
    return registrable_domain(host or "")


def ip_hex_of(value: str, ioc_type: str = "") -> str | None:
    """Fixed-width hex of an IP indicator, for the indexed `iocs.ip_hex` column.

    Same encoding as `asn.hex_key`, so an indicator and a BGP range compare
    directly and "everything we hold in this AS's range" is an indexed BETWEEN.
    Only `ip` rows get one; a domain has no address to compare.
    """
    v = (value or "").strip()
    if ioc_type and ioc_type != "ip":
        return None
    import ipaddress
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    return format(int(ip), "0%dx" % (8 if ip.version == 4 else 32))


def _backfill_ioc_ip_hex(conn) -> int:
    """Populate `iocs.ip_hex` for IP rows imported before the column existed.

    Runs once per database: afterwards every ip row either has a key or has been
    examined and genuinely cannot have one, so the WHERE clause matches nothing
    on later boots. Without it, the network pivot would silently see only
    indicators imported after the upgrade - a view that gets quietly less
    complete over time, which is worse than one that is slow.
    """
    rows = conn.execute(
        "SELECT id, value FROM iocs WHERE type='ip' AND ip_hex IS NULL").fetchall()
    updates = [(h, r["id"]) for r in rows if (h := ip_hex_of(r["value"], "ip"))]
    if updates:
        conn.executemany("UPDATE iocs SET ip_hex=? WHERE id=?", updates)
    return len(updates)


def _backfill_ioc_reg_domain(conn) -> int:
    """Populate `iocs.reg_domain` for domain/url rows imported before the column.

    Runs once per database: afterwards every domain/url row either has a value or
    has been examined and genuinely has none, so the WHERE clause matches nothing
    on later boots. Without it the sibling pivot would see only indicators
    imported after the upgrade - a view that silently gets less complete, which
    is the failure mode this project keeps having to hunt down.
    """
    rows = conn.execute(
        "SELECT id, value, type FROM iocs "
        "WHERE reg_domain IS NULL AND type IN ('domain','url')").fetchall()
    updates = [(d, r["id"]) for r in rows if (d := reg_domain_of(r["value"], r["type"]))]
    if updates:
        conn.executemany("UPDATE iocs SET reg_domain=? WHERE id=?", updates)
    return len(updates)


def _backfill_ioc_hosts(conn) -> int:
    """Populate `iocs.host` for URL rows imported before the column existed.

    Runs once per database: after this, every URL row either has a host or has
    been examined and genuinely has none, so the WHERE clause matches nothing on
    subsequent boots. Without the backfill, "is this domain known-bad?" would
    silently stop finding URLs hosted on it for everything already imported -
    a lookup that quietly gets less accurate after an upgrade is worse than one
    that is slow."""
    # The pattern is BOUND, not inlined. psycopg reads `%` in the SQL text as a
    # placeholder marker, so the literal `'%://%'` raised "only '%s', '%b', '%t'
    # are allowed as placeholders, got '%:'" and the backfill failed on every
    # Postgres boot - silently, because the caller logs and continues. That is
    # exactly the quiet degradation this function exists to prevent: pre-upgrade
    # URLs keep answering exact lookups while dropping out of domain queries.
    rows = conn.execute(
        "SELECT id, value, type FROM iocs WHERE host IS NULL AND value LIKE ?",
        ("%://%",),
    ).fetchall()
    updates = [(h, r["id"]) for r in rows if (h := host_of(r["value"], r["type"]))]
    if updates:
        conn.executemany("UPDATE iocs SET host=? WHERE id=?", updates)
    return len(updates)


def _backfill_source_assertions(conn) -> int:
    """Seed observable_sources from the `source` already on each indicator.

    Without this, corroboration only knows about values imported AFTER the
    feature landed. Feeds use conditional GET, so an unchanged feed is never
    re-fetched and its indicators would never acquire an assertion row - on a
    stable store that is effectively never. Every existing row is itself the
    record of one source asserting one value; this states that explicitly so the
    count starts from the truth rather than from zero.

    Runs once: after it, every ioc has at least its own source recorded, so the
    NOT EXISTS clause matches nothing on later boots."""
    rows = conn.execute(
        "SELECT value, source, first_seen, last_seen, threat_type, confidence "
        "FROM iocs WHERE source IS NOT NULL AND source != '' "
        "AND NOT EXISTS (SELECT 1 FROM observable_sources os "
        "                WHERE os.value = iocs.value AND os.source_id = iocs.source)"
    ).fetchall()
    if not rows:
        return 0
    now = _utc_now_iso()
    payload = [(r["value"], r["source"][:200], r["first_seen"] or now,
                r["last_seen"] or now, (r["threat_type"] or "")[:120],
                r["confidence"], r["last_seen"] or now) for r in rows]
    conn.executemany(
        "INSERT INTO observable_sources (value,source_id,first_seen,last_seen,"
        "raw_label,confidence) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(value,source_id) DO UPDATE SET last_seen=?", payload)
    seen = {r["source"][:200] for r in rows}
    conn.executemany(
        "INSERT INTO intel_sources (id,name,first_seen,last_seen) VALUES (?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET last_seen=?",
        [(sid, sid, now, now, now) for sid in seen])
    return len(payload)


def _seed_malware_catalogue(conn) -> int:
    """Ship what we know about each malware family, without overwriting edits."""
    from dashboard_api.malware import seed
    return seed(conn)


def _apply_feed_reliability_defaults(conn) -> int:
    """Grade the feeds we ship, without ever overwriting an operator's judgement.

    The composite score multiplies every claim by its source's Admiralty grade -
    the correct shape, and completely inert while every source sat at the default
    C. Uniform across 327,981 indicators, the multiplier differentiated nothing:
    the store held 20 distinct scores, 95% of them inside a 15-point band, so the
    list an analyst opens "sorted by relevance" opened on whichever phishing
    domain happened to sort first alphabetically.

    Re-applied on every boot rather than seeded once, so a revised default
    reaches existing installs - which is safe precisely because a source the
    operator has graded (`reliability_set_by` set) is excluded. Their judgement
    outranks ours; that is the whole point of making it editable."""
    from dashboard_api.connectors import feed_reliability_defaults
    updates = []
    for sid, (grade, reason) in feed_reliability_defaults().items():
        row = conn.execute(
            "SELECT reliability, reliability_reason, reliability_set_by "
            "FROM intel_sources WHERE id=?", (sid,)).fetchone()
        if row is None or row["reliability_set_by"]:
            continue
        if row["reliability"] == grade and row["reliability_reason"] == reason:
            continue
        updates.append((grade, reason, sid))
    if updates:
        conn.executemany(
            "UPDATE intel_sources SET reliability=?, reliability_reason=? WHERE id=?",
            updates)
    return len(updates)


def _adopt_existing_events(conn) -> int:
    """Declare the pre-`ti_checked` event backlog already threat-intel checked.

    Every event that existed before the column did HAS been through the matching
    pass - repeatedly, in fact, which is the bug the column fixes: the pass keyed
    off `processed`, which the detection queue sets the moment detection
    completes, so each ingest re-examined the same recent events and recorded a
    fresh sighting every time. Re-examining that backlog now would add a second
    sighting for observations already counted, and sightings feed the one score
    term that outranks any amount of third-party agreement.

    Called only from the boot where the column is first added, so it runs exactly
    once - on every later boot the column exists and nothing is adopted."""
    return conn.execute("UPDATE events SET ti_checked=1").rowcount


def _reclassify_severities(conn) -> int:
    """One-time: rebuild `iocs.severity` from the activity each feed named.

    Severity used to be a monotone function of confidence, so the column held no
    information the confidence column did not already have. On a real 315k store
    that produced `malware-distribution` at 50,181 "medium" and 50,024 "high" -
    one activity, two severities, decided by nothing but the number beside it -
    and left 81% of every indicator reading "high".

    NVD rows are left alone: their severity is the published CVSS band, which is
    a real external judgement rather than something we derived.

    Gated on a settings flag rather than a WHERE clause because, unlike the other
    backfills, this one is not self-limiting - an analyst who corrects a severity
    by hand must not have it overwritten on the next boot.
    """
    done = conn.execute(
        "SELECT value FROM settings WHERE key='severity_reclassified'").fetchone()
    if done:
        return 0
    from dashboard_api.connectors import severity_for
    rows = conn.execute(
        "SELECT id, threat_type, tags, severity FROM iocs "
        "WHERE source IS NULL OR source != 'nvd'").fetchall()
    updates = []
    for r in rows:
        tags = r["tags"]
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (ValueError, TypeError):
                tags = []
        fresh = severity_for(r["threat_type"], tags or [])
        if fresh != r["severity"]:
            updates.append((fresh, r["id"]))
    if updates:
        conn.executemany("UPDATE iocs SET severity=? WHERE id=?", updates)
    conn.execute("INSERT INTO settings (key,value) VALUES ('severity_reclassified','1') "
                 "ON CONFLICT(key) DO UPDATE SET value='1'")
    return len(updates)


def _utc_now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _verify_schema(conn):
    """Fail loudly if applying the schema did not produce every table it declares.

    `_safe_schema` deliberately swallows per-statement failures so one index on a
    not-yet-migrated column cannot stop a deployment booting. The cost is that a
    genuinely broken statement is silent too: an index placed above the table it
    references aborted the script, the fallback did not recover, and the first
    symptom was `no such table: events` from a migration much later - pointing at
    a table that had nothing to do with the mistake.

    The expected set is parsed out of SCHEMA itself, so it cannot drift from it."""
    import re
    expected = set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA))
    from dashboard_api.db_backend import is_postgres
    if is_postgres():  # pragma: no cover - opt-in backend
        rows = conn.execute("SELECT tablename AS name FROM pg_tables "
                            "WHERE schemaname='public'").fetchall()
    else:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    missing = sorted(expected - {r["name"] for r in rows})
    if missing:
        raise RuntimeError(
            f"Database schema is incomplete - these declared tables were not created: "
            f"{', '.join(missing)}. This usually means a schema statement failed; a "
            f"CREATE INDEX must appear after the table it references.")


def _schema_version_gate(conn):
    """Migration-gating on upgrade. Compares the DB's recorded schema version to
    SCHEMA_VERSION and either adopts (fresh/unversioned DB), bumps (normal
    upgrade after migrations applied), or refuses to boot (DB newer than code,
    i.e. a rollback) unless explicitly overridden."""
    row = conn.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
    stored = int(row["value"]) if row and str(row["value"]).isdigit() else None
    if stored is None:
        # Fresh DB, or one predating versioning: the running code's schema is now
        # authoritative (existing tables are additive-compatible). Adopt it.
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('schema_version', ?)",
                     (str(SCHEMA_VERSION),))
        return
    if stored > SCHEMA_VERSION:
        allow = os.environ.get("DASHBOARD_ALLOW_SCHEMA_DOWNGRADE", "").lower() in ("1", "true", "yes")
        if not allow:
            raise SchemaVersionError(stored, SCHEMA_VERSION)
        return  # overridden: proceed, but don't downgrade the recorded version
    if stored < SCHEMA_VERSION:
        # Normal upgrade: _apply_migrations already added the new columns; record it.
        conn.execute("UPDATE settings SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),))


def schema_versions() -> dict:
    """The code's and the DB's schema versions (for ops/health surfaces)."""
    try:
        with get_conn() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
        db = int(row["value"]) if row and str(row["value"]).isdigit() else None
    except Exception:
        db = None
    return {"code": SCHEMA_VERSION, "db": db}


def init_db():
    with get_conn() as conn:
        _safe_schema(conn)
        added = _apply_migrations(conn)
        # second pass: indexes that needed migrated columns now succeed
        _safe_schema(conn)
        _verify_schema(conn)
        if ("events", "ti_checked") in added:
            n = _adopt_existing_events(conn)
            if n:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Marked %d pre-existing events as threat-intel checked "
                    "(they were, under the old shared marker)", n)
        try:
            seeded = _backfill_source_assertions(conn)
            if seeded:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Seeded %d source assertions from existing indicators", seeded)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("source backfill failed")
        try:
            filled = _backfill_ioc_hosts(conn)
            if filled:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Backfilled host for %d URL indicators", filled)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("host backfill failed")
        try:
            keyed = _backfill_ioc_ip_hex(conn)
            if keyed:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Backfilled network key for %d IP indicators", keyed)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("ip_hex backfill failed")
        try:
            from dashboard_api.threat_actor_library import (
                correct_placeholder_first_seen, seed_actor_library)
            seed_actor_library(conn)
            fixed = correct_placeholder_first_seen(conn)
            if fixed:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Replaced the placeholder first-seen date on %d threat actors "
                    "with the year each was first publicly reported", fixed)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("actor library seed failed")
        try:
            named = _seed_malware_catalogue(conn)
            if named:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Refreshed %d malware-family entries (operator edits untouched)", named)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("malware catalogue seed failed")
        try:
            from dashboard_api.decay import seed_builtin_rules
            made = seed_builtin_rules(conn)
            if made:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Seeded %d builtin decay rules (same curves as before, now editable)",
                    made)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("decay rule seeding failed")
        try:
            regs = _backfill_ioc_reg_domain(conn)
            if regs:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Backfilled registrable domain for %d indicators", regs)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("reg_domain backfill failed")
        try:
            graded = _apply_feed_reliability_defaults(conn)
            if graded:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Applied shipped Admiralty grades to %d intel sources "
                    "(operator-set grades untouched)", graded)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("source grading failed")
        try:
            fixed = _reclassify_severities(conn)
            if fixed:
                import logging
                logging.getLogger("dashboard_api.db").info(
                    "Reclassified severity for %d indicators (was derived from "
                    "confidence, now from the asserted activity)", fixed)
        except Exception:
            import logging
            logging.getLogger("dashboard_api.db").exception("severity reclassify failed")
        # Migration-gating: refuse to run against a DB newer than this code
        # (rollback safety) before we touch any data.
        _schema_version_gate(conn)
        # Multi-tenancy foundation: ensure the default workspace exists and every
        # user belongs to one (non-breaking; single-tenant installs are unchanged).
        from dashboard_api.tenancy import ensure_default_org
        ensure_default_org(conn)
        conn.commit()
