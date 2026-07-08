"""Organization mode: `simple` vs `power` feature surfacing.

A small org drowning in a full SOC platform churns; a mature team hobbled by a
stripped-down UI churns too. The organization mode lets each deployment (or
each workspace, when multi-tenancy is on) pick which of the two it is:

  power  - the full feature surface (the default; zero behaviour change for
           existing installs).
  simple - a curated essential subset for small orgs: see the alerts, work the
           cases, know your assets, get basic threat intel, triage with one
           click - without rules engines, playbook builders, ATT&CK matrices
           and UEBA in the way.

**This is a UI-surfacing / preference layer, NOT a security boundary.** The
feature list tells the frontend what to *show*; every endpoint keeps enforcing
its real capability via `permissions.py` / `require_perm` exactly as before.
A user in simple mode who calls a "hidden" endpoint directly is still subject
to the same RBAC checks as always - nothing here grants or removes access.

Feature ids mirror the dashboard's navigation areas (Sidebar sections and
their sub-pages) plus the platform areas behind them, so the frontend can map
one feature id to one nav entry / page.

The simple-vs-power split, and why each power-only feature was excluded:

  In simple AND power (the essentials):
    overview          - the landing dashboard; orientation for any org size.
    soc               - the SOC console: one-click triage, the simple-org
                        day-to-day workflow.
    siem.alerts       - core SIEM alert queue; the product's heartbeat.
    siem.sources      - connect log sources / ingest - without it a small org
                        never gets an alert at all.
    soar.cases        - case management; even a two-person team tracks
                        incidents.
    cti.overview      - basic CTI: the IOC database, lookups, sightings.
    feeds             - out-of-the-box intel feeds + IOC import; how a small
                        org gets intel without an analyst team.
    assets.inventory  - know what you own and how risky it is.
    reports           - the one-click summary a small org sends up the chain.
    config            - settings/users/API keys; also where this very toggle
                        lives, so it must stay visible in both modes.

  Power only (analyst-grade depth a small org doesn't staff for):
    siem.rules        - authoring/tuning detection rules (out-of-box rules
                        still run server-side either way).
    siem.attack       - ATT&CK navigator coverage mapping.
    siem.entities     - UEBA entity-risk analytics.
    siem.hunt         - raw event threat-hunting query engine.
    soar.playbooks    - automation/playbook building and approvals.
    soar.integrations - response-tooling integrations.
    soar.metrics      - SOC performance metrics (MTTR etc.).
    cti.hunt          - hypothesis-driven CTI hunts.
    cti.actors        - threat-actor profiling and attribution.
    scanner           - IntelScope on-demand scanning.
    darkweb           - dark-web monitoring and takedowns.
    assets.vulns      - vulnerability findings and scanning.
    assets.network    - network topology mapping.
    connectors        - custom ingestion-connector management (curated feeds
                        still cover the simple case).
    compliance        - compliance reporting/exports.

Persistence follows the platform's settings pattern: one row in the
`settings` table - key `org_mode` for a single-tenant deployment, or
`org_mode:{org_id}` per workspace when multi-tenant isolation is on (the same
`key:{org}` convention as per-tenant quotas in `tenancy.py`). Unset or
unrecognised values resolve to `power`, so the default is fail-open to the
full UI and a garbled row can never lock anyone out of features.
"""

# Catalogue of feature areas (id -> what the UI surfaces for it).
FEATURES = {
    "overview": "Executive overview dashboard",
    "soc": "SOC console with one-click triage",
    "siem.alerts": "SIEM alert queue and triage",
    "siem.rules": "Detection rules engine (authoring, tuning, backtests)",
    "siem.attack": "MITRE ATT&CK coverage navigator",
    "siem.entities": "UEBA entity risk analytics",
    "siem.sources": "Log sources and ingestion",
    "siem.hunt": "Event threat-hunting query engine",
    "soar.cases": "Incident case management",
    "soar.playbooks": "Playbook automation and approvals",
    "soar.integrations": "Response tooling integrations",
    "soar.metrics": "SOC performance metrics",
    "cti.overview": "Core CTI: IOC database, lookups, sightings",
    "cti.hunt": "Hypothesis-driven CTI threat hunts",
    "cti.actors": "Threat actor profiles and attribution",
    "feeds": "Threat intel feeds and IOC import",
    "scanner": "IntelScope on-demand scanning",
    "darkweb": "Dark-web monitoring and takedowns",
    "assets.inventory": "Asset inventory and risk scoring",
    "assets.vulns": "Vulnerability findings and scanning",
    "assets.network": "Network topology map",
    "connectors": "Custom ingestion connector management",
    "reports": "Report generation and scheduling",
    "compliance": "Compliance reporting and exports",
    "config": "Platform configuration, users, API keys",
}

_SIMPLE = {
    "overview", "soc", "siem.alerts", "siem.sources", "soar.cases",
    "cti.overview", "feeds", "assets.inventory", "reports", "config",
}

MODES: dict[str, set[str]] = {
    "power": set(FEATURES),          # the full surface
    "simple": set(_SIMPLE),          # curated essentials (a strict subset)
}

DEFAULT_MODE = "power"               # no behaviour change unless explicitly set

SETTING_KEY = "org_mode"


def setting_key(org: str) -> str:
    """The settings-table key holding `org`'s mode: per-workspace when tenant
    isolation is on (same `key:{org}` convention as per-tenant quotas), one
    global key otherwise."""
    from dashboard_api import tenancy
    return f"{SETTING_KEY}:{org}" if tenancy.enforced() else SETTING_KEY


def effective_mode(conn, org: str) -> str:
    """The mode in effect for `org` - what was explicitly persisted, else the
    `power` default. Unrecognised stored values also resolve to the default,
    so a garbled settings row can never hide the full UI."""
    row = conn.execute("SELECT value FROM settings WHERE key=?",
                       (setting_key(org),)).fetchone()
    mode = row["value"] if row else None
    return mode if mode in MODES else DEFAULT_MODE


def has_explicit_mode(conn, org: str) -> bool:
    """Whether `org` has actually chosen a mode (vs. never having set one, so
    `effective_mode` is only reporting the `power` fallback).

    This distinction matters to callers beyond nav curation: some UI (e.g. the
    SIEM alert queue's card density / inline triage actions) already used this
    same normal/power toggle as a plain client-side preference, defaulting to
    'normal', *before* this org-level backend setting existed. If a client
    treated every GET response as authoritative, an org that has never
    explicitly chosen a mode would get silently flipped from that pre-existing
    'normal' default to the backend's 'power' fallback the moment it synced -
    a real behaviour change for every existing/fresh install. Callers should
    only let the backend override a pre-existing local preference when this
    is True."""
    row = conn.execute("SELECT value FROM settings WHERE key=?",
                       (setting_key(org),)).fetchone()
    return bool(row) and row["value"] in MODES


def enabled_features(mode: str) -> list[str]:
    """The sorted feature ids exposed in `mode` (default mode's set when the
    value is unknown - same fail-open-to-full-UI stance as effective_mode)."""
    return sorted(MODES.get(mode, MODES[DEFAULT_MODE]))
