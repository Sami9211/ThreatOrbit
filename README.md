# ThreatOrbit

**Important**: This project is public for viewing purposes only. All rights are reserved. See [LICENSE](LICENSE) for full terms. No use, modification, or distribution without explicit permission.


**A unified Super-SOC: SIEM + SOAR + CTI + Asset/Vuln + Dark-Web monitoring, with STIX / OpenCTI integration.**

ThreatOrbit takes the four disciplines a security team normally runs in four
separate tools - threat intelligence, log/anomaly detection, incident response,
and exposure management - and converges them into one operation that shares a
single data pipeline, one audit trail, and one operator console. It is built to
run anywhere from a single analyst's laptop to a containerized deployment for a
mid-size team, with the same code path either way.

### What's in the box

* A working **detection → correlation → response** pipeline (not a mock UI):
  events become SIEM alerts, alerts that share a pivot auto-escalate into SOAR
  cases, cases drive playbooks, and indicators flow back into CTI.
* **Real OSINT** ingestion (abuse.ch, NVD, RSS, OTX, TAXII, custom connectors)
  with trust scoring, dedup, VirusTotal enrichment, and STIX 2.1 / OpenCTI.
* A full **operator dashboard** (26 pages) - SIEM, SOAR, CTI, Assets, Dark Web,
  plus a security-bounded **AI assistant**, an 11-theme customizable
  **Appearance** system, per-user **TOTP MFA**, optional **multi-tenancy**,
  Prometheus **observability**, and a complete **audit trail**.
* Honest data: every number traces back to the API. The only synthesized input
  is the raw environment event stream a SIEM can't see until your own systems
  forward logs to it - and genuine logs flow through the identical pipeline.

### Who it's for

Individual analysts, blue teams, and small-to-mid SOCs that want a deployable,
inspectable CTI + detection + response workflow - and a clean console on top of
it - without standing up a heavyweight SIEM and a separate SOAR and a separate
TIP. The three backend services run independently or together, locally or in
containers. See [§13 Intended users](#13-intended-users) for the honest scope.

### Project status - read this first

An ambitious, security-aware platform - **not a production-audited product.** The
honest framing (the strong parts stand on their own without inflating the rest):

* **Single-node by default.** WAL-mode SQLite with an opt-in, staged Postgres
  backend. Measured ~10k EPS ingest / ~7k EPS detection on 4 vCPU
  ([`docs/LOAD_LIMITS.md`](docs/LOAD_LIMITS.md)); for higher sustained load, move
  to Postgres / externalise the event store.
* **The ML layer is unsupervised outlier _ranking_ for triage**, not trained
  ground-truth detection - it surfaces the most unusual sources (corroborated by
  a concrete signal), it doesn't assert "this is an attack".
* **OSINT is OTX + abuse.ch + a pluggable RSS layer.** The "dark-web" and
  "social" feeds are RSS slots that are **empty by default** until you add
  sources - extensible ingestion, not live dark-web/social collection.
* **Enterprise features (SSO/SCIM/SAML, billing, multi-tenancy)** are implemented
  and tested but **exploratory / not independently security-audited** - no SOC 2
  or third-party pentest yet ([`docs/COMPLIANCE.md`](docs/COMPLIANCE.md),
  [`SECURITY.md`](SECURITY.md)). Full caveats in [§15](#15-limitations--honest-caveats).

### Table of contents

| Getting started | Using it | Reference | Direction |
| --- | --- | --- | --- |
| [Architecture](#1-architecture-at-a-glance) · [Structure](#2-project-structure) · [Requirements](#3-requirements) · [Quick start](#4-quick-start---pick-the-path-for-your-machine) · [**Going live**](docs/GOING_LIVE.md) | [How the engine works](#2a-how-the-threatorbit-engine-works-the-real-data-pipeline) · [By role & task](#2b-using-the-dashboard---by-role-and-by-task) · [Real vs demo data](#4a-real-data-vs-demo-mode) | [Auth](#5-authentication-two-tier-api-keys) · [API reference](#10-api-reference) · [Testing](#11-testing) · [Troubleshooting](#12-troubleshooting) | [Roadmap & direction](#14-roadmap--direction) · [Limitations](#15-limitations--honest-caveats) · [Contributing](#16-contributing--extending) · [FAQ](#faq) |

---

ThreatOrbit is made of three backend services and a Next.js frontend (marketing site + full operator dashboard):

* **Threat API** (`threat_api`, Flask, port 8000)
  Ingests external threat feeds (OTX, abuse.ch, RSS - plus a pluggable dark-web/social RSS layer that is empty until you add sources) in parallel, normalizes and trust-scores indicators, enriches with VirusTotal, exports STIX 2.1, and reads from / pushes to OpenCTI.
* **Log API** (`log_api`, FastAPI, port 8001)
  Parses logs (Apache, Syslog, Windows Event, Generic), detects anomalies via four engines (Pattern, Statistical, an unsupervised ML outlier-_ranking_ layer, Temporal), generates HTML reports, and exports STIX 2.1 from findings.
* **Dashboard API** (`dashboard_api`, FastAPI, port 8002)
  The unified backend powering the operator dashboard: JWT auth (login + self-service registration with brute-force throttling) and role-based users, SIEM alerts with computed SOC metrics (MTTD/MTTA/MTTR), a correlation engine and a live hunt-query engine, SOAR case lifecycle (create, war-room notes, task workflow), CTI actors/IOCs with lookup + bulk import + scanner history, an asset surface with a transparent CVSS-style risk model, threat feeds, settings, API keys, webhooks, a full audit trail - and a **service bridge** that proxies the Threat API and Log API server-side so the browser never handles their API keys. See [`dashboard_api/README.md`](dashboard_api/README.md).
* **Frontend** (`frontend`, Next.js 16 + TypeScript)
  Marketing site **and** the operator dashboard (`/dashboard/**`, 26 wired pages) that consumes the Dashboard API live, with seeded demo data as graceful fallback. Deployable on Vercel (static export) or any Node host.

All APIs use WAL-mode SQLite and CORS for browser clients. The two ingestion APIs use an async job model and a two-tier API key scheme; the Dashboard API uses JWT bearer auth.

---

## 1. Architecture at a glance

```
                    +----------------------+
   OSINT feeds ---> |     Threat API       | ---> STIX 2.1 bundles ---> OpenCTI
 (OTX, abuse.ch,    |   (Flask, :8000)     | <--- read indicators  <---
  RSS, dark-web,    +----------+-----------+
  social)                      |
                               | WAL SQLite (threat_api.db)
                               |
   Log files ----------------> +----------------------+
 (Apache, syslog,  upload ---> |      Log API         | ---> HTML report
  Windows, generic)           |   (FastAPI, :8001)   | ---> STIX 2.1 from findings
                              +----------------------+
                               | WAL SQLite (log_api.db)

   Dashboard UI -------------> +----------------------+
 (JWT login, SIEM/SOAR/CTI/   |    Dashboard API     | ---> SOC metrics, risk scoring,
  assets/feeds/config pages)  |   (FastAPI, :8002)   |      correlations, audit trail
                              +----------------------+
                               | WAL SQLite (dashboard.db, auto-seeded)

   Browser ------------------> Frontend (Next.js, Vercel)
                                ├-- marketing site (/)
                                └-- operator dashboard (/dashboard/**) ---> Dashboard API
```

---

## 2. Project structure

```text
ThreatOrbit-V2/
├-- README.md
├-- Makefile                     # make up / down / test / dev-* shortcuts (Mac/Linux)
├-- windows-start.bat            # double-click: full local start on Windows
├-- windows-test.bat             # double-click: run every test suite on Windows
├-- linux-start.sh               # one command: live real-data start on Linux/Mac
├-- linux-test.sh                # one command: run every test suite on Linux/Mac
├-- .gitignore
├-- .env.example                 # copy to .env, fill in keys
├-- docker-compose.yml           # full stack: 3 APIs + frontend, healthchecked
├-- docker-compose.prod.yml      # production preset: live mode, real data only
│
├-- docs/                        # 16 operational references - architecture,
│   │                            #   DEPLOYMENT, OPERATIONS, GOING_LIVE,
│   │                            #   LOAD_LIMITS, SUPPORTED_SOURCES, COMPLIANCE,
│   │                            #   API_VERSIONING, ... (index below the tree)
│   └-- api/                     # versioned API path snapshot (v1-paths.json)
│
├-- deploy/
│   ├-- helm/                    # Kubernetes chart (probes pre-wired)
│   └-- prometheus/              # alert rules for the platform's own health
│
├-- scripts/                     # backup/restore, SBOM, static-site server
├-- collector/                   # stdlib log-forwarding agent for endpoints
│
├-- threat_api/                  # Flask threat-intel service (:8000)
│   ├-- Dockerfile
│   ├-- main.py                  # routes, async job runner, OpenCTI read/push
│   ├-- config.py                # env-driven config + API keys
│   ├-- db.py                    # WAL SQLite, batch upsert, IOC store
│   ├-- models.py
│   ├-- normalization.py
│   ├-- trust_scoring.py
│   ├-- rate_limit.py            # thread-safe rate limiter
│   ├-- source_health.py
│   ├-- scheduler.py
│   ├-- retention.py
│   ├-- metrics.py
│   ├-- opencti_push.py          # STIX bundle push over HTTP
│   ├-- source_trust_config.json
│   ├-- rss_feeds.txt
│   ├-- darkweb_sources.txt
│   ├-- social_sources.txt
│   ├-- requirements.txt
│   ├-- fetchers/                # otx, abusech, rss, darkweb_osint, social_osint
│   ├-- enrichment/              # virustotal (pooled session, retries)
│   ├-- stix_converter/          # converter to STIX 2.1
│   └-- tests/                   # conftest.py, test_health.py
│
├-- log_api/                     # FastAPI log-analysis service (:8001)
│   ├-- Dockerfile
│   ├-- main.py                  # routes, async analysis, auth dependencies
│   ├-- config.py
│   ├-- db.py                    # WAL SQLite
│   ├-- models.py
│   ├-- metrics.py
│   ├-- stix_from_findings.py
│   ├-- requirements.txt
│   ├-- parsers/                 # apache, syslog, windows_event, generic
│   ├-- detectors/               # pattern, statistical, ml_detector, temporal
│   ├-- alerts/                  # alerter.py (correlation + severity)
│   ├-- reporter/                # report.py (HTML report)
│   ├-- sample_logs/             # generator.py + sample_apache.log
│   └-- tests/                   # conftest.py, test_health.py
│
├-- dashboard_api/               # FastAPI dashboard backend (:8002)
│   ├-- Dockerfile
│   ├-- main.py                  # app wiring, CORS, error handlers, startup seed
│   ├-- auth.py                  # PBKDF2 passwords + stdlib HS256 JWT, role deps
│   ├-- mfa.py                   # per-user TOTP (RFC 6238, stdlib)
│   ├-- permissions.py           # capability matrix (roles → capabilities)
│   ├-- tenancy.py               # optional multi-tenant org scoping
│   ├-- secretstore.py           # Fernet encryption-at-rest for secrets
│   ├-- observability.py         # Prometheus /metrics, JSON logs, security headers
│   ├-- self_health.py           # the SOC's own vitals: one ok/degraded/down verdict
│   ├-- leader.py / event_queue.py / detection_pool.py  # HA lease + worker pool
│   ├-- fp_scoring.py            # false-positive likelihood scoring + bulk triage
│   ├-- ops.py                   # SQLite online-backup endpoint
│   ├-- config.py / db.py        # env config; WAL SQLite, schema, migrations, audit
│   ├-- db_backend.py            # SQLite default + staged Postgres backend
│   ├-- engine.py                # the live processing engine (telemetry→alerts→cases)
│   ├-- rule_engine.py / detections.py / hunting.py   # detection + KQL-style hunt
│   ├-- playbook_engine.py / integration_actions.py   # SOAR runner + real actions
│   ├-- scoring.py / attack_surface.py / vuln_scanner.py   # asset risk + vuln model
│   ├-- attribution.py / cti_graph.py / ioc_lifecycle.py   # CTI attribution + graph
│   ├-- threat_actor_library.py  # curated real CTI actor library
│   ├-- darkweb_logic.py         # dark-web finding generation + triage
│   ├-- assistant.py             # security-bounded read-only AI assistant
│   ├-- stix.py / taxii.py / misp.py / sigma.py   # interchange formats
│   ├-- licensing.py / webhooks.py / mailer.py / enrichment.py
│   ├-- log_listeners.py / events_stream.py / ingest.py   # log intake + SSE
│   ├-- seed.py                  # deterministic, internally-consistent demo data
│   ├-- routers/                 # 26 routers, 220+ routes: auth, users, orgs,
│   │                            #   overview, siem, soar, cti, assets, feeds,
│   │                            #   connectors, darkweb, platform, reports,
│   │                            #   services, stream, taxii, assistant, config,
│   │                            #   billing, compliance, privacy, roles,
│   │                            #   saml, scim, sso
│   └-- tests/                   # behaviour tests (pytest + TestClient)
│
└-- frontend/                    # Next.js 16 - marketing site + operator dashboard
    ├-- app/
    │   ├-- page.tsx             # marketing landing
    │   └-- dashboard/           # operator dashboard (26 pages, all API-wired):
    │                            #   overview, siem(+rules/sources/hunt/entities/
    │                            #   attack), soar(+playbooks/integrations/metrics),
    │                            #   cti(+actors/hunt), assets(+network/vulns),
    │                            #   darkweb, feeds(+sources/import), scanner,
    │                            #   config(+api/users/sources)
    ├-- components/
    │   ├-- dashboard/           # AuthGuard, Sidebar, TopBar, CommandPalette,
    │   │                        #   AssistantWidget, ThemeScope, WorldMap,
    │   │                        #   RuleEditor, PlaybookBuilder, EntityGraph, …
    │   ├-- effects/             # HeroScene/OrbitalScene (R3F), CursorParticles
    │   ├-- layout/              # Navbar, Footer
    │   ├-- sections/            # Hero, Features, ExpandingShowcase, etc.
    │   └-- ui/                  # Logo (faceted 3D gem), Reveal, MagneticButton, …
    ├-- lib/
    │   ├-- api.ts               # typed Dashboard API client (snake→camel mapping)
    │   ├-- useDashboardTheme.ts # 11 themes + per-user Appearance prefs
    │   ├-- usePermissions.ts    # client-side capability gating
    │   ├-- useLiveStream.ts     # SSE live updates
    │   └-- auth-context.tsx     # login/session state backed by /auth
    ├-- tailwind.config.ts
    ├-- next.config.mjs
    └-- package.json
```

`docs/` ships deeper references: `architecture.md`, `opencti_integration.md`,
`api_examples.md`, **`DEPLOYMENT.md`** (proxy/TLS topology, nginx + Caddy
configs, env checklist), **`OPERATIONS.md`** (backup/restore, retention,
runbook), **`SUPPORTED_SOURCES.md`** (the parser/source matrix - which vendor
log shapes normalise onto the detection vocabulary), **`API_VERSIONING.md`**
(the `/v1` contract + deprecation policy), **`GOING_LIVE.md`** (the real-data
production runbook: AD/Windows, AWS, Linux log forwarding, hardening),
**`PII_HANDLING.md`** (what is stored, redaction, DSAR reach) and **`DATA_RESIDENCY.md`** (every
external egress point + how to pin/disable each for in-region installs). HA/scale
deployers: see **`POSTGRES_HA.md`** (multi-AZ Postgres) and **`LOAD_LIMITS.md`**.

---

## 2a. How the ThreatOrbit engine works (the real data pipeline)

ThreatOrbit is not a mockup with hardcoded numbers - it is a working pipeline.
Here is exactly where data comes from and how each service processes and
displays it. (In **demo mode** these stores are pre-filled with realistic
sample data so you can evaluate the UI; in **live mode** they start empty and
fill from the real pipeline below - see [§4a](#4a-real-data-vs-demo-mode).)

### The engine (Threat API, `:8000`)

`threat_api` is the ingestion engine. One `POST /fetch` (or the built-in
scheduler) runs this pipeline (`threat_api/main.py` → `_run_pipeline`):

```
  ┌-- abuse.ch (Feodo blocklist - keyless; URLHaus - free Auth-Key)
  ├-- RSS security feeds (keyless - IOCs extracted from articles)
  ├-- AlienVault OTX (free API key)            -- parallel fetch --┐
  ├-- dark-web OSINT sources                                       │
  └-- social OSINT sources                                         ▼
                                              normalise → dedup → trust-score
                                              → confidence-correlate
                                              → VirusTotal enrich (optional key)
                                              → persist (WAL SQLite) + STIX 2.1
```

Every indicator carries a type, source, threat-type, a trust-weighted
confidence, tags, and (if enriched) a VirusTotal detection ratio. This is real
OSINT - abuse.ch's Feodo blocklist alone returns thousands of live malicious
IPs **with no API key**.

### The live processing engine (`dashboard_api/engine.py`)

The Threat API above is the *external* intelligence engine. The dashboard also
has its own **live processing engine** that makes every operational section
flow with data **without any external connector or internet**. In live mode it
runs on a background tick and is a real pipeline, stage by stage:

```
  environment telemetry        ← continuous, freshly generated each tick
        │                         (auth, network, endpoint, cloud, web, dark-web)
        ▼
  parse / normalise            ← structured fields: src_ip, user, host, action…
        ▼
  detection rules  -----------► SIEM ALERTS  (severity, MITRE technique→tactic,
        │                                     evidence, dedup, rule name)
        ▼
  IOC extraction  ------------► CTI INDICATORS (deduped, actor-attributed)
        ▼
  correlation (host/user/ip) -► SOAR CASES   (auto-opened when ≥3 critical/high
        │                                     alerts share a pivot; IR tasks +
        │                                     war room created)
        ▼
  dark-web monitoring --------► DARK-WEB FINDINGS (leaked creds, data sales,
                                                   actor chatter, access listings)
```

Every stage above - parsing, the detection rule engine, correlation, SOAR
escalation, IOC extraction, dark-web matching - is real, executable code, and
all of it runs on **real data** wherever real data is available: uploaded logs,
the syslog listener / file watcher, connector feeds, TAXII push, and threat-intel
matches all write into these same stores. The **only** seeded/generated input is
*environment telemetry* - the raw auth/network/endpoint event stream a SIEM
normally receives from your own infrastructure. That stream genuinely requires a
deployment with log forwarding configured (see
[§4a](#4a-real-data-vs-demo-mode) and the [FAQ](#faq)); until then the engine
generates a representative stream so the detection/correlation/response pipeline
has something real to act on. You can pause it, or click **Generate burst now**,
from **Config → General → Live Processing Engine**.

### Each section's workflow - distinct by design

SIEM, SOAR, and CTI are deliberately separate stages of one operation. Here is
exactly how each ingests, processes, and displays data:

**SIEM - detection & monitoring** (`/dashboard/siem`)
* **Ingest:** environment telemetry (engine) + uploaded logs (Log API's
  pattern/statistical/ML/temporal detectors) + critical-IOC intel matches.
* **Process:** every event is evaluated by detection rules → an alert with a
  risk score, MITRE technique→tactic, source IP/user/host, and raw evidence.
  `/siem/correlations` clusters unresolved alerts by shared pivot;
  `/siem/kpis` computes MTTD/MTTA/MTTR from per-alert latency;
  `/siem/mitre-distribution` builds the ATT&CK heatmap.
* **Display:** the alert queue (auto-refreshing every 15s), rules engine,
  correlation view, MITRE heatmap, and the KQL-style hunt console.

**SOAR - orchestration & response** (`/dashboard/soar`)
* **Ingest:** SIEM alerts. The correlation engine **auto-escalates** any pivot
  with ≥3 correlated critical/high alerts into a case; analysts also open cases
  from any alert (**Create Case**).
* **Process:** each case gets an IR task list (Triage → Containment →
  Eradication → Recovery), a war room, evidence chain, and SLA timer.
  Playbooks run response actions; `/soar/metrics` computes MTTR and the real
  automation rate from playbook-driven closures.
* **Display:** the case board, playbook runner with a live step timeline, the
  integrations grid, and SOC metrics. *This is why SIEM ≠ SOAR:* SIEM **finds**,
  SOAR **manages the response** - different data, different lifecycle.

**CTI - intelligence & library** (`/dashboard/cti`, `/dashboard/feeds`)
* **Ingest:** the Threat API OSINT engine + connectors (NVD, OTX, custom) +
  IOCs the live engine extracts from detections.
* **Process:** indicators are deduped, confidence/trust-scored, actor-attributed,
  and enriched (VirusTotal); `/cti/summary` and `/cti/graph` build the actor
  and relationship views; the scanner (`/cti/lookup`) checks any value against
  the store.
* **Display:** CTI overview, actor profiles, the IOC library/feeds, IntelScope
  scanner, and threat-hunt console.

**Asset Surface - exposure & risk** (`/dashboard/assets`)
* **Ingest:** assets you add/import + NVD CVEs (connector).
* **Process:** each asset's 0-100 risk is a transparent four-axis model
  (vulnerability, exposure, patch, alert-pressure - `scoring.py`); recomputed
  from live SIEM alert pressure, so triaging alerts lowers asset risk.
* **Display:** inventory, vulnerability rollup, and the interactive network map.

**Dark Web - external exposure** (`/dashboard/darkweb`) - *new*
* **Ingest:** the engine's dark-web monitoring stage produces findings across
  five categories (credential leak, data for sale, brand mention, actor chatter,
  access listing).
* **Process:** each finding has a severity, affected entity, source forum/market,
  and a triage lifecycle (new → investigating → mitigated → dismissed).
* **Display:** a dedicated, auto-refreshing findings feed with category filters
  and a triage panel - distinct from CTI (what's known *about threats*) because
  this is what's being said about *you* outside your perimeter.

So the chain is: **live engine + real OSINT + real log analysis → the stores →
every section**, each a distinct stage of the SOC workflow.

### See it live in 60 seconds

1. Start in live mode (the Windows launcher does this automatically; otherwise
   set `DASHBOARD_DATA_MODE=live`).
2. **Log in.** Every section is already populated by the engine's initial prime
   and keeps growing every 20 seconds - watch the SIEM queue, Dark Web, and CTI.
3. **Config → General → Live Processing Engine → Generate burst now** to add a
   wave of alerts/IOCs/cases/findings on demand (or **Pause** to freeze it).
4. Want *external* intelligence too? **Feeds → Sources → Sync now** on the
   ThreatOrbit OSINT and NVD connectors (needs internet). Want real detections
   from your own logs? **SIEM → Sources → upload a log**.

## 2b. Using the dashboard - by role and by task

The dashboard is one console, but different people use different slices of it.
Two ways to find your path: **by who you are** (role walkthroughs) and **by
what you need to do right now** (task recipes). The dashboard also has two
**experience modes** - *Normal* (analyst-first, pre-triaged) and *Power User*
(dense data, raw controls) - switchable in **Config → General → Experience
Mode**. This is one toggle with two effects: it's a per-browser display-density
preference (card density, inline triage actions) **and**, since it persists to
the org's account (`GET`/`PUT /config/mode`), it curates *which sidebar
sections even appear* - Normal ("simple mode") shows the 10-area small-org
essentials (Overview, SOC console, SIEM alerts + sources, Cases, core CTI,
Feeds, Assets, Reports, Config); Power reveals the full 24-area analyst-grade
surface (rules authoring, ATT&CK navigator, UEBA, hunting, playbook building,
threat-actor attribution, compliance, and more). It is a **UI-surfacing
preference, not a permission boundary** - every endpoint still enforces the
same RBAC regardless of mode, so a Normal-mode user hitting a "hidden" API
directly is not blocked by it, only steered away from it in the nav. A brand
new org sees Power (nothing hidden) until it explicitly picks a mode, so no
existing deployment's nav changes underneath it. And there is an in-dashboard
**AI assistant** (bottom-right) that can answer, recommend, and redirect
across these workflows for you.

### By role

**L1 analyst / on-call - triage the queue.**
Start on **Overview** for the at-a-glance picture (open alerts, risk score,
MTTD). Go to **SIEM** → work the alert queue top-down by severity; open an
alert to see its MITRE technique, evidence, and the source IP/user/host. If
several alerts share a pivot, **SIEM → Correlations** clusters them. Hand off
anything real by clicking **Create Case** (this moves it to SOAR). Use *Normal*
experience mode.

**Threat hunter - go looking.**
Use **SIEM → Hunt** (KQL-style query console) to pivot across events, and
**CTI → Hunt** to pivot across indicators. **SIEM → Entities** gives you the
UEBA view (per user/host/ip risk and timeline). **SIEM → ATT&CK** shows your
coverage heatmap so you can hunt the gaps. Save useful queries as views. Use
*Power User* mode.

**IR lead - run the incident.**
Live in **SOAR**. Each case has an IR task list (Triage → Containment →
Eradication → Recovery), a war room for notes, an evidence chain, and an SLA
timer. Run **Playbooks** for response actions and watch the live step timeline;
`approval` steps pause for sign-off. Close-out generates a case-scoped
post-incident report (the **Report** button on a case). **SOAR → Metrics**
shows MTTR and the real automation rate.

**CTI analyst - manage intelligence.**
**CTI → Overview** for the indicator/actor picture; **CTI → Actors** for
attributed profiles backed by the curated actor library. **Feeds → Sources**
to enable/sync connectors (OSINT, NVD, custom); **Feeds → Import** for bulk
IOC upload. Use the **Scanner** (IntelScope) to check any value against the
store. Push enriched intel to OpenCTI from the Threat API.

**Exposure owner - reduce risk.**
**Assets** lists your inventory with a transparent 0-100 risk per asset
(four-axis model: vulnerability, exposure, patch, alert-pressure). **Assets →
Vulns** rolls up CVEs; **Assets → Network** is the interactive map. Triaging
SIEM alerts lowers the alert-pressure axis, so risk drops as you work.
**Dark Web** shows what's being said about *you* outside the perimeter
(leaked creds, data-for-sale, brand mentions) with its own triage lifecycle.

**SOC manager / admin - run the platform.**
**Config** is home: workspace/licensing, the live engine controls, users &
RBAC (**Config → Users**), API keys, feed sources, notifications, security
(MFA, session, IP ranges), the **audit trail** (every state change, CSV
export), and **Appearance**. See the admin task recipes below.

### Common task recipes

| I want to… | Where | Notes |
| --- | --- | --- |
| Feed real logs in | SIEM → Sources → Log Collector (or `POST :8001/analyse`) | Apache/syslog/Windows/generic; also syslog listener + file-watcher. Sources **auto-register on first ingest** and show a live Events (24h) count |
| Check the platform's own health | Settings → General → System Health | Live DB/schema/queue/leader verdict; alerts on degrade/recover; Prometheus rules in `deploy/prometheus/` |
| Sync external intel | Feeds → Sources → Sync now | OSINT + NVD need internet; custom connectors are pluggable |
| Bulk-import IOCs | Feeds → Import | CSV/line-delimited; deduped + trust-scored on ingest |
| Turn an alert into a case | SIEM → open alert → Create Case | Or let correlation auto-escalate (≥3 critical/high on a pivot) |
| Tune a noisy rule | SIEM → Rules (editor + suppressions) | False-positive feedback feeds the tuning workflow |
| Run / build a playbook | SOAR → Playbooks (+ visual builder) | Live step timeline; `approval` steps pause for sign-off |
| Check a value (IP/hash/domain) | Scanner (IntelScope) | Backed by the live IOC store |
| Add a user / set a role | Config → Users | Capability-matrix RBAC (see permissions.py) |
| Turn on 2FA | Config → Security → Two-factor | Real TOTP (RFC 6238); secret shown once, stored encrypted |
| Mirror alerts to Slack | Config → Notifications → My Slack routing | Per-user webhook + severity floor |
| Create an API key | Config → API Keys | Read / Read+Write / Admin scopes; shown once |
| Export the audit trail | Config → Security → Audit Trail → Export CSV | Every state change, with actor + target |
| Customize the look | Config → General → Appearance | 11 themes, custom accent, UI scale, motion, density |
| Ask for help in-context | Assistant (bottom-right bubble) | Read-only, runs as you; answers / recommends / redirects |
| Switch detail level | Config → General → Experience Mode | Normal (simplified) ↔ Power User (raw) |
| Run the live engine | Config → General → Live Processing Engine | Pause, resume, or **Generate burst now** |

### The in-dashboard AI assistant

The floating assistant can **answer** ("what's my security posture?"),
**review** ("summarize open critical cases"), **recommend** ("what should I
look at first?"), and **redirect** ("take me to the noisy rule"). It is
deliberately constrained: it runs a fixed registry of **read-only** tools
**as you** (so it can never see data you can't), it never selects secrets,
it treats tool output as untrusted (prompt-injection contained), and it
**proposes** navigation rather than performing actions. With an API key
configured it reasons over those tools; with no key it honest-degrades to a
deterministic intent router over the same tools. See
[§16](#16-contributing--extending) for how to point it at a cheaper/free model.

## 3. Requirements

**Minimum (Path A - Windows, or Path C - Mac/Linux, no Docker)**

* Python 3.11+ and Node.js 18+ (LTS recommended) - nothing else
* CPU: 2 cores, RAM: 4 GB, Disk: 5 GB free

**For the one-command Docker path (B/D)**

* Docker Desktop (Windows/Mac) or Docker Engine + Compose (Linux)

**Recommended**

* CPU: 4+ cores, RAM: 8 to 16 GB, Disk: 20+ GB
* Stable internet (for feed ingestion and external enrichment APIs)

### Which OS is best?

**Ubuntu Server 22.04/24.04 LTS (or Debian 12) on x86_64 is the recommended
deployment OS.** Everything is developed and CI-tested on Linux, the launcher
and production compose file target it, systemd/journald handle service
supervision, and the measured throughput numbers in
[`docs/LOAD_LIMITS.md`](docs/LOAD_LIMITS.md) were taken on Linux x86_64.
Windows and macOS are fully supported for evaluation and development
(Paths A and C); for an always-on install serving real data, use Linux.

### Disk and memory footprint (measured)

| Item | Size |
| --- | --- |
| Repo checkout | ~50 MB |
| Python virtualenv (all three APIs) | ~380 MB |
| `frontend/node_modules` (build-time only) | ~880 MB |
| Built static site (`frontend/out`) | ~9 MB |
| Database at first boot (live mode) | <1 MB |
| Database growth | depends on your EPS and the retention window (default 90 days); plan 1-10 GB for a small org |

So ~1.5 GB installs everything with headroom; the 5 GB minimum leaves room
for the build cache and database growth. At runtime the four processes idle
around 500-800 MB RAM combined; sustained ingest at thousands of events/sec
runs comfortably in 4 GB (measured: a single SQLite node sustains roughly
8-11k EPS of ingest+detect on 4 vCPU - see
[`docs/LOAD_LIMITS.md`](docs/LOAD_LIMITS.md); move to the Postgres backend
past that).

For the OpenCTI workflow, deploy OpenCTI first using the official docs:
https://docs.opencti.io/latest/deployment/

---

## 4. Quick start - pick the path for your machine

> **Get the code first** (any OS): install [Git](https://git-scm.com/downloads)
> and run `git clone https://github.com/Sami9211/ThreatOrbit-V2.git` - or click
> **Code -> Download ZIP** on GitHub and unzip it. Every path below starts
> inside that folder.

**Which method do I use? (exact deployment method per goal)**

| Goal | Do this |
| --- | --- |
| Test on **Windows**, real live data | double-click **`windows-start.bat`** (Path A) |
| Test on **Linux/Mac**, real live data | **`./linux-start.sh`** (Path C) |
| Evaluate with showcase data | `./linux-start.sh --demo`, or Docker Path B (seeds demo by default) |
| **Production**, your real logs only | `docker compose -f docker-compose.prod.yml up -d` with secrets set, then follow [`docs/GOING_LIVE.md`](docs/GOING_LIVE.md) to forward logs |
| Kubernetes | the Helm chart in [`deploy/helm/`](deploy/helm/) |

### Path A - Windows, no Docker (easiest on Windows)

**You need exactly two installers, then one double-click.**

1. Install **Python** from https://www.python.org/downloads/ -
   ⚠️ on the first screen of the installer, tick **“Add python.exe to PATH”**.
2. Install **Node.js (LTS)** from https://nodejs.org/ - accept the defaults.
3. Open the `ThreatOrbit-V2` folder and **double-click `windows-start.bat`**.

The script installs everything, **builds the website for fast loading**, opens
four service windows, and launches your browser at http://localhost:3000.
First run takes a few minutes (npm download + build); after that pages open
**instantly** (it serves a production build, not the slow dev server).

* **Open the dashboard:** click **Sign in** on the site, or go to
  http://localhost:3000/dashboard
* **Sign in:** `admin@threatorbit.space` / `ChangeMe123!` (or create an account at `/signup`)
* **Real data:** the launcher runs in **live mode, real data only** (same
  default as `linux-start.sh`) - CTI/feeds fill from real OSINT + NVD
  connectors within a couple of minutes (needs internet), and the SIEM stays
  empty until you forward real logs
  ([`docs/GOING_LIVE.md`](docs/GOING_LIVE.md)). Nothing is fabricated. Want a
  livelier console? Run it from a terminal as `windows-start.bat synthetic`
  (live + demo telemetry engine) or `windows-start.bat demo` (seeded showcase
  dataset). See [§4a Real data vs demo](#4a-real-data-vs-demo-mode).
* **Stop:** close the four windows the script opened.
* **Test:** double-click **`windows-test.bat`** - it runs all backend tests
  and prints `ALL TESTS PASSED` at the end.

> **Were pages slow before (5-10s each)?** That was the Next.js *dev server*
> compiling each page on first visit. The launcher now serves a pre-built
> production site, so every page is instant. (If you run `npm run dev`
> manually you'll still see the dev-server delay - that's expected; use the
> launcher or `npm run build` for the fast version.)

<details>
<summary>Prefer typing the commands yourself? (PowerShell - run one line at a time)</summary>

```powershell
cd ThreatOrbit-V2
python -m pip install -r dashboard_api\requirements.txt
python -m uvicorn dashboard_api.main:app --port 8002
```

Leave that window open. In a **second** PowerShell window:

```powershell
cd ThreatOrbit-V2\frontend
npm install
npm run dev
```

Open http://localhost:3000/dashboard. To run the tests:

```powershell
cd ThreatOrbit-V2
python -m pip install -r dashboard_api\requirements.txt -r threat_api\requirements.txt -r log_api\requirements.txt
python -m pytest dashboard_api\tests -q
cd threat_api
python -m pytest -q
cd ..\log_api
python -m pytest -q
```

If `python` is not recognised, use `py -3` instead of `python` in every
command. Don’t chain commands with `&&` - older PowerShell doesn’t support it;
run each line separately.
</details>

### Path B - any OS with Docker Desktop (one command)

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
(Windows/Mac) or Docker Engine (Linux), then from the `ThreatOrbit-V2` folder:

```bash
# Windows (PowerShell or cmd):
copy .env.example .env
docker compose up --build -d

# Mac / Linux:
cp .env.example .env
docker compose up --build -d
```

One command builds and starts the complete product:

| Service       | URL                   | Notes                                              |
| ------------- | --------------------- | -------------------------------------------------- |
| Frontend      | http://localhost:3000 | Marketing site + operator dashboard (`/dashboard`) |
| Dashboard API | http://localhost:8002 | Auto-seeded with demo data on first boot           |
| Threat API    | http://localhost:8000 | OSINT ingestion engine                             |
| Log API       | http://localhost:8001 | Log anomaly analysis                               |

Sign in at http://localhost:3000/dashboard (`admin@threatorbit.space` /
`ChangeMe123!`). The service bridge is pre-wired, so **Feeds → Sources** can
trigger live OSINT ingestion and **SIEM → Sources** can analyse uploaded log
files out of the box. Stop with `docker compose down`.

#### Keep it running - start automatically on every boot

The Compose services already declare `restart: unless-stopped`, so Docker
restarts them if they crash **and brings them back whenever the Docker daemon
starts**. To have the whole stack come up on its own **every time the machine is
powered on**, make sure Docker itself starts at boot - then you never have to
re-run the command:

* **Linux (systemd):** enable the daemon once, then start the stack detached:
  ```bash
  sudo systemctl enable --now docker      # Docker starts on every boot
  docker compose up --build -d            # `-d` = detached; unless-stopped does the rest
  ```
  After a reboot the containers return automatically. Verify with `sudo reboot`,
  then `docker compose ps` once you're back.
* **Mac / Windows (Docker Desktop):** Docker Desktop → **Settings → General →
  "Start Docker Desktop when you sign in"** (and allow it to open at login in the
  OS). With the stack started once via `docker compose up -d`, it relaunches on
  each login.

Want it to restart **even after you manually `docker compose stop`**? Change
`restart: unless-stopped` to `restart: always` for the services in
`docker-compose.yml`. `unless-stopped` (the default here) is usually what you
want: it respects a deliberate stop but survives reboots and crashes. To turn
auto-start back off, just `docker compose down` (removes the containers) or
`sudo systemctl disable docker`.

### Path C - Linux / Mac, no Docker (one command, REAL live data)

**You need Python 3.11+ and Node.js 18+, then one command.**

```bash
cd ThreatOrbit-V2
./linux-start.sh
```

The script creates a virtualenv, installs everything, **builds the website
for fast loading**, starts the four services in the background with logs in
`.run/`, health-checks them, and prints the sign-in details. First run takes
a few minutes (pip + npm download + build); after that it starts in seconds
and every page opens instantly (it serves a production build, not the slow
dev server).

* **Open the dashboard:** http://localhost:3000/dashboard
* **Sign in:** `admin@threatorbit.space` / `ChangeMe123!` (or create an account at `/signup`)
* **Real data, by default:** the launcher runs **live mode with the synthetic
  engine off** - the dashboard starts empty, then the built-in OSINT and NVD
  connectors pull **real threat intelligence within a couple of minutes**
  (needs internet) and keep syncing on each connector's interval. SIEM alerts
  appear when you forward real logs (see
  [`docs/GOING_LIVE.md`](docs/GOING_LIVE.md)). Nothing is fabricated.
* **Other modes:** `./linux-start.sh --synthetic` adds simulated telemetry
  through the real detection pipeline (good for exercising SIEM/SOAR without
  log forwarding); `./linux-start.sh --demo` boots the seeded showcase data.
* **Stop / status:** `./linux-start.sh stop` and `./linux-start.sh status`.
  Logs live in `.run/*.log`.
* **Test:** `./linux-test.sh` runs every backend suite and prints
  `ALL TESTS PASSED` at the end.

<details>
<summary>Prefer typing the commands yourself?</summary>

```bash
cd ThreatOrbit-V2
pip install -r dashboard_api/requirements.txt
uvicorn dashboard_api.main:app --port 8002        # terminal 1 - leave running
```

```bash
cd ThreatOrbit-V2/frontend
npm install
npm run dev                                        # terminal 2 - leave running
```

Open http://localhost:3000/dashboard. Optional - also start the two ingestion
engines (each in its own terminal, from the repo root):

```bash
export APP_API_KEY=local-dev-key
python -m threat_api.main                          # Threat API on :8000
```

```bash
export APP_API_KEY=local-dev-key
uvicorn log_api.main:app --port 8001               # Log API on :8001
```

(Set `SERVICES_API_KEY=local-dev-key` when starting the dashboard API so it
can bridge to them.) Shortcuts if you have `make`: `make dev-api`,
`make dev-frontend`, `make up`, `make test` - see `make help`.

For **real data** instead of demo data, start the dashboard API with
`DASHBOARD_DATA_MODE=live` and the Threat API running (see
[§4a](#4a-real-data-vs-demo-mode)). For **fast page loads** use
`npm run build` then `python scripts/serve_frontend.py 3000` instead of
`npm run dev` (the dev server compiles each page on first visit).
</details>

### Path D - deploy to the internet

The simplest production split:

1. **Frontend → [Vercel](https://vercel.com) (free tier works).** Import the
   GitHub repo, set **Root Directory** to `frontend`, add the environment
   variable `NEXT_PUBLIC_API_URL=https://your-api-domain` and click Deploy.
   (Netlify works identically; `netlify.toml` is included.)
2. **Backend → any Linux server with Docker** (a $5 VPS is fine):
   ```bash
   git clone https://github.com/Sami9211/ThreatOrbit-V2.git && cd ThreatOrbit-V2
   cp .env.example .env
   nano .env    # set APP_API_KEY, ADMIN_API_KEY, DASHBOARD_JWT_SECRET,
                # and DASHBOARD_CORS_ORIGINS=https://your-frontend-domain
   docker compose up --build -d
   ```
   Put nginx/Caddy with TLS in front, expose only the frontend and the
   Dashboard API (8002) publicly, and keep 8000/8001 internal.

### Testing (all platforms)

| Platform   | Easiest way                                                  |
| ---------- | ------------------------------------------------------------ |
| Windows    | double-click **`windows-test.bat`**                          |
| Linux/Mac  | **`./linux-test.sh`** (or `make test`)                       |
| Any        | `python -m pytest dashboard_api/tests -q` (and the same in `threat_api/`, `log_api/`) |

Tests need **no `.env`, no Docker, and no running services** - each suite
creates its own isolated, seeded database.

---

## 4a. Real data vs demo mode

The dashboard runs in one of two modes, set by `DASHBOARD_DATA_MODE`:

| Mode             | What you get                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `demo` (default) | Seeded, realistic showcase data on first boot - great for evaluation/sales. |
| `live`           | **Starts empty**, then ingests **real** threat intelligence from connectors. |

* **Both launchers default to `live` with the engine off** (real data only) -
  `windows-start.bat synthetic` / `./linux-start.sh --synthetic` re-enable the
  evaluation telemetry engine, and `demo` / `--demo` seed the showcase dataset.
* **Docker** defaults to `demo`; switch with `DASHBOARD_DATA_MODE=live docker compose up --build -d` (or set it in `.env`).
* In live mode the dashboard bootstraps only the admin account + settings (no
  fake alerts/actors/assets) and a background scheduler keeps pulling real
  indicators on each connector's interval.
* **Deploying on real data only?** Set `DASHBOARD_ENGINE=off` as well - it
  disables the synthetic telemetry engine completely (no first-boot priming,
  boots paused every start), so the only events you ever see are your own
  forwarded logs and connector intel. The full production runbook - secrets,
  TLS, forwarding logs from **Windows/Active Directory**, **AWS/CloudTrail**,
  Linux and syslog senders - is **[`docs/GOING_LIVE.md`](docs/GOING_LIVE.md)**.

### Connectors - where real data comes from

Open **Dashboard → Feeds → Sources**. The **Threat Intel Connectors** panel is
the control surface (the same model OpenCTI uses): every connector pulls real
indicators, normalises them, and writes into the one CTI store the whole
dashboard reads from. Two come built in:

| Connector                | Real data | Needs a key?                          |
| ------------------------ | --------- | ------------------------------------- |
| **ThreatOrbit OSINT Engine** | abuse.ch, RSS, dark-web & social OSINT (and OTX if you add a key) | No - works immediately with internet |
| **NVD CVE Feed**         | Live CVEs with CVSS severity from nvd.nist.gov | No (an NVD key only raises rate limits) |

Press **Sync now** on either, or just wait - the scheduler runs them
automatically. New indicators appear across CTI, the scanner, and feeds.

### Add your own connector (build a source, connect it like AlienVault)

Click **Add Connector**. Besides the presets you can register **any** source:

* **AlienVault OTX** - pick *AlienVault OTX*, paste your free key from
  otx.alienvault.com (Settings → API); the endpoint is handled for you (no URL
  to enter). A sync **pages through your whole subscribed feed**, not just the
  first page.
* **TAXII 2.1 collection** - consume indicators from **any** TAXII 2.1 server
  (OpenCTI, MISP, Anomali, …). Paste the collection *objects* URL
  (`…/collections/<id>/objects/`); add an Authorization value only if the server
  needs auth. The paginated feed is walked automatically and STIX indicator
  objects are imported.
* **Custom JSON** - point it at any URL that returns a JSON array of
  indicators, then map which fields hold the value / type / threat-type /
  confidence / severity / tags. (Leave *type* blank to auto-detect
  ip/domain/url/hash/cve.) Optional API key sent in a header you choose.
* **Custom CSV** - same idea for a CSV endpoint; map columns instead of fields.
* **Custom STIX 2.x** - point it at a STIX bundle URL; indicator objects are imported.

So if you build your own intel system (your own “AlienVault”), expose a
JSON/CSV/STIX/TAXII endpoint and connect it here by URL + key - no code changes.
API keys you enter are stored server-side and **never sent back to the browser**.
(ThreatOrbit is *also* a TAXII 2.1 **server** - it re-serves its own indicators
at `/taxii2/` for other platforms to consume, so it both pulls and publishes.)

> **Why might a connector show an error?** Usually no internet, a wrong URL, or
> a missing/expired API key - the connector row shows the exact message and the
> dashboard keeps running. Fix it and press **Sync now**.

---

## 5. Authentication (two-tier API keys)

ThreatOrbit uses a header `X-API-Key` with two key tiers:

| Key             | Access                                                                 |
| --------------- | ---------------------------------------------------------------------- |
| `APP_API_KEY`   | Standard user. Read IOCs, jobs, results, reports, OpenCTI read routes. |
| `ADMIN_API_KEY` | Admin. Everything above, plus trigger fetch, export STIX, push OpenCTI.|

`ADMIN_API_KEY` falls back to `APP_API_KEY` when unset, so single-key setups keep working. Configure via `.env` (see `.env.example`). Optional keys: `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `OPENCTI_URL`, `OPENCTI_API_KEY`.

Feed source files (one URL per line): `threat_api/rss_feeds.txt`, `threat_api/darkweb_sources.txt`, `threat_api/social_sources.txt`. Trust weights live in `threat_api/source_trust_config.json`.

---

## 6. Health checks and self-observability

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8002/health
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8001/ready
curl http://127.0.0.1:8002/ready
```

The two probes have different jobs (wire them to the matching Kubernetes/LB
slots): `/health` is **liveness** - always 200 while the process is up;
`/ready` is **readiness** - it runs a real database check and returns
**HTTP 503** when the DB is unreachable, so an orchestrator pulls the
instance out of rotation instead of routing traffic it cannot serve.

Beyond the probes, the platform watches its own vitals:

* **`GET /self-health`** (authenticated) aggregates database latency, schema
  version, detection-queue backpressure, leader lease, and process counters
  into one ok/degraded/down verdict - rendered live in the dashboard at
  **Settings → General → System Health**, with a notification raised on every
  verdict transition (degrade/recover).
* **`GET /metrics`** serves Prometheus metrics, and
  [`deploy/prometheus/`](deploy/prometheus/) ships ready-to-use alert rules
  over them (target down, readiness failing, error rate, detection backlog).
  Details: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

---

## 7. Threat API usage (:8000)

The async job model: `POST /fetch` returns a `job_id` immediately, then you poll `GET /jobs/{id}`.

```bash
# Trigger ingestion (admin key). Returns a job_id.
curl -X POST "http://127.0.0.1:8000/fetch?enrich=true&max_enrich=25" \
  -H "X-API-Key: YOUR_ADMIN_API_KEY"

# Poll job status
curl "http://127.0.0.1:8000/jobs/<JOB_ID>" -H "X-API-Key: YOUR_APP_API_KEY"

# List IOCs
curl "http://127.0.0.1:8000/iocs?limit=20" -H "X-API-Key: YOUR_APP_API_KEY"

# Source health
curl "http://127.0.0.1:8000/source-health" -H "X-API-Key: YOUR_APP_API_KEY"

# Export STIX bundle (admin key)
curl -X POST "http://127.0.0.1:8000/stix/export" \
  -H "X-API-Key: YOUR_ADMIN_API_KEY" -o threat_stix_bundle.json
```

---

## 8. Log API usage (:8001)

```bash
# Analyse a log file (user key). Add ?async=true to run in the background.
curl -X POST "http://127.0.0.1:8001/analyse?log_format=apache&generate_report=true" \
  -H "X-API-Key: YOUR_APP_API_KEY" \
  -F "file=@log_api/sample_logs/sample_apache.log"

# Poll a background job
curl "http://127.0.0.1:8001/jobs/<JOB_ID>" -H "X-API-Key: YOUR_APP_API_KEY"

# View the HTML report
#   open http://127.0.0.1:8001/report  (send the X-API-Key header)

# Severity trend summary
curl "http://127.0.0.1:8001/trends/severity" -H "X-API-Key: YOUR_APP_API_KEY"

# Export STIX from a result
curl "http://127.0.0.1:8001/results/<RESULT_ID>/stix" \
  -H "X-API-Key: YOUR_APP_API_KEY" -o log_stix_bundle.json
```

---

## 9. OpenCTI integration

1. Deploy OpenCTI (https://docs.opencti.io/latest/deployment/) and set `OPENCTI_URL` + `OPENCTI_API_KEY` in `.env`.
2. Check connectivity and read indicators directly from the Threat API:

```bash
curl "http://127.0.0.1:8000/opencti/status"      -H "X-API-Key: YOUR_APP_API_KEY"
curl "http://127.0.0.1:8000/opencti/stats"       -H "X-API-Key: YOUR_APP_API_KEY"
curl "http://127.0.0.1:8000/opencti/indicators"  -H "X-API-Key: YOUR_APP_API_KEY"
curl "http://127.0.0.1:8000/opencti/search?q=APT" -H "X-API-Key: YOUR_APP_API_KEY"
```

3. Push enriched intelligence (admin key):

```bash
curl -X POST "http://127.0.0.1:8000/opencti/push" -H "X-API-Key: YOUR_ADMIN_API_KEY"
```

You can also export STIX bundles from both services and import them through the OpenCTI UI (Data > Import).

---

## 10. API reference

### Threat API (`:8000`)

| Method | Path                     | Auth  | Purpose                          |
| ------ | ------------------------ | ----- | -------------------------------- |
| GET    | `/health`                | none  | Liveness                         |
| GET    | `/ready`                 | none  | Readiness                        |
| GET    | `/metrics`               | none  | Prometheus-style metrics         |
| GET    | `/source-health`         | user  | Per-source fetch health          |
| GET    | `/source-stats`          | user  | Per-source counts                |
| GET    | `/trust/config`          | user  | Active trust-scoring config      |
| POST   | `/fetch`                 | admin | Start ingestion job (returns id) |
| GET    | `/jobs`                  | user  | List recent jobs                 |
| GET    | `/jobs/{job_id}`         | user  | Job status                       |
| GET    | `/iocs`                  | user  | Query stored IOCs                |
| POST   | `/stix/export`           | admin | Export STIX 2.1 bundle           |
| POST   | `/opencti/push`          | admin | Push bundle to OpenCTI           |
| GET    | `/opencti/status`        | user  | OpenCTI connectivity             |
| GET    | `/opencti/stats`         | user  | OpenCTI counts                   |
| GET    | `/opencti/indicators`    | user  | Read indicators from OpenCTI     |
| GET    | `/opencti/search`        | user  | Search OpenCTI                   |

### Log API (`:8001`)

| Method | Path                          | Auth | Purpose                       |
| ------ | ----------------------------- | ---- | ----------------------------- |
| GET    | `/health`                     | none | Liveness                      |
| GET    | `/ready`                      | none | Readiness                     |
| GET    | `/metrics`                    | none | Prometheus-style metrics      |
| GET    | `/trends/severity`            | user | Severity trend summary        |
| POST   | `/analyse`                    | user | Analyse a log file            |
| GET    | `/jobs/{job_id}`              | user | Background job status         |
| GET    | `/report`                     | user | Latest HTML report            |
| GET    | `/results/{result_id}`        | user | Result detail                 |
| GET    | `/results/{result_id}/stix`   | user | STIX 2.1 from a result        |

### Dashboard API (`:8002`)

JWT bearer auth (`POST /auth/login`, self-service `POST /auth/register`).
200+ routes across 18 routers (auth, users, orgs, overview, SIEM, SOAR, CTI,
assets, feeds, connectors, darkweb, platform, reports, services, stream, taxii,
assistant, config) - including computed SOC metrics, an
alert-correlation engine, a live hunt-query engine, SOAR case lifecycle
(notes/tasks), a transparent asset risk model with per-axis breakdowns, IOC
lookup/bulk-import/scanner history, webhooks, and a full audit trail. The
complete endpoint map and algorithm notes live in
[`dashboard_api/README.md`](dashboard_api/README.md).

---

## 11. Testing

* **Windows:** double-click **`windows-test.bat`** (installs test deps, runs
  all three suites, prints a clear pass/fail summary).
* **Mac/Linux:** `make test` - all three API suites plus the frontend type-check.

Or run any suite directly (works on every OS - run each line separately):

```bash
python -m pytest dashboard_api/tests -q   # from the repo root (147 tests)
cd threat_api
python -m pytest -q
cd ../log_api
python -m pytest -q
cd ../frontend
npx tsc --noEmit
npm run build
```

Tests set their own API keys and use an isolated temp database via
`conftest.py`, so no `.env`, Docker, or running services are required.

---

## 12. Troubleshooting

**Windows-specific**

* **`'python' is not recognized`**: Python isn’t on PATH. Re-run the installer
  and tick **“Add python.exe to PATH”**, or replace `python` with `py -3` in
  every command. `windows-start.bat` / `windows-test.bat` handle this fallback
  automatically.
* **`'make' is not recognized`**: `make` is a Mac/Linux tool - on Windows use
  `windows-start.bat` / `windows-test.bat` instead.
* **`The token '&&' is not a valid statement separator`**: older PowerShell
  doesn’t support `&&`. Run each command on its own line.
* **pip errors mentioning “Microsoft Visual C++” or “building wheel”**: you’re
  likely on a very new Python before our pinned ranges - run
  `python -m pip install --upgrade pip` and retry; all dependencies ship
  prebuilt wheels for Python 3.11-3.13.
* **A service window closes immediately**: a port is already in use. Close
  other ThreatOrbit windows (or anything on ports 3000/8000/8001/8002) and
  run `windows-start.bat` again.

**General**

* **401 Unauthorized**: the `X-API-Key` header is missing or does not match `APP_API_KEY` / `ADMIN_API_KEY`.
* **403 Admin access required**: the route needs `ADMIN_API_KEY` and you sent the user key.
* **No IOCs ingested**: feed files may be empty or unreachable. Check `/source-health`.
* **Empty STIX export**: run `/fetch` (Threat API) or `/analyse` (Log API) first.
* **OpenCTI push fails**: confirm OpenCTI is reachable and `OPENCTI_URL` / `OPENCTI_API_KEY` are set.
* **ML detector warnings**: ensure `scikit-learn` and `numpy` are installed in `log_api`.
* **429 Rate limit**: too many requests too quickly. Retry later or raise `RATE_LIMIT_PER_MINUTE`.
* **Docker rebuild**: `docker compose down && docker compose up --build`.
* **Frontend 404 on Vercel**: set the project Root Directory to `frontend`.

---

## 13. Intended users

ThreatOrbit suits individual analysts and small-to-mid security teams who want a deployable CTI plus anomaly-detection workflow that integrates with OpenCTI - topped with a full SOC dashboard (SIEM triage, SOAR cases/playbooks, asset risk, dark-web monitoring, an AI assistant, and a complete audit trail) - without standing up a heavy SIEM. The three services can run independently or together, locally or in containers.

**One platform, two postures.** The same install serves a two-person team and
an analyst-grade SOC without a different SKU: flip **Simple mode** (Config →
General → Experience Mode → Normal) for a small org that wants the 10-area
essentials - triage the alert queue, work cases, get basic intel, know your
assets, report up the chain - without a rules engine, playbook builder,
ATT&CK matrix, or UEBA console in the way. Flip **Power mode** for the full
24-area surface once the team is ready for it. Nothing is deleted or degraded
underneath - it's a curated nav over the identical backend and RBAC, so an org
can move from Simple to Power the moment it outgrows the essentials view,
with zero migration. See [§2b](#2b-using-the-dashboard---by-role-and-by-task)
for the full feature split.

**Scaling honestly:** the default single-node SQLite stack comfortably serves a
small team and is the right starting point. Larger teams should run the staged
Postgres backend, put the APIs behind a TLS proxy (see `docs/DEPLOYMENT.md`),
and turn on multi-tenancy. The remaining work before a *large-enterprise*
go-live is tracked honestly in [§14](#14-roadmap--direction) and
[§15](#15-limitations--honest-caveats) - read those before you pitch this to a
big SOC.

## 14. Roadmap & direction

**Where it is.** The full product roadmap (Phases 0-5: cross-cutting platform,
SIEM depth, SOAR depth, CTI depth, asset/vuln/dark-web depth, and product
polish) is **implemented** and recorded - see [`plan.md`](plan.md), which keeps
a dated CHANGELOG so the roadmap stays honest. That includes real-time push
(SSE), RBAC depth, multi-tenancy, MFA, an ATT&CK navigator, a visual playbook
builder, STIX/TAXII, an enrichment pipeline, IOC lifecycle, and the security
pass (audits in CI, patched deps, security headers, encryption-at-rest).

**Where it's going (direction).** The guiding idea is *convergence done
honestly*: one pipeline, one audit trail, one console - and never a number on
screen that doesn't trace back to the API. Near-term direction:

* **Production hardening to enterprise scale** - validate the Postgres backend
  under load, wire E2E (Playwright) into CI, complete an external pentest, and
  run a real-log pilot. These are the Tier-1 items in `plan.md` under
  *Production readiness*.
* **Identity** - SSO (OIDC/SAML) and SCIM provisioning for larger orgs.
* **Billing** - Stripe-backed plans/seats on top of the existing licensing.
* **Connectors** - broaden first-class connectors (EDR/cloud/identity) beyond
  the current OSINT/NVD/TAXII set.
* **Assistant** - pluggable model backends (OpenAI-compatible, local) so the
  in-dashboard AI runs cheaply or fully offline (see [§16](#16-contributing--extending)).

If you want to influence priority, open an issue describing the workflow you
need - the roadmap is deliberately demand-driven.

## 15. Limitations & honest caveats

In the spirit of "no invented data", here is what ThreatOrbit does **not** do
yet, or only does under specific conditions:

* **One synthesized input.** In demo mode the raw *environment event stream*
  (auth/network/endpoint logs) is generated, because a SIEM cannot have that be
  "real" before your systems forward logs to it. Everything downstream
  (detection, correlation, response, enrichment, attribution, reporting) is
  real code on that data, and genuine logs flow through the identical pipeline.
  Run `DASHBOARD_DATA_MODE=live` and forward logs for a fully real stream.
* **Single-node by default.** The default store is WAL-mode SQLite - excellent
  for a laptop or small team, not for a high-write multi-node cluster. A
  Postgres backend is staged (`db_backend.py`) but not yet load-validated at
  scale.
* **No external pentest yet.** The code ships a security pass (dependency
  audits in CI, security headers, encryption-at-rest, MFA, rate limiting, an
  audit trail), and `SECURITY.md` states plainly that a third-party
  penetration test has **not** been performed. Treat it accordingly before
  exposing it to untrusted networks.
* **Auth scope.** Email+password (JWT) with optional TOTP MFA today. SSO
  (OIDC/SAML) and SCIM are on the roadmap, not shipped.
* **Billing.** Licensing/seat limits exist; payment (Stripe) does not.
* **Appearance prefs are per-browser.** Theme, accent, scale, motion and
  density are stored in `localStorage` and sync across your open tabs - they
  are not yet a server-side per-user profile, so they don't follow you to a new
  device.
* **Assistant needs a model key for full reasoning.** Without one it still
  works via a deterministic intent router over the same read-only tools, but
  the free-form "reason about my data" path needs an API key (and any
  OpenAI-compatible/local backend needs the small adapter noted in §16).
* **Some integrations are reference-grade.** Slack/PagerDuty/webhook routing
  is real; the broader connector catalog on the marketing site describes the
  direction, not a guarantee that every named vendor is wired.

## 16. Contributing & extending

**Repo workflow.**

* Develop on a feature branch; keep commits small and descriptive (one logical
  unit each). Run the gates below before you push.
* **Safety rule we follow:** if a change might break the build or a workflow,
  don't ship it half-done - keep what's needed and comment the rest (or move it
  to a separate file) rather than leaving the tree broken.
* The full stack must stay installable in one shot: the three services share
  pinned dependency ranges so the Windows bats' combined `pip install`
  resolves (a past divergence broke it - see the CHANGELOG).

**The gates (run before pushing).**

```bash
python -m pytest dashboard_api/tests -q     # backend behaviour tests
cd threat_api && python -m pytest -q && cd ..
cd log_api   && python -m pytest -q && cd ..
cd frontend  && npx tsc --noEmit && npm run build   # type-check + production build
```

`windows-test.bat` (Windows) and `make test` (Mac/Linux) run all of this.

**Extending - where things plug in.**

* **A new API surface:** add a router in `dashboard_api/routers/`, include it in
  `main.py`, and add behaviour tests under `dashboard_api/tests/`. Stamp state
  changes into the audit trail (see `db.py`'s audit helper) and respect the
  capability matrix in `permissions.py`.
* **A new dashboard page:** add a route under `frontend/app/dashboard/`, call the
  typed client in `lib/api.ts`, and gate it with `usePermissions`. Anything
  visual reads from the API - no hardcoded numbers.
* **A new detection rule:** extend `rule_engine.py` / `detections.py`; new
  alerts automatically feed correlation → SOAR.
* **A new intel connector:** follow the connector pattern (the README's
  "Add your own connector" section and `routers/connectors.py`); indicators land
  in the same store as OSINT.
* **A cheaper/free assistant backend:** `assistant.py` calls the Anthropic
  Messages API over `httpx` and reads `DASHBOARD_ASSISTANT_MODEL` +
  `ANTHROPIC_API_KEY`. To use an OpenAI-compatible endpoint (Azure OpenAI,
  OpenRouter, Groq, a local Ollama/LM Studio server, etc.) add a small adapter
  that maps the request/response shape - the tool registry and security model
  stay identical. With **no** key it already works via the deterministic
  router, so the dashboard is never blocked on a paid API.

## FAQ

**Is the data real, or is it simulated?**
Wherever real data can be obtained, ThreatOrbit uses real data - and it is wired
end-to-end, not faked in the UI. Threat intelligence is real OSINT (abuse.ch,
NVD, RSS, OTX, custom connectors, TAXII push). Detections, correlation, UEBA,
SOAR playbook execution, vulnerability scanning, dark-web credential matching,
enrichment, attribution and reporting are all real, executable backend code
operating on that data. The dashboard reads it live from the API.

**Then what part is generated?**
One input: the raw **environment event stream** (auth/network/endpoint/cloud
logs from *your own* infrastructure). A SIEM only sees that once it is deployed
and your systems forward logs to it - there is no way to have it be "real"
before then. So in demo mode the engine generates a representative stream for
that one input, and the **real** detection→correlation→response pipeline runs on
it. You can feed genuine logs at any time and they flow through the identical
pipeline:

* **Upload** a log file (SIEM → Sources → Log Collector, or the Log API).
* **Syslog**: point a forwarder at the UDP listener (`DASHBOARD_SYSLOG_PORT`)
  or the TLS listener (`DASHBOARD_SYSLOG_TLS_PORT`, RFC 5425, optional mTLS).
* **File watcher**: drop/append files into `DASHBOARD_LOG_WATCH_DIR`.
* **Connectors / TAXII push** for indicators.

Windows/Sysmon, AWS/Azure/GCP audit, CrowdStrike & SentinelOne EDR, Microsoft
365 (Defender + Office audit), and Palo Alto / FortiGate firewall logs are all
recognised and normalised onto the detection vocabulary at ingest - see
[`docs/SUPPORTED_SOURCES.md`](docs/SUPPORTED_SOURCES.md) for the full matrix.

**How do I run it on fully real data?**
Set `DASHBOARD_DATA_MODE=live` (starts empty, no generated stream), enable
connectors for intel, and forward your logs via one of the paths above. See
[§4a](#4a-real-data-vs-demo-mode).

**Is anything hardcoded in the UI?**
No section should display invented numbers - the dashboard pulls from the API.
If you spot a value that does not trace back to the API, it is a bug; please
open an issue.

**Does the AI assistant cost money to run?**
Only if you point it at a paid model. Out of the box, with no API key, it runs
a deterministic intent router over the same read-only tools - free and offline.
For free-form reasoning it calls a model via `ANTHROPIC_API_KEY` /
`DASHBOARD_ASSISTANT_MODEL`. You can instead point it at a cheaper or free
OpenAI-compatible backend (Azure OpenAI, OpenRouter, Groq, a local Ollama / LM
Studio server, etc.) by adding a small request/response adapter in
`assistant.py` - the tool registry and the read-only security model stay
identical. See [§16](#16-contributing--extending).

**Can I recolour or rescale the dashboard?**
Yes - **Config → General → Appearance**: 11 themes, a custom accent colour
(presets or any hex), a UI-scale slider, and motion / density toggles. Choices
are saved per-browser and sync across your open dashboard tabs; the public
marketing site keeps its signature Plasma Noir look.

**How do I turn on two-factor auth?**
**Config → Security → Two-factor authentication.** It is real TOTP (RFC 6238) -
scan the secret into any authenticator app, verify a code to enable, and every
future sign-in asks for one. The secret is shown once and stored encrypted.
