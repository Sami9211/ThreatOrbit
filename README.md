# ThreatOrbit

**Threat Intelligence Ingestion + Log Anomaly Detection + SOC Dashboard + STIX / OpenCTI Integration**

ThreatOrbit is a cybersecurity platform made of three backend services and a Next.js frontend (marketing site + full operator dashboard):

* **Threat API** (`threat_api`, Flask, port 8000)
  Ingests external threat feeds (OTX, abuse.ch, RSS, dark-web OSINT, social OSINT) in parallel, normalizes and trust-scores indicators, enriches with VirusTotal, exports STIX 2.1, and reads from / pushes to OpenCTI.
* **Log API** (`log_api`, FastAPI, port 8001)
  Parses logs (Apache, Syslog, Windows Event, Generic), detects anomalies via four engines (Pattern, Statistical, ML, Temporal), generates HTML reports, and exports STIX 2.1 from findings.
* **Dashboard API** (`dashboard_api`, FastAPI, port 8002)
  The unified backend powering the operator dashboard: JWT auth (login + self-service registration with brute-force throttling) and role-based users, SIEM alerts with computed SOC metrics (MTTD/MTTA/MTTR), a correlation engine and a live hunt-query engine, SOAR case lifecycle (create, war-room notes, task workflow), CTI actors/IOCs with lookup + bulk import + scanner history, an asset surface with a transparent CVSS-style risk model, threat feeds, settings, API keys, webhooks, a full audit trail — and a **service bridge** that proxies the Threat API and Log API server-side so the browser never handles their API keys. See [`dashboard_api/README.md`](dashboard_api/README.md).
* **Frontend** (`frontend`, Next.js 14 + TypeScript)
  Marketing site **and** the operator dashboard (`/dashboard/**`, 23 wired pages) that consumes the Dashboard API live, with seeded demo data as graceful fallback. Deployable on Vercel.

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
                                ├── marketing site (/)
                                └── operator dashboard (/dashboard/**) ---> Dashboard API
```

---

## 2. Project structure

```text
ThreatOrbit-V2/
├── README.md
├── Makefile                     # make up / down / test / dev-* shortcuts (Mac/Linux)
├── windows-start.bat            # double-click: full local start on Windows
├── windows-test.bat             # double-click: run every test suite on Windows
├── .gitignore
├── .env.example                 # copy to .env, fill in keys
├── docker-compose.yml           # full stack: 3 APIs + frontend, healthchecked
│
├── docs/
│   ├── architecture.md
│   ├── opencti_integration.md
│   └── api_examples.md
│
├── threat_api/                  # Flask threat-intel service (:8000)
│   ├── Dockerfile
│   ├── main.py                  # routes, async job runner, OpenCTI read/push
│   ├── config.py                # env-driven config + API keys
│   ├── db.py                    # WAL SQLite, batch upsert, IOC store
│   ├── models.py
│   ├── normalization.py
│   ├── trust_scoring.py
│   ├── rate_limit.py            # thread-safe rate limiter
│   ├── source_health.py
│   ├── scheduler.py
│   ├── retention.py
│   ├── metrics.py
│   ├── opencti_push.py          # STIX bundle push over HTTP
│   ├── source_trust_config.json
│   ├── rss_feeds.txt
│   ├── darkweb_sources.txt
│   ├── social_sources.txt
│   ├── requirements.txt
│   ├── fetchers/                # otx, abusech, rss, darkweb_osint, social_osint
│   ├── enrichment/              # virustotal (pooled session, retries)
│   ├── stix_converter/          # converter to STIX 2.1
│   └── tests/                   # conftest.py, test_health.py
│
├── log_api/                     # FastAPI log-analysis service (:8001)
│   ├── Dockerfile
│   ├── main.py                  # routes, async analysis, auth dependencies
│   ├── config.py
│   ├── db.py                    # WAL SQLite
│   ├── models.py
│   ├── metrics.py
│   ├── stix_from_findings.py
│   ├── requirements.txt
│   ├── parsers/                 # apache, syslog, windows_event, generic
│   ├── detectors/               # pattern, statistical, ml_detector, temporal
│   ├── alerts/                  # alerter.py (correlation + severity)
│   ├── reporter/                # report.py (HTML report)
│   ├── sample_logs/             # generator.py + sample_apache.log
│   └── tests/                   # conftest.py, test_health.py
│
├── dashboard_api/               # FastAPI dashboard backend (:8002)
│   ├── Dockerfile
│   ├── main.py                  # app wiring, CORS, error handlers, startup seed
│   ├── auth.py                  # PBKDF2 passwords + stdlib HS256 JWT, role deps
│   ├── config.py                # env-driven config
│   ├── db.py                    # WAL SQLite, schema, migrations, audit helper
│   ├── scoring.py               # CVSS-style asset risk model + org rollups
│   ├── seed.py                  # deterministic, internally-consistent demo data
│   ├── routers/                 # auth, users, overview, siem, soar, cti, assets,
│   │                            #   feeds, config — 59 routes total
│   └── tests/                   # 29 behaviour tests (pytest + TestClient)
│
└── frontend/                    # Next.js 14 — marketing site + operator dashboard
    ├── app/
    │   ├── page.tsx             # marketing landing
    │   └── dashboard/           # operator dashboard (23 pages, all API-wired):
    │                            #   overview, siem(+rules/sources/hunt),
    │                            #   soar(+playbooks/integrations/metrics),
    │                            #   cti(+actors/hunt), assets(+network/vulns),
    │                            #   feeds(+sources/import), scanner,
    │                            #   config(+api/users/sources)
    ├── components/
    │   ├── dashboard/           # AuthGuard (JWT route protection)
    │   ├── effects/             # ParticleNetwork, CursorGlow, SmoothScroll
    │   ├── layout/              # Navbar, Footer
    │   ├── sections/            # Hero, Features, ExpandingShowcase, etc.
    │   └── ui/                  # Logo, Reveal, MagneticButton, CountUp, ScrollProgress
    ├── lib/
    │   ├── api.ts               # typed Dashboard API client (snake→camel mapping)
    │   └── auth-context.tsx     # login/session state backed by /auth
    ├── tailwind.config.ts
    ├── next.config.mjs
    └── package.json
```

---

## 2a. How the ThreatOrbit engine works (the real data pipeline)

ThreatOrbit is not a mockup with hardcoded numbers — it is a working pipeline.
Here is exactly where data comes from and how each service processes and
displays it. (In **demo mode** these stores are pre-filled with realistic
sample data so you can evaluate the UI; in **live mode** they start empty and
fill from the real pipeline below — see [§4a](#4a-real-data-vs-demo-mode).)

### The engine (Threat API, `:8000`)

`threat_api` is the ingestion engine. One `POST /fetch` (or the built-in
scheduler) runs this pipeline (`threat_api/main.py` → `_run_pipeline`):

```
  ┌── abuse.ch (Feodo blocklist — keyless; URLHaus — free Auth-Key)
  ├── RSS security feeds (keyless — IOCs extracted from articles)
  ├── AlienVault OTX (free API key)            ── parallel fetch ──┐
  ├── dark-web OSINT sources                                       │
  └── social OSINT sources                                         ▼
                                              normalise → dedup → trust-score
                                              → confidence-correlate
                                              → VirusTotal enrich (optional key)
                                              → persist (WAL SQLite) + STIX 2.1
```

Every indicator carries a type, source, threat-type, a trust-weighted
confidence, tags, and (if enriched) a VirusTotal detection ratio. This is real
OSINT — abuse.ch's Feodo blocklist alone returns thousands of live malicious
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
  detection rules  ───────────► SIEM ALERTS  (severity, MITRE technique→tactic,
        │                                     evidence, dedup, rule name)
        ▼
  IOC extraction  ────────────► CTI INDICATORS (deduped, actor-attributed)
        ▼
  correlation (host/user/ip) ─► SOAR CASES   (auto-opened when ≥3 critical/high
        │                                     alerts share a pivot; IR tasks +
        │                                     war room created)
        ▼
  dark-web monitoring ────────► DARK-WEB FINDINGS (leaked creds, data sales,
                                                   actor chatter, access listings)
```

Every stage above — parsing, the detection rule engine, correlation, SOAR
escalation, IOC extraction, dark-web matching — is real, executable code, and
all of it runs on **real data** wherever real data is available: uploaded logs,
the syslog listener / file watcher, connector feeds, TAXII push, and threat-intel
matches all write into these same stores. The **only** seeded/generated input is
*environment telemetry* — the raw auth/network/endpoint event stream a SIEM
normally receives from your own infrastructure. That stream genuinely requires a
deployment with log forwarding configured (see
[§4a](#4a-real-data-vs-demo-mode) and the [FAQ](#faq)); until then the engine
generates a representative stream so the detection/correlation/response pipeline
has something real to act on. You can pause it, or click **Generate burst now**,
from **Config → General → Live Processing Engine**.

### Each section's workflow — distinct by design

SIEM, SOAR, and CTI are deliberately separate stages of one operation. Here is
exactly how each ingests, processes, and displays data:

**SIEM — detection & monitoring** (`/dashboard/siem`)
* **Ingest:** environment telemetry (engine) + uploaded logs (Log API's
  pattern/statistical/ML/temporal detectors) + critical-IOC intel matches.
* **Process:** every event is evaluated by detection rules → an alert with a
  risk score, MITRE technique→tactic, source IP/user/host, and raw evidence.
  `/siem/correlations` clusters unresolved alerts by shared pivot;
  `/siem/kpis` computes MTTD/MTTA/MTTR from per-alert latency;
  `/siem/mitre-distribution` builds the ATT&CK heatmap.
* **Display:** the alert queue (auto-refreshing every 15s), rules engine,
  correlation view, MITRE heatmap, and the KQL-style hunt console.

**SOAR — orchestration & response** (`/dashboard/soar`)
* **Ingest:** SIEM alerts. The correlation engine **auto-escalates** any pivot
  with ≥3 correlated critical/high alerts into a case; analysts also open cases
  from any alert (**Create Case**).
* **Process:** each case gets an IR task list (Triage → Containment →
  Eradication → Recovery), a war room, evidence chain, and SLA timer.
  Playbooks run response actions; `/soar/metrics` computes MTTR and the real
  automation rate from playbook-driven closures.
* **Display:** the case board, playbook runner with a live step timeline, the
  integrations grid, and SOC metrics. *This is why SIEM ≠ SOAR:* SIEM **finds**,
  SOAR **manages the response** — different data, different lifecycle.

**CTI — intelligence & library** (`/dashboard/cti`, `/dashboard/feeds`)
* **Ingest:** the Threat API OSINT engine + connectors (NVD, OTX, custom) +
  IOCs the live engine extracts from detections.
* **Process:** indicators are deduped, confidence/trust-scored, actor-attributed,
  and enriched (VirusTotal); `/cti/summary` and `/cti/graph` build the actor
  and relationship views; the scanner (`/cti/lookup`) checks any value against
  the store.
* **Display:** CTI overview, actor profiles, the IOC library/feeds, IntelScope
  scanner, and threat-hunt console.

**Asset Surface — exposure & risk** (`/dashboard/assets`)
* **Ingest:** assets you add/import + NVD CVEs (connector).
* **Process:** each asset's 0–100 risk is a transparent four-axis model
  (vulnerability, exposure, patch, alert-pressure — `scoring.py`); recomputed
  from live SIEM alert pressure, so triaging alerts lowers asset risk.
* **Display:** inventory, vulnerability rollup, and the interactive network map.

**Dark Web — external exposure** (`/dashboard/darkweb`) — *new*
* **Ingest:** the engine's dark-web monitoring stage produces findings across
  five categories (credential leak, data for sale, brand mention, actor chatter,
  access listing).
* **Process:** each finding has a severity, affected entity, source forum/market,
  and a triage lifecycle (new → investigating → mitigated → dismissed).
* **Display:** a dedicated, auto-refreshing findings feed with category filters
  and a triage panel — distinct from CTI (what's known *about threats*) because
  this is what's being said about *you* outside your perimeter.

So the chain is: **live engine + real OSINT + real log analysis → the stores →
every section**, each a distinct stage of the SOC workflow.

### See it live in 60 seconds

1. Start in live mode (the Windows launcher does this automatically; otherwise
   set `DASHBOARD_DATA_MODE=live`).
2. **Log in.** Every section is already populated by the engine's initial prime
   and keeps growing every 20 seconds — watch the SIEM queue, Dark Web, and CTI.
3. **Config → General → Live Processing Engine → Generate burst now** to add a
   wave of alerts/IOCs/cases/findings on demand (or **Pause** to freeze it).
4. Want *external* intelligence too? **Feeds → Sources → Sync now** on the
   ThreatOrbit OSINT and NVD connectors (needs internet). Want real detections
   from your own logs? **SIEM → Sources → upload a log**.

## 3. Requirements

**Minimum (Path A — Windows, or Path C — Mac/Linux, no Docker)**

* Python 3.11+ and Node.js 18+ (LTS recommended) — nothing else
* CPU: 2 cores, RAM: 4 GB, Disk: 5 GB free

**For the one-command Docker path (B/D)**

* Docker Desktop (Windows/Mac) or Docker Engine + Compose (Linux)

**Recommended**

* CPU: 4+ cores, RAM: 8 to 16 GB, Disk: 20+ GB
* Stable internet (for feed ingestion and external enrichment APIs)

For the OpenCTI workflow, deploy OpenCTI first using the official docs:
https://docs.opencti.io/latest/deployment/

---

## 4. Quick start — pick the path for your machine

> **Get the code first** (any OS): install [Git](https://git-scm.com/downloads)
> and run `git clone https://github.com/Sami9211/ThreatOrbit-V2.git` — or click
> **Code → Download ZIP** on GitHub and unzip it. Every path below starts
> inside that folder.

### Path A — Windows, no Docker (easiest on Windows)

**You need exactly two installers, then one double-click.**

1. Install **Python** from https://www.python.org/downloads/ —
   ⚠️ on the first screen of the installer, tick **“Add python.exe to PATH”**.
2. Install **Node.js (LTS)** from https://nodejs.org/ — accept the defaults.
3. Open the `ThreatOrbit-V2` folder and **double-click `windows-start.bat`**.

The script installs everything, **builds the website for fast loading**, opens
four service windows, and launches your browser at http://localhost:3000.
First run takes a few minutes (npm download + build); after that pages open
**instantly** (it serves a production build, not the slow dev server).

* **Open the dashboard:** click **Sign in** on the site, or go to
  http://localhost:3000/dashboard
* **Sign in:** `admin@threatorbit.space` / `ChangeMe123!` (or create an account at `/signup`)
* **Real data:** the launcher runs in **live mode** — the dashboard starts
  empty and fills itself from real OSINT feeds within a couple of minutes
  (needs internet). See [§4a Real data vs demo](#4a-real-data-vs-demo-mode).
* **Stop:** close the four windows the script opened.
* **Test:** double-click **`windows-test.bat`** — it runs all backend tests
  and prints `ALL TESTS PASSED` at the end.

> **Were pages slow before (5–10s each)?** That was the Next.js *dev server*
> compiling each page on first visit. The launcher now serves a pre-built
> production site, so every page is instant. (If you run `npm run dev`
> manually you'll still see the dev-server delay — that's expected; use the
> launcher or `npm run build` for the fast version.)

<details>
<summary>Prefer typing the commands yourself? (PowerShell — run one line at a time)</summary>

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
command. Don’t chain commands with `&&` — older PowerShell doesn’t support it;
run each line separately.
</details>

### Path B — any OS with Docker Desktop (one command)

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

### Path C — Mac / Linux, no Docker

```bash
cd ThreatOrbit-V2
pip install -r dashboard_api/requirements.txt
uvicorn dashboard_api.main:app --port 8002        # terminal 1 — leave running
```

```bash
cd ThreatOrbit-V2/frontend
npm install
npm run dev                                        # terminal 2 — leave running
```

Open http://localhost:3000/dashboard. Optional — also start the two ingestion
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
`make dev-frontend`, `make up`, `make test` — see `make help`.

For **real data** instead of demo data, start the dashboard API with
`DASHBOARD_DATA_MODE=live` and the Threat API running (see
[§4a](#4a-real-data-vs-demo-mode)). For **fast page loads** use
`npm run build` then `python scripts/serve_frontend.py 3000` instead of
`npm run dev` (the dev server compiles each page on first visit).

### Path D — deploy to the internet

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
| Mac/Linux  | `make test`                                                   |
| Any        | `python -m pytest dashboard_api/tests -q` (and the same in `threat_api/`, `log_api/`) |

Tests need **no `.env`, no Docker, and no running services** — each suite
creates its own isolated, seeded database.

---

## 4a. Real data vs demo mode

The dashboard runs in one of two modes, set by `DASHBOARD_DATA_MODE`:

| Mode             | What you get                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `demo` (default) | Seeded, realistic showcase data on first boot — great for evaluation/sales. |
| `live`           | **Starts empty**, then ingests **real** threat intelligence from connectors. |

* The **Windows launcher uses `live`** so you see real data.
* **Docker** defaults to `demo`; switch with `DASHBOARD_DATA_MODE=live docker compose up --build -d` (or set it in `.env`).
* In live mode the dashboard bootstraps only the admin account + settings (no
  fake alerts/actors/assets) and a background scheduler keeps pulling real
  indicators on each connector's interval.

### Connectors — where real data comes from

Open **Dashboard → Feeds → Sources**. The **Threat Intel Connectors** panel is
the control surface (the same model OpenCTI uses): every connector pulls real
indicators, normalises them, and writes into the one CTI store the whole
dashboard reads from. Two come built in:

| Connector                | Real data | Needs a key?                          |
| ------------------------ | --------- | ------------------------------------- |
| **ThreatOrbit OSINT Engine** | abuse.ch, RSS, dark-web & social OSINT (and OTX if you add a key) | No — works immediately with internet |
| **NVD CVE Feed**         | Live CVEs with CVSS severity from nvd.nist.gov | No (an NVD key only raises rate limits) |

Press **Sync now** on either, or just wait — the scheduler runs them
automatically. New indicators appear across CTI, the scanner, and feeds.

### Add your own connector (build a source, connect it like AlienVault)

Click **Add Connector**. Besides the presets you can register **any** source:

* **AlienVault OTX** — pick *AlienVault OTX*, paste your free key from
  otx.alienvault.com (Settings → API). Your subscribed pulses flow in.
* **Custom JSON** — point it at any URL that returns a JSON array of
  indicators, then map which fields hold the value / type / threat-type /
  confidence / severity / tags. (Leave *type* blank to auto-detect
  ip/domain/url/hash/cve.) Optional API key sent in a header you choose.
* **Custom CSV** — same idea for a CSV endpoint; map columns instead of fields.
* **Custom STIX 2.x** — point it at a STIX bundle URL; indicator objects are imported.

So if you build your own intel system (your own “AlienVault”), expose a
JSON/CSV/STIX endpoint and connect it here by URL + key — no code changes.
API keys you enter are stored server-side and **never sent back to the browser**.

> **Why might a connector show an error?** Usually no internet, a wrong URL, or
> a missing/expired API key — the connector row shows the exact message and the
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

## 6. Health checks

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8002/health
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8001/ready
curl http://127.0.0.1:8002/ready
```

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
80+ routes across auth, users, overview, SIEM, SOAR, CTI, assets, feeds,
config, and the `/services/*` bridge — including computed SOC metrics, an
alert-correlation engine, a live hunt-query engine, SOAR case lifecycle
(notes/tasks), a transparent asset risk model with per-axis breakdowns, IOC
lookup/bulk-import/scanner history, webhooks, and a full audit trail. The
complete endpoint map and algorithm notes live in
[`dashboard_api/README.md`](dashboard_api/README.md).

---

## 11. Testing

* **Windows:** double-click **`windows-test.bat`** (installs test deps, runs
  all three suites, prints a clear pass/fail summary).
* **Mac/Linux:** `make test` — all three API suites plus the frontend type-check.

Or run any suite directly (works on every OS — run each line separately):

```bash
python -m pytest dashboard_api/tests -q   # from the repo root (48 tests)
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
* **`'make' is not recognized`**: `make` is a Mac/Linux tool — on Windows use
  `windows-start.bat` / `windows-test.bat` instead.
* **`The token '&&' is not a valid statement separator`**: older PowerShell
  doesn’t support `&&`. Run each command on its own line.
* **pip errors mentioning “Microsoft Visual C++” or “building wheel”**: you’re
  likely on a very new Python before our pinned ranges — run
  `python -m pip install --upgrade pip` and retry; all dependencies ship
  prebuilt wheels for Python 3.11–3.13.
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

ThreatOrbit suits individual analysts and small-to-mid security teams who want a deployable CTI plus anomaly-detection workflow that integrates with OpenCTI — topped with a lightweight SOC dashboard (SIEM triage, SOAR cases/playbooks, asset risk, audit trail) — without standing up a heavy SIEM. The three services can run independently or together, locally or in containers.

## FAQ

**Is the data real, or is it simulated?**
Wherever real data can be obtained, ThreatOrbit uses real data — and it is wired
end-to-end, not faked in the UI. Threat intelligence is real OSINT (abuse.ch,
NVD, RSS, OTX, custom connectors, TAXII push). Detections, correlation, UEBA,
SOAR playbook execution, vulnerability scanning, dark-web credential matching,
enrichment, attribution and reporting are all real, executable backend code
operating on that data. The dashboard reads it live from the API.

**Then what part is generated?**
One input: the raw **environment event stream** (auth/network/endpoint/cloud
logs from *your own* infrastructure). A SIEM only sees that once it is deployed
and your systems forward logs to it — there is no way to have it be "real"
before then. So in demo mode the engine generates a representative stream for
that one input, and the **real** detection→correlation→response pipeline runs on
it. You can feed genuine logs at any time and they flow through the identical
pipeline:

* **Upload** a log file (SIEM → Sources → Log Collector, or the Log API).
* **Syslog**: point a forwarder at the UDP listener (`DASHBOARD_SYSLOG_PORT`).
* **File watcher**: drop/append files into `DASHBOARD_LOG_WATCH_DIR`.
* **Connectors / TAXII push** for indicators.

**How do I run it on fully real data?**
Set `DASHBOARD_DATA_MODE=live` (starts empty, no generated stream), enable
connectors for intel, and forward your logs via one of the paths above. See
[§4a](#4a-real-data-vs-demo-mode).

**Is anything hardcoded in the UI?**
No section should display invented numbers — the dashboard pulls from the API.
If you spot a value that does not trace back to the API, it is a bug; please
open an issue.
