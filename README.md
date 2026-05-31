# ThreatOrbit

**Threat Intelligence Ingestion + Log Anomaly Detection + STIX / OpenCTI Integration**

ThreatOrbit is a cybersecurity platform made of two backend services and a marketing/landing frontend:

* **Threat API** (`threat_api`, Flask, port 8000)
  Ingests external threat feeds (OTX, abuse.ch, RSS, dark-web OSINT, social OSINT) in parallel, normalizes and trust-scores indicators, enriches with VirusTotal, exports STIX 2.1, and reads from / pushes to OpenCTI.
* **Log API** (`log_api`, FastAPI, port 8001)
  Parses logs (Apache, Syslog, Windows Event, Generic), detects anomalies via four engines (Pattern, Statistical, ML, Temporal), generates HTML reports, and exports STIX 2.1 from findings.
* **Frontend** (`frontend`, Next.js 14 + TypeScript)
  Marketing site that presents the platform. Deployable on Vercel.

Both APIs use WAL-mode SQLite, an async job model so long pipelines never block requests, CORS for browser clients, and a two-tier API key scheme (standard user key + admin key).

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

   Browser ------------------> Frontend (Next.js, Vercel) ---> calls the two APIs
```

---

## 2. Project structure

```text
ThreatOrbit-V2/
├── README.md
├── .gitignore
├── .env.example                 # copy to .env, fill in keys
├── docker-compose.yml           # runs both APIs with healthchecks
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
└── frontend/                    # Next.js 14 marketing site (Vercel)
    ├── app/                     # layout.tsx, page.tsx, globals.css
    ├── components/
    │   ├── effects/             # ParticleNetwork, CursorGlow, SmoothScroll
    │   ├── layout/              # Navbar, Footer
    │   ├── sections/            # Hero, Features, ExpandingShowcase, etc.
    │   └── ui/                  # Logo, Reveal, MagneticButton, CountUp, ScrollProgress
    ├── lib/
    ├── tailwind.config.ts
    ├── next.config.mjs
    └── package.json
```

---

## 3. Requirements

**Minimum**

* OS: Linux, macOS, or Windows (WSL2 recommended on Windows)
* CPU: 2 cores, RAM: 4 GB, Disk: 5 GB free
* Docker + Docker Compose, Git

**Recommended**

* CPU: 4+ cores, RAM: 8 to 16 GB, Disk: 20+ GB
* Stable internet (for feed ingestion and external enrichment APIs)

For the OpenCTI workflow, deploy OpenCTI first using the official docs:
https://docs.opencti.io/latest/deployment/

---

## 4. Quick start (Docker)

```bash
# 1. Configure secrets
cp .env.example .env
# edit .env and set APP_API_KEY (required) and ADMIN_API_KEY (recommended)

# 2. Start both APIs
docker compose up --build
```

Services:

* Threat API: http://127.0.0.1:8000
* Log API:    http://127.0.0.1:8001

Stop with `docker compose down`.

### Run locally without Docker

Two terminals:

```bash
# Terminal 1: Threat API
cd threat_api
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export APP_API_KEY=your-secret-key                   # Windows: set APP_API_KEY=...
python main.py
```

```bash
# Terminal 2: Log API
cd log_api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export APP_API_KEY=your-secret-key
uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

### Run the frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

To deploy on Vercel, set the project **Root Directory** to `frontend` and deploy. Vercel auto-detects Next.js.

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
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8001/ready
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

---

## 11. Testing

```bash
cd threat_api && pytest -q
cd ../log_api && pytest -q
```

Tests set their own API keys via `conftest.py`, so no `.env` is required to run them.

---

## 12. Troubleshooting

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

ThreatOrbit suits individual analysts and small-to-mid security teams who want a deployable CTI plus anomaly-detection workflow that integrates with OpenCTI, without standing up a heavy SIEM. The two services can run independently or together, locally or in containers.
