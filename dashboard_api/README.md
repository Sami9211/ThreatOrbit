# Dashboard API (`dashboard_api`, FastAPI, :8002)

The unified backend that powers the ThreatOrbit operator **dashboard**. Where
`threat_api` and `log_api` are specialized ingestion/analysis engines, this
service owns the data the dashboard UI reads and writes: users, SIEM alerts,
SOAR cases/playbooks/integrations, CTI actors/IOCs, the asset surface, threat
feeds, and configuration.

- **Storage:** WAL-mode SQLite (single file), seeded with realistic,
  internally-consistent demo data on first boot.
- **Auth:** JWT (HS256) bearer tokens + PBKDF2-hashed passwords. Role-based
  access (`admin`, `manager`, `analyst`, `viewer`).

## Run locally

```bash
cd dashboard_api
pip install -r requirements.txt
# from the repo root so the package imports resolve:
cd .. && uvicorn dashboard_api.main:app --reload --port 8002
```

Seeded admin login: `admin@threatorbit.space` / `ChangeMe123!` (override with
`DASHBOARD_ADMIN_EMAIL` / `DASHBOARD_ADMIN_PASSWORD`).

```bash
# Log in, grab a token, hit a protected route
TOKEN=$(curl -s -X POST localhost:8002/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@threatorbit.space","password":"ChangeMe123!"}' | jq -r .token)
curl localhost:8002/overview/kpis -H "Authorization: Bearer $TOKEN"
```

## Endpoint map

| Area      | Routes |
| --------- | ------ |
| Auth      | `POST /auth/login`, `POST /auth/register` (self-service signup, throttled), `GET /auth/me`, `POST /auth/change-password` |
| Users     | `GET/POST /users`, `PATCH /users/{id}` (incl. `mfa_enabled`), `DELETE /users/{id}` |
| Overview  | `/overview/kpis`, `/threat-vectors`, `/hourly-volume`, `/mitre-heatmap`, `/recent-alerts`, `/recent-incidents`, `/top-actors`, `/live-feed` |
| SIEM      | `/siem/alerts` (GET/POST - sortable/filterable, manual/intel escalation), `/siem/alerts/{id}` (GET/PATCH), `/siem/kpis`, `/siem/correlations`, `/siem/mitre-distribution`, `POST /siem/ingest` (native log collector), `/siem/entities` + `/siem/entities/detail` (UEBA), `/siem/attack-coverage` (ATT&CK navigator), `/siem/rules` (GET/POST), `/siem/rule-schema`, `POST /siem/rules/test` (backtest), `/siem/rules/{id}` (PATCH/DELETE), `/siem/sources` (GET/POST), `/siem/hunts` (GET/POST), `POST /siem/hunts/{id}/run`, `POST /siem/hunt-query` (ad-hoc hunt engine) |
| SOAR      | `/soar/cases` (GET/POST), `/soar/cases/{id}` (GET/PATCH), `POST /soar/cases/{id}/notes`, `PATCH /soar/cases/{id}/tasks/{task_id}`, `/soar/playbooks`, `/soar/playbooks/{id}`, `POST /soar/playbooks/{id}/run`, `/soar/integrations` (GET/POST), `POST /soar/integrations/{id}/test`, `POST /soar/integrations/{id}/actions/run`, `/soar/metrics` |
| CTI       | `/cti/actors`, `/cti/actors/{id}`, `/cti/iocs` (sortable/filterable), `POST /cti/iocs/import`, `/cti/lookup`, `/cti/ioc-types`, `/cti/summary`, `/cti/hunts` (GET/POST), `POST /cti/hunts/{id}/run`, `/cti/graph`, `/cti/scans` (GET/POST - IntelScope history) |
| Assets    | `/assets` (GET/POST), `/assets/{id}` (incl. per-axis `riskBreakdown`), `/assets/summary`, `/assets/vulns`, `/assets/risk-distribution`, `POST /assets/recompute-risk` |
| Feeds     | `/feeds` (GET/POST), `/feeds/summary`, `PATCH /feeds/{id}` |
| Config    | `/config/settings` (GET/PUT), `/config/api-keys` (GET/POST/DELETE), `/config/webhooks` (GET/POST/PATCH/DELETE), `POST /config/webhooks/{id}/test`, `/config/jobs`, `/config/audit-log` |
| Connectors| `/connectors` (GET/POST), `/connectors/kinds`, `/connectors/{id}` (PATCH/DELETE), `POST /connectors/{id}/run` - real threat-intel ingestion (threatorbit / nvd / otx / json / csv / stix) into the IOC store |
| Dark Web  | `/darkweb/findings` (GET, filterable), `/darkweb/summary`, `PATCH /darkweb/findings/{id}` (triage status) |
| Engine    | `GET /config/engine` (live engine status), `POST /config/engine` (pause/resume, or `generate` N bursts of live data) |
| Platform  | `/notifications` (GET + read), `/search` (global), `/report-schedules` (CRUD + run), `/saved-views` (CRUD), `/config/audit-export` (CSV), `POST /config/retention/enforce` |
| Reports   | `/reports/kinds`, `GET /reports/{kind}?period=daily\|weekly\|monthly\|custom&from=&to=` - structured reports (executive / siem / soar / cti / assets / darkweb) with summary, breakdowns, findings, recommendations |
| Services  | `/services/status`, `/services/threat/source-health`, `/services/threat/iocs`, `POST /services/threat/fetch`, `/services/threat/jobs/{id}`, `/services/threat/opencti-status`, `POST /services/threat/sync-iocs`, `POST /services/logs/analyse` (multipart), `/services/logs/results/{id}`, `/services/logs/trends` |
| Triage    | `/siem/fp-triage` (bulk false-positive scoring queue), `POST /siem/rules/import-sigma` + community-pack bulk import |
| Interchange | `/taxii/*` (TAXII 2.1 server), STIX/MISP import-export, `/stream` (SSE live updates, ticket-authenticated) |
| Tenancy/Enterprise | `/orgs/*` (workspaces + quotas), `/roles/*` (custom roles), `/billing/*`, `/compliance/*`, `/privacy/*`, SSO (`/sso`, `/saml`, `/scim`) |
| Meta      | `/health` (liveness, always 200), `/ready` (readiness - real DB check, **503 when the DB is unreachable**), `/self-health` (authed: DB/schema/queue/leader/process verdict, powers Settings → System Health), `/about` (authed: product/API/schema versions + effective posture, powers Settings → About), `/metrics` (Prometheus), `/config/leader` (HA lease) |

The full, versioned path inventory (220+ routes) lives in
[`docs/api/v1-paths.json`](../docs/api/v1-paths.json); CI fails if a
documented path disappears without an API version bump.

List endpoints accept whitelisted `sort`/`order` parameters plus rich filters
(e.g. `/siem/alerts?sort=severity&tactic=Exfiltration`,
`/cti/iocs?min_confidence=80&actor=APT29`); unknown sort columns return `400`.

### Service bridge (`/services/*`)

The Threat API (`:8000`) and Log API (`:8001`) authenticate with `X-API-Key`
headers that must not reach the browser. The dashboard proxies them
server-side: operators stay on JWT, keys live in `SERVICES_API_KEY` /
`SERVICES_ADMIN_KEY`. Reads degrade gracefully (`{"available": false}`) when a
service is down; actions return `503`. `POST /services/threat/sync-iocs` pulls
the ingestion engine's indicators into the dashboard IOC store with type
normalisation (md5/sha* → hash), confidence-derived severity, and dedup.

### Hunt engine (`hunting.py`)

`POST /siem/hunt-query` and the saved-hunt `run` endpoints execute analyst
queries against the live stores: MITRE technique ids, IPv4s, severities, and
quoted keywords are extracted from the query text and matched against alerts
(SIEM) or IOCs (CTI). Every result row is a real stored record; saved-hunt
runs persist `last_run`, `hit_count`, `status`, `progress`.

## Algorithms

- **Risk scoring** (`scoring.py`) - a transparent, CVSS-inspired model. Each
  asset's 0-100 score blends four bounded axes (vulnerability burden, exposure,
  patch hygiene, active alert pressure) with weights summing to 1.0, scaled by
  business criticality. `GET /assets/{id}` returns the per-axis breakdown;
  `POST /assets/recompute-risk` recomputes the fleet from live alert pressure,
  so triaging alerts visibly lowers asset risk. The org-level score in
  `/overview/kpis` is the criticality-weighted mean.
- **SOC metrics** - MTTD/MTTA/MTTR in `/siem/kpis` are computed from per-alert
  latency telemetry (detect/ack/respond columns), not hardcoded. The SOAR
  automation rate is the real share of playbook-driven closed cases.
- **Correlation engine** - `/siem/correlations` clusters unresolved alerts by
  shared pivot (src_ip / hostname / username), ranked by cluster size.
- **Audit trail** - every mutation (alerts, rules, cases, playbook runs, users,
  settings, keys, feeds, imports, recomputes) writes an `audit_log` row with
  actor/action/target, readable via `/config/audit-log`.

## Tests

```bash
python -m pytest dashboard_api/tests -q   # 570+ tests, no services or .env needed
```

The suite also runs against a live Postgres in CI (`DASHBOARD_DB_BACKEND=postgres`
+ `DATABASE_URL`) - both backends must stay green.

### Live processing engine

In live mode (`DASHBOARD_DATA_MODE=live`) `engine.py` runs on a background tick:
it generates fresh environment telemetry and runs it through real
detect → correlate → escalate stages, producing SIEM alerts, CTI indicators,
auto-escalated SOAR cases, and dark-web findings continuously. It's the
self-contained live data source (no external dependency); pause/seed it via
`POST /config/engine`. Real log uploads and connectors write into the same
stores, so the source is fully swappable. For a **real-data-only** install set
`DASHBOARD_ENGINE=off`: the synthetic engine is disabled completely and the
only events you ever see are your forwarded logs and connector intel. Ingested
events carry their `source` name; unknown sources **auto-register** on first
ingest so SIEM → Sources reflects the real flow with a live Events (24h) count.

### Webhooks

Registered webhooks (`/config/webhooks`) receive a JSON envelope
`{event, ts, data}` on: `alert.created`, `case.created`, `incident.resolved`,
`ioc.confirmed`, and `playbook.failed`. Delivery is fire-and-forget with a 5s
timeout; failures mark the hook `failing` (it keeps receiving events until
paused/deleted). `POST /config/webhooks/{id}/test` sends a synchronous test
event and reports reachability.

## Re-seed

The database seeds once. To rebuild demo data:

```bash
python -m dashboard_api.seed   # force-rebuilds every table
```

## Configuration (env)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `DASHBOARD_DB_PATH` | `dashboard_api/dashboard.db` | SQLite file |
| `DASHBOARD_JWT_SECRET` | dev default | HS256 signing key (**set in prod** - startup logs a warning on the default) |
| `DASHBOARD_JWT_TTL_MINUTES` | `720` | Token lifetime |
| `DASHBOARD_ADMIN_EMAIL` / `_PASSWORD` | admin@… / ChangeMe123! | Bootstrap admin |
| `DASHBOARD_CORS_ORIGINS` | localhost:3000,… | Allowed browser origins |
| `DASHBOARD_ALLOW_REGISTRATION` | `true` | Enable `POST /auth/register` self-service signup |
| `DASHBOARD_DATA_MODE` | `demo` | `demo` seeds showcase data; `live` starts empty + ingests real intel via connectors |
| `DASHBOARD_CONNECTOR_TICK_SECONDS` | `60` | How often the live-mode scheduler runs due connectors |
| `DASHBOARD_AUTH_MAX_FAILURES` | `10` | Failed logins per client+email before 429 |
| `DASHBOARD_AUTH_FAILURE_WINDOW_SEC` | `300` | Sliding window for the throttle |
| `THREAT_API_URL` | `http://127.0.0.1:8000` | Ingestion engine for `/services/threat/*` |
| `LOG_API_URL` | `http://127.0.0.1:8001` | Log engine for `/services/logs/*` |
| `SERVICES_API_KEY` | `$APP_API_KEY` | X-API-Key presented upstream |
| `SERVICES_ADMIN_KEY` | `$ADMIN_API_KEY` | Admin key for `/fetch` upstream |
| `DASHBOARD_AUTO_SEED` | `true` | Seed on first boot |
| `DASHBOARD_SEED` | `1337` | Deterministic data seed |
| `DASHBOARD_ENGINE` | `on` | `off` = real-data-only: synthetic telemetry fully disabled |
| `DASHBOARD_DB_BACKEND` / `DATABASE_URL` | sqlite | `postgres` + a DSN switches the storage backend |
| `DASHBOARD_MULTI_TENANT` | off | Per-workspace (org) isolation for MSSP installs |
| `DASHBOARD_REQUIRE_SECRETS` | `false` | Refuse to boot on default secrets (production posture) |
| `DASHBOARD_METRICS_TOKEN` | unset | Require `Authorization: Bearer` on `GET /metrics` |
| `DASHBOARD_LOG_FORMAT` | human | `json` = one-line structured logs for shipping |
| `DASHBOARD_LOG_REDACT` | off | PII/secret redaction of raw log lines before persisting |
| `DASHBOARD_HEALTH_LAG_SECONDS` / `_QUEUE_DEPTH` | `300` / `10000` | Self-health degradation thresholds |
| `DASHBOARD_HEALTH_MONITOR_SECONDS` | `60` | Self-health alert cadence (live mode; `0` disables) |
| `DASHBOARD_ALLOW_PRIVATE_URLS` | `false` | Permit private targets for user-added webhooks/connectors (the bundled companion at `THREAT_API_URL` is always allowed) |
