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
| Auth      | `POST /auth/login`, `GET /auth/me`, `POST /auth/change-password` |
| Users     | `GET/POST /users`, `PATCH/DELETE /users/{id}` |
| Overview  | `/overview/kpis`, `/threat-vectors`, `/hourly-volume`, `/mitre-heatmap`, `/recent-alerts`, `/recent-incidents`, `/top-actors`, `/live-feed` |
| SIEM      | `/siem/alerts` (sortable/filterable), `/siem/alerts/{id}` (GET/PATCH), `/siem/kpis`, `/siem/correlations`, `/siem/mitre-distribution`, `/siem/rules`, `PATCH /siem/rules/{id}`, `/siem/sources`, `/siem/hunts` |
| SOAR      | `/soar/cases`, `/soar/cases/{id}` (GET/PATCH), `/soar/playbooks`, `/soar/playbooks/{id}` , `POST /soar/playbooks/{id}/run`, `/soar/integrations`, `/soar/metrics` |
| CTI       | `/cti/actors`, `/cti/actors/{id}`, `/cti/iocs` (sortable/filterable), `POST /cti/iocs/import`, `/cti/lookup`, `/cti/ioc-types`, `/cti/summary`, `/cti/hunts`, `/cti/graph` |
| Assets    | `/assets`, `/assets/{id}` (incl. per-axis `riskBreakdown`), `/assets/summary`, `/assets/vulns`, `/assets/risk-distribution`, `POST /assets/recompute-risk` |
| Feeds     | `/feeds`, `/feeds/summary`, `PATCH /feeds/{id}` |
| Config    | `/config/settings` (GET/PUT), `/config/api-keys` (GET/POST/DELETE), `/config/audit-log` |
| Meta      | `/health`, `/ready` |

List endpoints accept whitelisted `sort`/`order` parameters plus rich filters
(e.g. `/siem/alerts?sort=severity&tactic=Exfiltration`,
`/cti/iocs?min_confidence=80&actor=APT29`); unknown sort columns return `400`.

## Algorithms

- **Risk scoring** (`scoring.py`) — a transparent, CVSS-inspired model. Each
  asset's 0–100 score blends four bounded axes (vulnerability burden, exposure,
  patch hygiene, active alert pressure) with weights summing to 1.0, scaled by
  business criticality. `GET /assets/{id}` returns the per-axis breakdown;
  `POST /assets/recompute-risk` recomputes the fleet from live alert pressure,
  so triaging alerts visibly lowers asset risk. The org-level score in
  `/overview/kpis` is the criticality-weighted mean.
- **SOC metrics** — MTTD/MTTA/MTTR in `/siem/kpis` are computed from per-alert
  latency telemetry (detect/ack/respond columns), not hardcoded. The SOAR
  automation rate is the real share of playbook-driven closed cases.
- **Correlation engine** — `/siem/correlations` clusters unresolved alerts by
  shared pivot (src_ip / hostname / username), ranked by cluster size.
- **Audit trail** — every mutation (alerts, rules, cases, playbook runs, users,
  settings, keys, feeds, imports, recomputes) writes an `audit_log` row with
  actor/action/target, readable via `/config/audit-log`.

## Tests

```bash
python -m pytest dashboard_api/tests -q   # 29 tests
```

## Re-seed

The database seeds once. To rebuild demo data:

```bash
python -m dashboard_api.seed   # force-rebuilds every table
```

## Configuration (env)

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `DASHBOARD_DB_PATH` | `dashboard_api/dashboard.db` | SQLite file |
| `DASHBOARD_JWT_SECRET` | dev default | HS256 signing key (**set in prod**) |
| `DASHBOARD_JWT_TTL_MINUTES` | `720` | Token lifetime |
| `DASHBOARD_ADMIN_EMAIL` / `_PASSWORD` | admin@… / ChangeMe123! | Bootstrap admin |
| `DASHBOARD_CORS_ORIGINS` | localhost:3000,… | Allowed browser origins |
| `DASHBOARD_AUTO_SEED` | `true` | Seed on first boot |
| `DASHBOARD_SEED` | `1337` | Deterministic data seed |
