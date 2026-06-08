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
| SIEM      | `/siem/alerts`, `/siem/alerts/{id}` (GET/PATCH), `/siem/kpis`, `/siem/mitre-distribution`, `/siem/rules`, `/siem/sources`, `/siem/hunts` |
| SOAR      | `/soar/cases`, `/soar/cases/{id}` (GET/PATCH), `/soar/playbooks`, `/soar/integrations`, `/soar/metrics` |
| CTI       | `/cti/actors`, `/cti/iocs`, `/cti/ioc-types`, `/cti/hunts`, `/cti/graph` |
| Assets    | `/assets`, `/assets/{id}`, `/assets/summary`, `/assets/vulns` |
| Feeds     | `/feeds`, `/feeds/summary`, `PATCH /feeds/{id}` |
| Config    | `/config/settings` (GET/PUT), `/config/api-keys` (GET/POST/DELETE) |
| Meta      | `/health`, `/ready` |

## Tests

```bash
python -m pytest dashboard_api/tests -q
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
