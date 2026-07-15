# ThreatOrbit Helm chart

Deploys the full platform on Kubernetes - `dashboard-api` (:8002), `threat-api`
(:8000), `log-api` (:8000) and the `frontend` (nginx :80) - mirroring
[`docker-compose.yml`](../../docker-compose.yml).

## Quick start

```bash
# 1. Build & push the four images (or use your registry mirror):
#    docker build -t <registry>/threatorbit/threat-api    ./threat_api
#    docker build -t <registry>/threatorbit/log-api       ./log_api
#    docker build -t <registry>/threatorbit/dashboard-api ./dashboard_api
#    docker build -t <registry>/threatorbit/frontend \
#      --build-arg NEXT_PUBLIC_API_URL=https://api.threatorbit.example ./frontend

# 2. Install (set the registry + the required secrets):
helm install threatorbit ./deploy/helm/threatorbit \
  --set image.registry=<registry> \
  --set secrets.appApiKey=$(openssl rand -hex 24) \
  --set secrets.jwtSecret=$(openssl rand -hex 32) \
  --set secrets.adminPassword='ChangeMe!Strong1'
```

## Required secrets

| value | why |
|-------|-----|
| `secrets.appApiKey`     | `threat-api`/`log-api` refuse to start without it |
| `secrets.jwtSecret`     | dashboard token signing (REQUIRED when running >1 dashboard replica) |
| `secrets.adminPassword` | bootstrap admin login (changed on first login) |

Manage them yourself instead by setting `secrets.existingSecret` to a Secret with
keys: `appApiKey, adminApiKey, jwtSecret, adminEmail, adminPassword, otxApiKey,
virustotalApiKey, openctiApiKey, databaseUrl`.

## High availability

The three API services use SQLite on a `ReadWriteOnce` PVC by default, so they run
**single-replica** (`strategy: Recreate`). For a horizontally-scalable dashboard,
point it at Postgres:

```bash
helm upgrade threatorbit ./deploy/helm/threatorbit \
  --set postgres.enabled=true \
  --set postgres.url='postgresql://user:pass@pg:5432/threatorbit' \
  --set dashboardApi.replicas=3 \
  --set secrets.jwtSecret=$(openssl rand -hex 32)
```

The `frontend` is stateless and scales freely (default 2 replicas).

## Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  host: app.threatorbit.example       # web UI
  apiHost: api.threatorbit.example    # dashboard API (its routes live at the root)
  tls: { enabled: true, secretName: threatorbit-tls }
```

The frontend calls the API at the URL **baked into its image** at build time
(`NEXT_PUBLIC_API_URL`), so set that build-arg to `https://<apiHost>`.

## Probes and monitoring

The chart wires `livenessProbe` to `/health` (always 200 while the process is
up) and `readinessProbe` to `/ready`, which performs a real database check and
returns **503** when the DB is unreachable - so Kubernetes pulls a broken pod
out of rotation instead of routing traffic to it. For alerting on the
platform's own health, scrape `GET /metrics` and load the ready-made rules in
[`../prometheus/`](../prometheus/) (a `PrometheusRule` wrapper for the
prometheus-operator is documented there).

## Validate before installing

```bash
helm lint ./deploy/helm/threatorbit
helm template threatorbit ./deploy/helm/threatorbit | kubectl apply --dry-run=client -f -
```
