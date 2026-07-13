# Operations: backup, restore, upgrade

This is the runbook for operating a ThreatOrbit deployment. It is honest
about what is automated and what is a manual drill.

## Backup

### SQLite (default backend)

Never copy the `.db` file of a running service — under WAL you would race
the write-ahead log and capture a torn snapshot. Use one of the
transactionally consistent paths instead:

**From the UI/API** (admin, `config.manage`):

```
GET /config/backup        → downloads threatorbit-backup-<UTC ts>.db
```

The snapshot is taken with SQLite's online backup API and integrity-checked
before it is handed out; every download is audited (`config.backup`).

**From the host** (cron-able):

```bash
python -m dashboard_api.ops backup /backups/$(date -u +%F).db
# verify any snapshot later:
python -m dashboard_api.ops verify /backups/2026-06-12.db
```

A sane small-deployment schedule: hourly `ops backup` to local disk +
daily sync of the backup directory to object storage. Backups contain
encrypted credentials (`enc:v1:` envelopes) — they are only useful together
with the deployment's `DASHBOARD_ENCRYPTION_KEY`, so **back the key up
separately and securely** (a backup without the key cannot decrypt stored
connector/integration credentials; everything else restores fine).

### Packaged scheduled-backup job

You don't have to wire cron yourself — the repo ships the schedule in both
deployment shapes, wrapping the same consistent tar.gz backup
(`python -m dashboard_api.backup`, all three databases):

* **docker-compose:** an opt-in `backup` service —
  `docker compose --profile backup up -d`. Daily by default, archives land on
  the `backup_data` volume, and archives older than the retention window are
  pruned. Tune with `BACKUP_INTERVAL_SECONDS` / `BACKUP_RETENTION_DAYS`
  (`scripts/backup_loop.sh` is the entrypoint; any external cron/systemd timer
  can call it with `BACKUP_ONESHOT=1`).
* **Helm:** set `backup.enabled=true` — a `CronJob` (default `0 2 * * *`)
  snapshots onto a dedicated PVC with the same retention pruning
  (`backup.schedule` / `backup.retentionDays` / `backup.size`). It
  co-schedules with the service pods because the data volumes are
  ReadWriteOnce. With `postgres.enabled` it covers the two ingestion
  services; dump the dashboard database with `pg_dump` (below).

Either way, ship the archive directory/PVC off-box for real DR — a backup on
the same disk as the database it protects is not a disaster-recovery story.

### Postgres (opt-in backend)

Use the native tooling — `GET /config/backup` deliberately refuses on
Postgres:

```bash
pg_dump --format=custom "$DATABASE_URL" > threatorbit-$(date -u +%F).dump
pg_restore --clean --if-exists -d "$DATABASE_URL" threatorbit-2026-06-12.dump
```

## Restore (drill this before you need it)

Restore is an **offline** operation by design — there is no hot-restore API.

1. Stop the dashboard service (`docker compose stop dashboard_api` or your
   unit manager).
2. Verify the snapshot: `python -m dashboard_api.ops verify <backup.db>`.
3. Replace the live DB file (the path in `DASHBOARD_DB_PATH`) with the
   backup. Remove any stale `-wal`/`-shm` siblings of the old file.
4. Ensure `DASHBOARD_ENCRYPTION_KEY` (and `DASHBOARD_JWT_SECRET`) match the
   values from the time of the backup, or stored credentials will honestly
   read back as not-configured.
5. Start the service. Boot re-applies schema migrations idempotently and
   re-encrypts any legacy plaintext secrets; check the log for
   `integrity` problems and log in.

## Upgrade

Schema migrations are **additive-only** (new tables / new defaulted
columns), applied automatically at boot. That gives a simple contract:

- **Upgrade:** take a backup → deploy the new code (`git pull`,
  `pip install -r dashboard_api/requirements.txt`, rebuild the frontend or
  pull the new image) → restart. The boot migration brings the schema up.
- **Rollback:** older code tolerates newer schemas (extra columns are
  ignored), so rolling the code back is usually enough. If a release says
  otherwise in its notes, restore the pre-upgrade backup instead.
- Run the test suite against a copy when in doubt:
  `python -m pytest dashboard_api/tests -q`.

### Migration-gating (rollback safety)

The DB records the schema version it was migrated to (`SCHEMA_VERSION` in
`dashboard_api/db.py`, surfaced at `GET /ready` as `schema.{code,db}`). On boot
the code:

- **adopts** a fresh or pre-versioning database (no gate);
- **bumps** the recorded version after a normal (additive) upgrade;
- **refuses to start** if the database is *newer* than the binary — i.e. a build
  was rolled back onto a schema a later build wrote. This stops an old binary
  from silently corrupting newer data.

Check before a deploy/rollback:

```bash
python -m dashboard_api.ops schema-version    # prints code vs db; rc=1 if db is newer
```

If you have **verified** the newer schema is compatible with the older code,
override the gate with `DASHBOARD_ALLOW_SCHEMA_DOWNGRADE=1`; otherwise deploy a
build that supports the DB's version, or restore the pre-upgrade backup. Bump
`SCHEMA_VERSION` by 1 whenever you add a migration.

## Observability

- **Metrics:** `GET /metrics` (Prometheus text format) — request
  rate/latency by route template + status, domain counters (engine ticks &
  failures, engine/ingested events, alerts, unhandled errors), and core-table
  row-count gauges. Open by default for private-network scrapers; set
  `DASHBOARD_METRICS_TOKEN` to require `Authorization: Bearer <token>`.
- **Structured logs:** `DASHBOARD_LOG_FORMAT=json` switches all API logs to
  one-line JSON (ts/level/logger/message/exception) for Loki/CloudWatch/
  Datadog shipping. Unset = human-readable.
- **Error tracking:** set `SENTRY_DSN` and `pip install sentry-sdk` to
  forward unhandled exceptions to Sentry. With the DSN set but the SDK
  missing, the platform logs that tracking is off — it never pretends.
- **Self-health surface:** `GET /self-health` (authenticated; same access as
  `/config/leader`) aggregates the platform's *own* vitals — database
  reachability + measured round-trip latency, code-vs-DB schema version,
  detection-queue depth/lag backpressure, background-work leader lease, and
  process uptime/counters — into one verdict (`ok` / `degraded` / `down`). The
  overall verdict is the worst *gating* check (database `down` ⇒ down; schema
  drift or a queue past its thresholds ⇒ degraded). Rendered live in the
  dashboard at **Settings → General → System Health**. Queue thresholds tune
  with `DASHBOARD_HEALTH_LAG_SECONDS` (default 300) and
  `DASHBOARD_HEALTH_QUEUE_DEPTH` (default 10000).
- **Self-health alerting:** in live mode a leader-gated monitor samples the
  verdict every `DASHBOARD_HEALTH_MONITOR_SECONDS` (default 60; `0` disables)
  and raises a `platform.health` notification — bell + SSE + Slack routing —
  **only on a verdict transition** (degrade / recover), so a steadily-degraded
  platform never spams. When the database is itself the fault the notification
  can't be written, so the `CRITICAL` log line (plus `/metrics` and Sentry) is
  the out-of-band channel — wire an alert on `threatorbit_domain_total{counter="errors"}`
  or on scrape failure for that case.

### Health probes (liveness vs. readiness)

Two endpoints, two jobs — wire them to the matching Kubernetes/LB probe:

| Endpoint | Probe | Checks | On failure |
|---|---|---|---|
| `GET /health` | **liveness** | process is up (static `ok`) | always 200 — a DB outage a restart can't fix must **not** trigger a pod kill |
| `GET /ready` | **readiness** | `SELECT 1` + schema versions | **HTTP 503** when the DB is unreachable, so the orchestrator pulls the pod out of rotation instead of routing traffic it can't serve |

The Helm chart (`deploy/helm/…`) already points `livenessProbe` at `/health`
and `readinessProbe` at `/ready`.

## Key management

| Env var | Purpose | Rotation effect |
|---|---|---|
| `DASHBOARD_JWT_SECRET` | session tokens | all sessions invalidated (users re-log-in) |
| `DASHBOARD_ENCRYPTION_KEY` | secrets at rest | stored credentials become unreadable — re-enter them after rotating. Pin this BEFORE first use; if unset it falls back to the JWT secret, coupling the two rotations |
| `DASHBOARD_EVIDENCE_SECRET` | evidence-bundle signatures | previously exported bundles fail verification against the new key — keep the old key to re-verify old bundles |
