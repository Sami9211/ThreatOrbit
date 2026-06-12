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

## Key management

| Env var | Purpose | Rotation effect |
|---|---|---|
| `DASHBOARD_JWT_SECRET` | session tokens | all sessions invalidated (users re-log-in) |
| `DASHBOARD_ENCRYPTION_KEY` | secrets at rest | stored credentials become unreadable — re-enter them after rotating. Pin this BEFORE first use; if unset it falls back to the JWT secret, coupling the two rotations |
| `DASHBOARD_EVIDENCE_SECRET` | evidence-bundle signatures | previously exported bundles fail verification against the new key — keep the old key to re-verify old bundles |
