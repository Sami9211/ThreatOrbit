# Backup & restore (disaster recovery)

ThreatOrbit's state lives in three SQLite databases (WAL mode):

| Service | Default path (Docker volume) | Holds |
|---|---|---|
| `dashboard_api` | `/data/dashboard.db` | users, alerts, cases, IOCs, assets, rules, config, audit |
| `threat_api` | `/data/threat_api.db` | ingested indicators, feeds |
| `log_api` | `/data/log_api.db` | log-analysis findings/reports |

The tooling takes a **live-safe, point-in-time snapshot** of each (SQLite's
online backup API — no need to stop the service), verifies each with
`PRAGMA integrity_check`, and bundles them into one timestamped `tar.gz`.

## Back up

```bash
# Writes ./backups/threatorbit-backup-<UTC-timestamp>.tar.gz
./scripts/backup.sh

# Custom output dir / paths via env:
BACKUP_OUT_DIR=/srv/backups \
DASHBOARD_DB_PATH=/data/dashboard.db THREAT_DB_PATH=/data/threat_api.db LOG_DB_PATH=/data/log_api.db \
  ./scripts/backup.sh
```

Inside the running container the DBs are on the `/data` volume, so either run the
script in the container (`docker compose exec dashboard_api ./scripts/backup.sh`)
or point the env vars at the host bind-mounts.

The snapshot is consistent even while the services are writing, so backups need
no downtime. A failed integrity check aborts the backup (you never keep a
corrupt archive).

## Restore

Restore **overwrites** the live databases, so stop the stack first:

```bash
docker compose down
./scripts/restore.sh ./backups/threatorbit-backup-<ts>.tar.gz --force
docker compose up -d
```

Each snapshot is integrity-checked **before** it replaces a live file, and any
stale `-wal` / `-shm` sidecars of the old database are removed so SQLite opens
the restored file cleanly. Without `--force`, restore refuses to overwrite an
existing file (so you can dry-run against an empty target).

Restore a single database by passing only that `--db` to the underlying tool:

```bash
python -m dashboard_api.backup restore \
  --archive backups/<file>.tar.gz --db dashboard=/data/dashboard.db --force
```

## Scheduling, retention & RPO/RTO

- **RPO** (how much data you can lose) = your backup interval. Run `backup.sh`
  from cron / a systemd timer at that cadence (e.g. hourly) and **ship the
  archives off-box** (object storage / another host) — a backup on the same disk
  is not disaster recovery.
- **RTO** (how long to recover) is a `down` → `restore.sh` → `up`, typically a
  minute or two for these database sizes.
- **Retention**: keep a rolling window (e.g. 24 hourly + 30 daily) and prune
  older archives; each archive is self-contained.
- **Verify restores periodically** — restore into a throwaway path and diff a
  few row counts. An untested backup is a hope, not a plan.

## Encryption

Archives contain operational data; encrypt them at rest in transit/off-box
(e.g. `age`/`gpg` the `tar.gz`, or rely on encrypted object storage). Secrets
already stored in the dashboard DB are Fernet-encrypted at the application layer
(`DASHBOARD_ENCRYPTION_KEY`) — keep that key backed up **separately** from the
archives, or a restore can't decrypt them.

## Postgres deployments

When `dashboard_api` runs on the staged Postgres backend (see
`docs/OPERATIONS.md`), use Postgres-native backups (`pg_dump` / continuous
archiving) for that database instead of this SQLite tool; `threat_api` and
`log_api` remain SQLite and are covered as above.
