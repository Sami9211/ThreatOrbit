#!/usr/bin/env bash
# Consistent, live-safe backup of the three ThreatOrbit SQLite databases into a
# timestamped tar.gz. Thin wrapper around `python -m dashboard_api.backup`; the
# DB paths default to the Docker /data volumes and can be overridden by env.
#
#   ./scripts/backup.sh                 # -> ./backups/threatorbit-backup-<ts>.tar.gz
#   BACKUP_OUT_DIR=/srv/backups ./scripts/backup.sh
#
# Schedule from cron/systemd-timer for your RPO; ship the archives off-box. See
# docs/BACKUP_RESTORE.md.
set -euo pipefail

OUT_DIR="${BACKUP_OUT_DIR:-./backups}"
DASH="${DASHBOARD_DB_PATH:-/data/dashboard.db}"
THREAT="${THREAT_DB_PATH:-/data/threat_api.db}"
LOG="${LOG_DB_PATH:-/data/log_api.db}"

cd "$(dirname "$0")/.."
exec python -m dashboard_api.backup backup --out "$OUT_DIR" \
  --db "dashboard=$DASH" --db "threat=$THREAT" --db "log=$LOG"
