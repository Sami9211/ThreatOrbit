#!/usr/bin/env bash
# Restore the three ThreatOrbit SQLite databases from a backup archive made by
# scripts/backup.sh. Each snapshot is integrity-checked before it overwrites a
# live file. STOP the services first (so nothing is mid-write), then:
#
#   ./scripts/restore.sh ./backups/threatorbit-backup-<ts>.tar.gz --force
#
# DB destinations default to the Docker /data volumes; override with env.
# See docs/BACKUP_RESTORE.md.
set -euo pipefail

ARCHIVE="${1:?usage: restore.sh <archive.tar.gz> [--force]}"
FORCE="${2:-}"
DASH="${DASHBOARD_DB_PATH:-/data/dashboard.db}"
THREAT="${THREAT_DB_PATH:-/data/threat_api.db}"
LOG="${LOG_DB_PATH:-/data/log_api.db}"

cd "$(dirname "$0")/.."
exec python -m dashboard_api.backup restore --archive "$ARCHIVE" \
  --db "dashboard=$DASH" --db "threat=$THREAT" --db "log=$LOG" ${FORCE:+--force}
