#!/usr/bin/env sh
# Packaged scheduled-backup job (HA/DR): take the consistent tar.gz backup on
# an interval and prune archives past the retention window. This is the
# entrypoint of the opt-in docker-compose `backup` service
# (`docker compose --profile backup up -d`); the Helm chart ships the same job
# as a Kubernetes CronJob (backup.enabled), which runs it one-shot
# (BACKUP_ONESHOT=1). Any cron/systemd-timer can call it the same way.
#
# Env:
#   BACKUP_OUT_DIR           where archives land            (default /backups)
#   BACKUP_DBS               name=path,name=path…           (default: all three)
#   BACKUP_INTERVAL_SECONDS  loop period                    (default 86400 = daily)
#   BACKUP_RETENTION_DAYS    prune archives older than this (default 14; 0 = keep all)
#   BACKUP_ONESHOT=1         run once and exit (CronJob / external scheduler mode)
#
# Postgres deployments: this job covers the SQLite stores; back the dashboard
# database up with pg_dump instead (docs/OPERATIONS.md, docs/POSTGRES_HA.md).
set -eu

OUT_DIR="${BACKUP_OUT_DIR:-/backups}"
DBS="${BACKUP_DBS:-dashboard=/vol/dashboard/dashboard.db,threat=/vol/threat/threat_api.db,log=/vol/log/log_api.db}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

run_once() {
    set --
    old_ifs="$IFS"; IFS=','
    for pair in $DBS; do
        path="${pair#*=}"
        if [ -f "$path" ]; then
            set -- "$@" --db "$pair"
        else
            echo "backup: skipping $pair (no database file yet)" >&2
        fi
    done
    IFS="$old_ifs"
    if [ "$#" -eq 0 ]; then
        echo "backup: nothing to back up yet" >&2
        return 0
    fi
    python -m dashboard_api.backup backup --out "$OUT_DIR" "$@"
    if [ "$RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
        find "$OUT_DIR" -name 'threatorbit-backup-*.tar.gz' \
            -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
    fi
}

if [ "${BACKUP_ONESHOT:-0}" = "1" ]; then
    run_once
    exit 0
fi

while :; do
    # A failed pass must not kill the scheduler: log it and try again next tick.
    run_once || echo "backup: pass failed; retrying in ${INTERVAL}s" >&2
    sleep "$INTERVAL"
done
