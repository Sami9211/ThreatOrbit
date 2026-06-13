"""Operational tooling: consistent backups + restore guidance.

SQLite backups use the online backup API (`Connection.backup`), which takes a
transactionally consistent snapshot even while the service is running under
WAL - never copy the .db file directly (you'd race the WAL). Postgres
deployments should use `pg_dump` instead (see docs/OPERATIONS.md).

CLI:
    python -m dashboard_api.ops backup [dest.db]     # snapshot to a file
    python -m dashboard_api.ops verify <backup.db>   # integrity-check a backup

Restore is deliberately NOT an API or hot operation: stop the service,
replace the DB file with the backup, start the service (migrations re-apply
idempotently). The full drill is documented in docs/OPERATIONS.md.
"""
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from dashboard_api.config import DB_PATH


def default_backup_name() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"threatorbit-backup-{ts}.db"


def backup_sqlite(dest: str | Path) -> Path:
    """Write a consistent snapshot of the live DB to `dest` (online backup API)."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(DB_PATH, timeout=30)
    try:
        out = sqlite3.connect(str(dest))
        try:
            src.backup(out)
            out.commit()
        finally:
            out.close()
    finally:
        src.close()
    return dest


def verify_backup(path: str | Path) -> dict:
    """Open a backup read-only and run PRAGMA integrity_check + count core rows.
    Returns a summary; raises if the file is not a healthy snapshot."""
    conn = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"integrity_check failed: {integrity}")
        counts = {}
        for table in ("users", "alerts", "cases", "iocs", "assets"):
            try:
                counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                counts[table] = None  # table absent (very old snapshot)
        return {"integrity": integrity, "counts": counts}
    finally:
        conn.close()


def _main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "backup":
        dest = argv[1] if len(argv) > 1 else default_backup_name()
        path = backup_sqlite(dest)
        print(f"backup written: {path} ({path.stat().st_size} bytes)")
        print(f"verify: {verify_backup(path)}")
        return 0
    if len(argv) >= 2 and argv[0] == "verify":
        print(verify_backup(argv[1]))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":  # pragma: no cover - thin CLI shell
    raise SystemExit(_main(sys.argv[1:]))
