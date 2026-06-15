"""Cold-storage archival for retention: write purged rows to compressed NDJSON
before they're deleted, so a compliance team can keep raw logs cheaply.

Enabled only when `DASHBOARD_ARCHIVE_DIR` points at a writable directory (read
live from config so tests/ops can flip it). One gzipped, append-friendly
NDJSON file per table per purge day: `<table>-<YYYYMMDD>.ndjson.gz`. A failure to
archive must NOT cause data to be deleted unarchived, so the caller treats a
None/raise as "do not purge this batch".
"""
import gzip
import json
import os
from datetime import datetime, timezone


def enabled() -> bool:
    from dashboard_api import config
    return bool(getattr(config, "ARCHIVE_DIR", ""))


def _dir() -> str:
    from dashboard_api import config
    return config.ARCHIVE_DIR


def archive_rows(table: str, rows: list) -> str | None:
    """Append `rows` (sqlite Row or dict) to today's gzip NDJSON for `table`.
    Returns the file path, or None when archival is disabled or there's nothing
    to write. Raises on I/O failure so the caller can abort the delete."""
    if not enabled() or not rows:
        return None
    os.makedirs(_dir(), exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    path = os.path.join(_dir(), f"{table}-{day}.ndjson.gz")
    with gzip.open(path, "at", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(dict(r), default=str, separators=(",", ":")) + "\n")
    return path
