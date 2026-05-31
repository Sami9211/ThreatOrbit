import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List

from threat_api.config import DB_PATH
from threat_api.models import EnrichedIOC

_DB_PATH = Path(DB_PATH)
_write_lock = threading.Lock()


def _apply_pragmas(conn: sqlite3.Connection):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-32000")   # 32 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA mmap_size=268435456") # 256 MB mmap


def init_db():
    with sqlite3.connect(_DB_PATH) as conn:
        _apply_pragmas(conn)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            threat_type TEXT,
            confidence INTEGER,
            enrichment_status TEXT,
            vt_malicious_count INTEGER,
            created_at TEXT,
            data_json TEXT
        )
        """)
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_unique
        ON iocs (ioc_type, value, source)
        """)
        # Non-destructive migration for older schemas
        try:
            cur.execute("ALTER TABLE iocs ADD COLUMN data_json TEXT")
        except Exception:
            pass
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_iocs_created ON iocs (created_at)
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT,
            created_at TEXT,
            updated_at TEXT,
            details TEXT
        )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    _apply_pragmas(conn)
    try:
        yield conn
    finally:
        conn.close()


def upsert_iocs(iocs: Iterable[EnrichedIOC]):
    rows = [
        (
            i.ioc_type,
            i.value,
            i.source,
            i.threat_type,
            i.confidence,
            i.enrichment_status,
            i.vt_malicious_count,
            i.last_seen.isoformat() if i.last_seen else None,
            i.model_dump_json(),
        )
        for i in iocs
    ]
    with _write_lock:
        with get_conn() as conn:
            conn.executemany(
                """
                INSERT INTO iocs (
                    ioc_type, value, source, threat_type, confidence,
                    enrichment_status, vt_malicious_count, created_at, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_type, value, source) DO UPDATE SET
                    threat_type=excluded.threat_type,
                    confidence=excluded.confidence,
                    enrichment_status=excluded.enrichment_status,
                    vt_malicious_count=excluded.vt_malicious_count,
                    created_at=excluded.created_at,
                    data_json=excluded.data_json
                """,
                rows,
            )
            conn.commit()


def load_iocs_from_db(limit: int = 10_000) -> List[EnrichedIOC]:
    """Restore in-memory store from DB on startup."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT data_json FROM iocs WHERE data_json IS NOT NULL "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    result = []
    for (data_json,) in rows:
        try:
            result.append(EnrichedIOC.model_validate_json(data_json))
        except Exception:
            pass
    return result
