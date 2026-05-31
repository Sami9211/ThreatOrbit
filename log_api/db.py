import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.getenv("LOG_DB_PATH", "log_api.db"))


def _apply_pragmas(conn: sqlite3.Connection):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-16000")  # 16 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        _apply_pragmas(conn)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS analysis_jobs (
            id TEXT PRIMARY KEY,
            status TEXT,
            created_at TEXT,
            updated_at TEXT,
            summary_json TEXT
        )
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_jobs_created ON analysis_jobs (created_at)
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _apply_pragmas(conn)
    try:
        yield conn
    finally:
        conn.close()
