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
        # Additive columns: the full result + the rendered report are persisted
        # per job, so results survive a restart and are visible to every worker
        # (no in-memory result store, no single shared report file).
        cols = {r[1] for r in cur.execute("PRAGMA table_info(analysis_jobs)").fetchall()}
        if "result_json" not in cols:
            cur.execute("ALTER TABLE analysis_jobs ADD COLUMN result_json TEXT")
        if "report_html" not in cols:
            cur.execute("ALTER TABLE analysis_jobs ADD COLUMN report_html TEXT")
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _apply_pragmas(conn)
    try:
        yield conn
    finally:
        conn.close()
