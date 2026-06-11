"""Database backend seam — SQLite today, Postgres staged.

ThreatOrbit runs on single-file WAL SQLite, which is perfect up to a busy
single node. Scaling past that means Postgres. The *full* switch is a breaking
migration: every query in the codebase uses SQLite's `?` placeholder and a few
SQLite idioms (`INSERT OR REPLACE`, `datetime('now')`, `AUTOINCREMENT`,
`PRAGMA`, `executescript`). Rewriting all of that at once is risky, so it's
staged here rather than rushed onto `main`:

  * backend selection is live and non-breaking — `DASHBOARD_DB_BACKEND`
    (default `sqlite`) + an optional `DATABASE_URL`;
  * the **dialect translation** below (`to_postgres`) is pure and unit-tested:
    it rewrites a SQLite statement to Postgres form (placeholders + the common
    idioms). When the Postgres path is switched on, `get_conn()` wraps
    `execute()` to translate on the fly, so call sites stay unchanged;
  * the Postgres connection path requires `psycopg` and is only taken when the
    backend is explicitly set — SQLite installs are 100% unaffected.

Flipping it on (set `DASHBOARD_DB_BACKEND=postgres`, install psycopg, point at
a DSN) is then mechanical and reviewable on its own, with this translation
layer already proven.
"""
import os
import re

BACKEND = os.environ.get("DASHBOARD_DB_BACKEND", "sqlite").lower()
DATABASE_URL = os.environ.get("DATABASE_URL", "")


def is_postgres() -> bool:
    return BACKEND in ("postgres", "postgresql", "pg")


# ── SQLite → Postgres statement translation (pure, tested) ────────────────────────

_INSERT_OR_REPLACE = re.compile(r"\bINSERT\s+OR\s+REPLACE\s+INTO\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)",
                                re.IGNORECASE)
_AUTOINC = re.compile(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.IGNORECASE)
_DATETIME_NOW = re.compile(r"datetime\(\s*'now'\s*\)", re.IGNORECASE)
_PRAGMA = re.compile(r"^\s*PRAGMA\b.*$", re.IGNORECASE | re.MULTILINE)


def _qmark_to_dollar(sql: str) -> str:
    """Replace `?` placeholders with `$1,$2,…` — but not `?` inside string
    literals. Postgres' psycopg accepts `%s`; we use `%s` for parameter style
    compatibility with psycopg's default."""
    out, i, in_str = [], 0, False
    for ch in sql:
        if ch == "'":
            in_str = not in_str
            out.append(ch)
        elif ch == "?" and not in_str:
            out.append("%s")
        else:
            out.append(ch)
    return "".join(out)


def to_postgres(sql: str) -> str:
    """Translate a SQLite statement to a Postgres-compatible one.

    Handles the idioms this codebase actually uses: `?`→`%s` placeholders,
    `INSERT OR REPLACE`→`INSERT … ON CONFLICT … DO UPDATE`, `AUTOINCREMENT`→
    `SERIAL`/`GENERATED`, `datetime('now')`→`now()`, and strips `PRAGMA`.
    Conservative: anything it doesn't recognise passes through unchanged.
    """
    s = _PRAGMA.sub("", sql)
    s = _AUTOINC.sub("BIGSERIAL PRIMARY KEY", s)
    s = _DATETIME_NOW.sub("now()", s)

    def _upsert(m):
        table, cols = m.group(1), m.group(2)
        first_col = cols.split(",")[0].strip()
        updates = ", ".join(f"{c.strip()}=EXCLUDED.{c.strip()}"
                            for c in cols.split(",") if c.strip() != first_col)
        # ON CONFLICT on the PK/first column — matches how the app uses
        # INSERT OR REPLACE (settings(key), single-PK upserts).
        tail = f" ON CONFLICT ({first_col}) DO UPDATE SET {updates}" if updates else \
               f" ON CONFLICT ({first_col}) DO NOTHING"
        return f"INSERT INTO {table} ({cols}) /*UPSERT {first_col}*/{tail}__VALUES__"

    if _INSERT_OR_REPLACE.search(s):
        # mark the ON CONFLICT clause to move after the VALUES(...) list
        s2 = _INSERT_OR_REPLACE.sub(_upsert, s)
        m = re.search(r"/\*UPSERT (\w+)\*/(.*?)__VALUES__(.*)", s2, re.DOTALL)
        if m:
            conflict, values = m.group(2), m.group(3)
            s2 = s2[:m.start()] + values.strip() + conflict
        s = s2
    return _qmark_to_dollar(s)


def connect_postgres():
    """Open a Postgres connection (staged path). Requires psycopg + a DSN."""
    if not DATABASE_URL:
        raise RuntimeError("DASHBOARD_DB_BACKEND=postgres requires DATABASE_URL")
    try:
        import psycopg  # noqa: F401
    except ImportError as e:  # pragma: no cover - depends on optional driver
        raise RuntimeError(
            "Postgres backend selected but 'psycopg' is not installed "
            "(pip install psycopg[binary]).") from e
    import psycopg
    conn = psycopg.connect(DATABASE_URL, autocommit=False)
    return conn


def backend_info() -> dict:
    return {
        "backend": "postgres" if is_postgres() else "sqlite",
        "configured": is_postgres() and bool(DATABASE_URL),
        "driverReady": _driver_ready(),
        "note": ("Postgres is staged: dialect translation is in place and "
                 "tested; flip DASHBOARD_DB_BACKEND=postgres + install psycopg "
                 "+ set DATABASE_URL to enable."),
    }


def _driver_ready() -> bool:
    try:
        import psycopg  # noqa: F401
        return True
    except ImportError:
        return False
