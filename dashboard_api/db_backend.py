"""Database backend seam - SQLite today, Postgres staged.

ThreatOrbit runs on single-file WAL SQLite, which is perfect up to a busy
single node. Scaling past that means Postgres. The *full* switch is a breaking
migration: every query in the codebase uses SQLite's `?` placeholder and a few
SQLite idioms (`INSERT OR REPLACE`, `datetime('now')`, `AUTOINCREMENT`,
`PRAGMA`, `executescript`). Rewriting all of that at once is risky, so it's
staged here rather than rushed onto `main`:

  * backend selection is live and non-breaking - `DASHBOARD_DB_BACKEND`
    (default `sqlite`) + an optional `DATABASE_URL`;
  * the **dialect translation** below (`to_postgres`) is pure and unit-tested:
    it rewrites a SQLite statement to Postgres form (placeholders + the common
    idioms). When the Postgres path is switched on, `get_conn()` wraps
    `execute()` to translate on the fly, so call sites stay unchanged;
  * the Postgres connection path requires `psycopg` and is only taken when the
    backend is explicitly set - SQLite installs are 100% unaffected.

Flipping it on (set `DASHBOARD_DB_BACKEND=postgres`, install psycopg, point at
a DSN) is then mechanical and reviewable on its own, with this translation
layer already proven.
"""
import os
import re
from decimal import Decimal

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
    """Replace `?` placeholders with `$1,$2,…` - but not `?` inside string
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
    # SQLite's INTEGER is 64-bit; Postgres INTEGER is 32-bit and overflows on the
    # larger values this app stores (uptime, byte counts, epoch-ish ints), so map
    # plain INTEGER -> BIGINT. Runs after AUTOINCREMENT handling (which already
    # produced BIGSERIAL), so PKs are unaffected.
    s = re.sub(r"\bINTEGER\b", "BIGINT", s)
    # SQLite's scalar MIN(a, b)/MAX(a, b) (always written here with a numeric
    # first argument) is LEAST()/GREATEST() in Postgres; aggregate MIN(col)/
    # MAX(col) never starts with a digit, so this targeted form is safe.
    s = re.sub(r"\bMIN\(\s*(\d)", r"LEAST(\1", s, flags=re.IGNORECASE)
    s = re.sub(r"\bMAX\(\s*(\d)", r"GREATEST(\1", s, flags=re.IGNORECASE)
    s = _DATETIME_NOW.sub("now()", s)

    def _upsert(m):
        table, cols = m.group(1), m.group(2)
        first_col = cols.split(",")[0].strip()
        updates = ", ".join(f"{c.strip()}=EXCLUDED.{c.strip()}"
                            for c in cols.split(",") if c.strip() != first_col)
        # ON CONFLICT on the PK/first column - matches how the app uses
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


class PgRow(dict):
    """Row supporting BOTH dict access (`row["col"]`) and positional access
    (`row[0]`), matching how the codebase reads sqlite3.Row. Key lookup is also
    case-insensitive, because Postgres folds unquoted column/alias names to
    lower case while call sites may read them in mixed case."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        if super().__contains__(key):
            return super().__getitem__(key)
        return super().__getitem__(key.lower())

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default


def split_statements(script: str) -> list[str]:
    """Split a SQL script into statements on `;`, ignoring semicolons inside
    string literals and `-- line comments` (a `;` in a schema comment must not
    start a new statement, and a bare comment fragment is not valid SQL to PG)."""
    out, buf, in_str = [], [], False
    i, n = 0, len(script)
    while i < n:
        ch = script[i]
        if in_str:
            buf.append(ch)
            if ch == "'":
                in_str = False
            i += 1
            continue
        if ch == "'":
            in_str = True
            buf.append(ch)
            i += 1
            continue
        if ch == "-" and i + 1 < n and script[i + 1] == "-":
            while i < n and script[i] != "\n":   # skip the line comment
                i += 1
            continue
        if ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


class _PgCursor:  # pragma: no cover - exercised only against a live Postgres
    def __init__(self, cur):
        self._cur = cur

    @property
    def rowcount(self):
        return self._cur.rowcount

    def _wrap(self, row):
        if row is None:
            return None
        cols = [d[0] for d in (self._cur.description or [])]
        # Postgres aggregates (AVG/SUM) and NUMERIC columns come back as Decimal,
        # which the codebase and stdlib json don't expect - normalise to float so
        # rows behave exactly like SQLite's (which yields int/float/str).
        return PgRow((c, float(v) if isinstance(v, Decimal) else v) for c, v in zip(cols, row))

    def fetchone(self):
        return self._wrap(self._cur.fetchone())

    def fetchall(self):
        return [self._wrap(r) for r in self._cur.fetchall()]


class PgConnection:  # pragma: no cover - exercised only against a live Postgres
    """Adapts a psycopg connection to the sqlite3-ish interface the codebase
    uses (`execute`/`executemany`/`executescript`/`commit`/`close`), translating
    each statement through `to_postgres` so call sites stay unchanged."""

    def __init__(self, raw):
        self._raw = raw

    def execute(self, sql, params=()):
        translated = to_postgres(sql)
        if not translated.strip():
            return _PgCursor(self._raw.cursor())  # PRAGMA etc. → no-op
        cur = self._raw.cursor()
        cur.execute(translated, tuple(params))
        return _PgCursor(cur)

    def executemany(self, sql, seq):
        cur = self._raw.cursor()
        cur.executemany(to_postgres(sql), [tuple(p) for p in seq])
        return _PgCursor(cur)

    def executescript(self, script):
        for stmt in split_statements(script):
            translated = to_postgres(stmt)
            if translated.strip():
                self._raw.cursor().execute(translated)
        return None

    def commit(self):
        self._raw.commit()

    def close(self):
        self._raw.close()


def table_columns_sql() -> str:
    """Backend-aware column introspection for migrations: Postgres can't use
    `PRAGMA table_info`, so the migration runner asks information_schema."""
    return ("SELECT column_name AS name FROM information_schema.columns "
            "WHERE table_name = %s")


def connect_postgres():
    """Open a Postgres connection (opt-in path). Requires psycopg + a DSN.
    Returns the adapter, so every existing call site works unchanged."""
    if not DATABASE_URL:
        raise RuntimeError("DASHBOARD_DB_BACKEND=postgres requires DATABASE_URL")
    try:
        import psycopg  # noqa: F401
    except ImportError as e:  # pragma: no cover - depends on optional driver
        raise RuntimeError(
            "Postgres backend selected but 'psycopg' is not installed "
            "(pip install psycopg[binary]).") from e
    import psycopg
    return PgConnection(psycopg.connect(DATABASE_URL, autocommit=False))


def backend_info() -> dict:
    return {
        "backend": "postgres" if is_postgres() else "sqlite",
        "configured": is_postgres() and bool(DATABASE_URL),
        "driverReady": _driver_ready(),
        "note": ("Postgres adapter implemented and validated against a live "
                 "Postgres 16 (full dashboard suite green; CI runs it on every "
                 "change). Enable with DASHBOARD_DB_BACKEND=postgres + "
                 "DATABASE_URL + psycopg. SQLite remains the default."),
    }


def _driver_ready() -> bool:
    try:
        import psycopg  # noqa: F401
        return True
    except ImportError:
        return False
