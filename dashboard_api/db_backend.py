"""Database backend seam - SQLite today, Postgres staged.

ThreatOrbit runs on single-file WAL SQLite, which is perfect up to a busy
single node. Scaling past that means Postgres. The *full* switch is a breaking
migration: every query in the codebase uses SQLite's `?` placeholder and a few
SQLite idioms (`INSERT OR REPLACE`, `datetime('now')`, `AUTOINCREMENT`,
`PRAGMA`, `executescript`). Rather than rewrite all of that, the dialect gap is
bridged here:

  * backend selection is live and non-breaking - `DASHBOARD_DB_BACKEND`
    (default `sqlite`) + an optional `DATABASE_URL`;
  * the **dialect translation** (`to_postgres`) parses each statement with
    **sqlglot** (a real SQL parser/transpiler) and applies AST transforms for the
    app-specific idioms sqlglot doesn't map on its own (SQLite `INTEGER`→`BIGINT`,
    `INSERT OR REPLACE`→`ON CONFLICT`, `datetime('now')`→`now()`), then renders
    Postgres. This replaces the previous regex rewriter, which is kept as a
    best-effort fallback for any statement sqlglot can't parse (or when sqlglot
    isn't installed). When the Postgres path is on, `get_conn()` wraps `execute()`
    to translate on the fly, so call sites stay unchanged;
  * connections come from a **pool** (`psycopg_pool`) so the per-call
    open/close cost is gone under load;
  * the Postgres path requires `psycopg` (+ `psycopg_pool`, `sqlglot` for the
    full experience) and is only taken when the backend is explicitly set -
    SQLite installs are 100% unaffected. See `requirements-postgres.txt`.
"""
import os
import re
from decimal import Decimal

BACKEND = os.environ.get("DASHBOARD_DB_BACKEND", "sqlite").lower()
DATABASE_URL = os.environ.get("DATABASE_URL", "")


def is_postgres() -> bool:
    return BACKEND in ("postgres", "postgresql", "pg")


# -- SQLite → Postgres statement translation -----------------------------------

_PRAGMA_ONLY = re.compile(r"^\s*PRAGMA\b", re.IGNORECASE)


def _qmark_to_dollar(sql: str) -> str:
    """Replace `?` placeholders with psycopg's `%s` - but never a `?` inside a
    string literal."""
    out, in_str = [], False
    for ch in sql:
        if ch == "'":
            in_str = not in_str
            out.append(ch)
        elif ch == "?" and not in_str:
            out.append("%s")
        else:
            out.append(ch)
    return "".join(out)


def _pg_transform(tree, exp):
    """Apply the app-specific SQLite→Postgres transforms sqlglot doesn't do on its
    own, on the parsed AST (no regex on SQL text)."""
    # SQLite INTEGER is 64-bit; Postgres INTEGER is 32-bit and overflows on the
    # larger values this app stores (uptime, byte counts, epochs). Widen every
    # INT data type to BIGINT (an `INTEGER PRIMARY KEY AUTOINCREMENT` becomes a
    # `BIGINT … GENERATED … AS IDENTITY`, which is what we want).
    for dt in tree.find_all(exp.DataType):
        if dt.this == exp.DataType.Type.INT:
            dt.set("this", exp.DataType.Type.BIGINT)
    # datetime('now') → now()
    for fn in list(tree.find_all(exp.Anonymous)):
        if fn.name.upper() == "DATETIME":
            a = fn.expressions
            if len(a) == 1 and isinstance(a[0], exp.Literal) and a[0].this == "now":
                fn.replace(exp.func("now"))
    # sqlglot (30.x) parses SQLite `ON CONFLICT(col)` targets as `Ordered`
    # expressions and the Postgres generator renders them as `col NULLS FIRST`,
    # which Postgres REJECTS inside an ON CONFLICT clause ("NULLS FIRST/LAST is
    # not allowed in ON CONFLICT clause"). Strip the ordering wrapper from every
    # conflict key so the target renders as a bare column list.
    for oc in tree.find_all(exp.OnConflict):
        keys = oc.args.get("conflict_keys")
        if keys:
            oc.set("conflict_keys",
                   [k.this if isinstance(k, exp.Ordered) else k for k in keys])
    # INSERT OR REPLACE → INSERT … ON CONFLICT (first/PK column) DO UPDATE/NOTHING,
    # matching how the app uses it (single-PK upserts: settings(key), leases, …).
    import sqlglot
    if isinstance(tree, exp.Insert) and str(tree.args.get("alternative") or "").upper() == "REPLACE":
        tree.set("alternative", None)
        schema = tree.this
        cols = [c.name for c in schema.expressions] if isinstance(schema, exp.Schema) else []
        if cols:
            first = cols[0]
            updates = [c for c in cols if c != first]
            if updates:
                setc = ", ".join(f"{c} = EXCLUDED.{c}" for c in updates)
                tmpl = (f"INSERT INTO _x ({', '.join(cols)}) VALUES ({', '.join(['1'] * len(cols))}) "
                        f"ON CONFLICT ({first}) DO UPDATE SET {setc}")
            else:
                tmpl = f"INSERT INTO _x ({first}) VALUES (1) ON CONFLICT ({first}) DO NOTHING"
            tree.set("conflict", sqlglot.parse_one(tmpl, read="postgres").args["conflict"])
    return tree


def to_postgres(sql: str) -> str:
    """Translate a SQLite statement to Postgres. Parses with sqlglot and applies
    the AST transforms in `_pg_transform`; falls back to the regex rewriter for
    anything sqlglot can't parse (or when sqlglot isn't installed). PRAGMA has no
    Postgres equivalent and translates to an empty (no-op) statement."""
    if _PRAGMA_ONLY.match(sql):
        return ""
    try:
        import sqlglot
        from sqlglot import exp
    except ImportError:
        return _to_postgres_regex(sql)
    try:
        tree = sqlglot.parse_one(sql, read="sqlite")
        if tree is None:
            return _to_postgres_regex(sql)
        return _pg_transform(tree, exp).sql(dialect="postgres")
    except Exception:
        # Parser couldn't handle this statement - best-effort regex rewrite keeps
        # the path working (and surfaces in the live-Postgres CI run if wrong).
        return _to_postgres_regex(sql)


# -- Regex rewriter (fallback for statements sqlglot can't parse) --------------

_INSERT_OR_REPLACE = re.compile(r"\bINSERT\s+OR\s+REPLACE\s+INTO\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)",
                                re.IGNORECASE)
_AUTOINC = re.compile(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.IGNORECASE)
_DATETIME_NOW = re.compile(r"datetime\(\s*'now'\s*\)", re.IGNORECASE)
_PRAGMA = re.compile(r"^\s*PRAGMA\b.*$", re.IGNORECASE | re.MULTILINE)


def _to_postgres_regex(sql: str) -> str:
    """Best-effort regex SQLite→Postgres rewrite. Retained as the fallback for the
    sqlglot translator; conservative (anything unrecognised passes through)."""
    s = _PRAGMA.sub("", sql)
    s = _AUTOINC.sub("BIGSERIAL PRIMARY KEY", s)
    s = re.sub(r"\bINTEGER\b", "BIGINT", s)
    s = re.sub(r"\bMIN\(\s*(\d)", r"LEAST(\1", s, flags=re.IGNORECASE)
    s = re.sub(r"\bMAX\(\s*(\d)", r"GREATEST(\1", s, flags=re.IGNORECASE)
    s = _DATETIME_NOW.sub("now()", s)

    def _upsert(m):
        table, cols = m.group(1), m.group(2)
        first_col = cols.split(",")[0].strip()
        updates = ", ".join(f"{c.strip()}=EXCLUDED.{c.strip()}"
                            for c in cols.split(",") if c.strip() != first_col)
        tail = f" ON CONFLICT ({first_col}) DO UPDATE SET {updates}" if updates else \
               f" ON CONFLICT ({first_col}) DO NOTHING"
        return f"INSERT INTO {table} ({cols}) /*UPSERT {first_col}*/{tail}__VALUES__"

    if _INSERT_OR_REPLACE.search(s):
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
    each statement through `to_postgres` so call sites stay unchanged. When it
    came from a pool, `close()` returns it to the pool instead of closing it."""

    def __init__(self, raw, pool=None):
        self._raw = raw
        self._pool = pool

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

    def rollback(self):
        self._raw.rollback()

    def close(self):
        if self._pool is not None:
            self._pool.putconn(self._raw)   # return to the pool (reset on return)
        else:
            self._raw.close()


def table_columns_sql() -> str:
    """Backend-aware column introspection for migrations: Postgres can't use
    `PRAGMA table_info`, so the migration runner asks information_schema."""
    return ("SELECT column_name AS name FROM information_schema.columns "
            "WHERE table_name = %s")


# -- Connection pool (psycopg_pool) --------------------------------------------

_pool = None


def _get_pool():  # pragma: no cover - exercised only against a live Postgres
    """Lazily build a process-wide connection pool. Raises ImportError if
    psycopg_pool isn't installed, so the caller can fall back to a direct
    connection."""
    global _pool
    if _pool is None:
        from psycopg_pool import ConnectionPool
        _pool = ConnectionPool(
            DATABASE_URL,
            min_size=int(os.environ.get("DASHBOARD_PG_POOL_MIN", "1")),
            max_size=int(os.environ.get("DASHBOARD_PG_POOL_MAX", "10")),
            kwargs={"autocommit": False},
            open=True,
            name="threatorbit",
        )
    return _pool


def connect_postgres():
    """Open a Postgres connection (opt-in path). Requires psycopg + a DSN;
    pools via psycopg_pool when available. Returns the adapter, so every existing
    call site works unchanged."""
    if not DATABASE_URL:
        raise RuntimeError("DASHBOARD_DB_BACKEND=postgres requires DATABASE_URL")
    try:
        import psycopg  # noqa: F401
    except ImportError as e:  # pragma: no cover - depends on optional driver
        raise RuntimeError(
            "Postgres backend selected but 'psycopg' is not installed "
            "(pip install -r dashboard_api/requirements-postgres.txt).") from e
    try:  # pragma: no cover - exercised only against a live Postgres
        from psycopg_pool import ConnectionPool  # noqa: F401
        pool = _get_pool()
        return PgConnection(pool.getconn(), pool=pool)
    except ImportError:  # pragma: no cover - pool extra not installed
        import psycopg
        return PgConnection(psycopg.connect(DATABASE_URL, autocommit=False))


def backend_info() -> dict:
    return {
        "backend": "postgres" if is_postgres() else "sqlite",
        "configured": is_postgres() and bool(DATABASE_URL),
        "driverReady": _driver_ready(),
        "note": ("Postgres adapter: sqlglot-based dialect translation + a "
                 "psycopg_pool connection pool, validated against a live "
                 "Postgres 16 (full dashboard suite green in CI on every change). "
                 "Enable with DASHBOARD_DB_BACKEND=postgres + DATABASE_URL and "
                 "requirements-postgres.txt. SQLite remains the default."),
    }


def _driver_ready() -> bool:
    try:
        import psycopg  # noqa: F401
        return True
    except ImportError:
        return False
