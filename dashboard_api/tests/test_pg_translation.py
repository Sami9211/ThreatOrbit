"""Regression fence for the SQLite→Postgres query translator (`db_backend`).

The `backend-postgres` CI job caught a real break: sqlglot 30.x renders a SQLite
`ON CONFLICT(col)` target as `col NULLS FIRST`, which Postgres rejects
("NULLS FIRST/LAST is not allowed in ON CONFLICT clause"), breaking every upsert.
These assert the translator emits a clean conflict target for the exact upsert
shapes the app uses — so a future transpiler bump that reintroduces the ordering
wrapper fails here (fast, unit-level) instead of only in the live-Postgres job.
"""
import pytest

from dashboard_api.db_backend import to_postgres

# The real explicit ON CONFLICT statements in the app (audit_sink, vuln_scanner,
# orgs) plus representative INSERT OR REPLACE forms (translated to ON CONFLICT).
_UPSERTS = [
    "INSERT INTO audit_sink_cursor (id,last_id,updated) VALUES (1,?,?) "
    "ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id, updated=excluded.updated",
    "INSERT INTO cve_catalogue (cve,product,cvss) VALUES (?,?,?) "
    "ON CONFLICT(cve,product) DO UPDATE SET cvss=excluded.cvss",
    "INSERT INTO user_org_roles (user_id,org_id,role) VALUES (?,?,?) "
    "ON CONFLICT(user_id,org_id) DO UPDATE SET role=excluded.role",
    "INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
    "INSERT OR REPLACE INTO leader_lease (id,holder,expires_at) VALUES (?,?,?)",
]


@pytest.mark.parametrize("sql", _UPSERTS)
def test_on_conflict_never_emits_nulls_ordering(sql):
    """Postgres forbids NULLS FIRST/LAST inside ON CONFLICT — the translator must
    never produce it (the sqlglot 30.x regression this guards against)."""
    out = to_postgres(sql).upper()
    assert "ON CONFLICT" in out, out
    # No NULLS FIRST/LAST anywhere in the conflict target (or the statement).
    assert "NULLS FIRST" not in out and "NULLS LAST" not in out, out


def test_conflict_columns_are_preserved():
    """The stripped conflict target keeps the real key columns (not dropped)."""
    out = to_postgres(
        "INSERT INTO cve_catalogue (cve,product,cvss) VALUES (?,?,?) "
        "ON CONFLICT(cve,product) DO UPDATE SET cvss=excluded.cvss").lower()
    # both conflict keys survive in the target
    assert "on conflict" in out
    conflict = out.split("on conflict", 1)[1]
    assert "cve" in conflict and "product" in conflict


def test_placeholders_converted_to_postgres():
    """`?` params are converted to a Postgres paramstyle after translation
    (`%s` on the sqlglot path, `$n` on the regex fallback when sqlglot is absent)."""
    import re
    out = to_postgres("INSERT INTO settings (key,value) VALUES (?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    assert "?" not in out
    assert "%s" in out or re.search(r"\$\d", out), out
