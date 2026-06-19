"""Migration-gating on upgrade (HA/DR rollback safety).

The DB records the schema version it was migrated to; on boot the code adopts a
fresh/unversioned DB, bumps a normal upgrade, and REFUSES to run against a DB
newer than it understands (a rolled-back binary) unless explicitly overridden.
"""
import pytest

from dashboard_api.db import (SCHEMA_VERSION, SchemaVersionError, _schema_version_gate,
                              get_conn, schema_versions)


def _set_db_version(v):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('schema_version', ?)", (str(v),))
        conn.commit()


def _restore():
    _set_db_version(SCHEMA_VERSION)


def test_fresh_db_adopts_code_version():
    v = schema_versions()
    assert v["code"] == SCHEMA_VERSION and v["db"] == SCHEMA_VERSION


def test_downgrade_is_gated():
    _set_db_version(SCHEMA_VERSION + 1)
    try:
        with get_conn() as conn:
            with pytest.raises(SchemaVersionError):
                _schema_version_gate(conn)
    finally:
        _restore()


def test_downgrade_override_allows(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ALLOW_SCHEMA_DOWNGRADE", "1")
    _set_db_version(SCHEMA_VERSION + 2)
    try:
        with get_conn() as conn:
            _schema_version_gate(conn)            # no raise under override
            conn.commit()
        assert schema_versions()["db"] == SCHEMA_VERSION + 2   # not silently downgraded
    finally:
        _restore()


def test_upgrade_bumps_recorded_version():
    _set_db_version(max(0, SCHEMA_VERSION - 1))
    try:
        with get_conn() as conn:
            _schema_version_gate(conn)
            conn.commit()
        assert schema_versions()["db"] == SCHEMA_VERSION
    finally:
        _restore()


def test_ready_reports_schema(client):
    body = client.get("/ready").json()
    assert body["ready"] is True
    assert body["schema"]["code"] == SCHEMA_VERSION


def test_ops_schema_version_cli(capsys):
    from dashboard_api import ops
    rc = ops._main(["schema-version"])
    assert rc == 0
    assert "code schema version" in capsys.readouterr().out
