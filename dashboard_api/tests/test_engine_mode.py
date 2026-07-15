"""DASHBOARD_ENGINE - the real-data switch. With "off", boot pauses the
synthetic telemetry engine (every start, operator env wins); the UI can still
resume it deliberately. With the default "on", boot leaves the UI-owned
setting alone.
"""
from dashboard_api import config as cfg
from dashboard_api import main as app_main
from dashboard_api.db import get_conn


def _setting():
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key='engine_enabled'").fetchone()
    return None if row is None else row["value"]


def _set(value):
    with get_conn() as conn:
        if value is None:
            conn.execute("DELETE FROM settings WHERE key='engine_enabled'")
        else:
            conn.execute("INSERT OR REPLACE INTO settings (key,value) "
                         "VALUES ('engine_enabled',?)", (value,))
        conn.commit()


def test_engine_off_pauses_on_every_boot(client, auth, monkeypatch):
    monkeypatch.setattr(cfg, "ENGINE_MODE", "off")
    prev = _setting()
    try:
        # Even if the UI had resumed it, the next boot re-pauses (env wins).
        _set("true")
        assert app_main._apply_engine_mode() is True
        assert _setting() == "false"
        # The status endpoint reflects it.
        st = client.get("/config/engine", headers=auth).json()
        assert st["enabled"] is False and st["running"] is False
        # …and the UI toggle can still deliberately resume until next restart.
        r = client.post("/config/engine", json={"enabled": True}, headers=auth)
        assert r.status_code == 200
        assert client.get("/config/engine", headers=auth).json()["enabled"] is True
    finally:
        _set(prev)


def test_engine_on_leaves_ui_setting_alone(monkeypatch):
    monkeypatch.setattr(cfg, "ENGINE_MODE", "on")
    prev = _setting()
    try:
        _set("true")
        assert app_main._apply_engine_mode() is False
        assert _setting() == "true"       # untouched: the UI owns it
        _set("false")
        assert app_main._apply_engine_mode() is False
        assert _setting() == "false"      # a UI pause also survives boot
    finally:
        _set(prev)
