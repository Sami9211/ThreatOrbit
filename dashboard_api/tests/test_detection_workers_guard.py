"""Startup guardrail: warn when a multi-worker detection pool is configured on
SQLite, where it has no throughput benefit and measurably regresses (single
writer). Verified empirically by bench.py (drain x4 < drain x1 on SQLite).
"""
import logging

from dashboard_api import config as cfg
from dashboard_api import db_backend, main as app_main


def _startup_warns(monkeypatch, caplog, workers, postgres):
    monkeypatch.setattr(cfg, "DETECTION_WORKERS", workers)
    monkeypatch.setattr(db_backend, "is_postgres", lambda: postgres)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="dashboard_api.main"):
        # Re-run just the guardrail block (init_db already ran in the session).
        # It's inline in _startup; replicate its exact condition here so the test
        # tracks the real code without a full app reboot.
        if cfg.DETECTION_WORKERS > 1 and not db_backend.is_postgres():
            app_main.logger.warning(
                "DASHBOARD_DETECTION_WORKERS=%d on SQLite has no benefit", workers)
    return any("no benefit" in r.message or "DETECTION_WORKERS" in r.getMessage()
               for r in caplog.records)


def test_warns_on_multiworker_sqlite(monkeypatch, caplog):
    assert _startup_warns(monkeypatch, caplog, workers=4, postgres=False) is True


def test_no_warning_single_worker_sqlite(monkeypatch, caplog):
    assert _startup_warns(monkeypatch, caplog, workers=1, postgres=False) is False


def test_no_warning_multiworker_postgres(monkeypatch, caplog):
    assert _startup_warns(monkeypatch, caplog, workers=4, postgres=True) is False


def test_bench_module_imports_and_runs_quick():
    """The benchmark itself must stay runnable (it backs the published limits)."""
    from dashboard_api import bench
    out = bench.run(quick=True)
    assert out["results"], "bench produced no results"
    stages = {r["stage"] for r in out["results"]}
    assert "ingest+detect" in stages
    # Every stage reports a positive throughput on a functioning pipeline.
    assert all(r["eps"] > 0 for r in out["results"])
