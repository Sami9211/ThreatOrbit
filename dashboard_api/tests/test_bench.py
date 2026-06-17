"""The load benchmark runs end-to-end and reports throughput. Run in a subprocess
with the test DB path stripped, so the benchmark uses its OWN temp DB (its
setdefault would otherwise inherit the conftest DASHBOARD_DB_PATH and pollute the
shared test database)."""
import os
import subprocess
import sys


def test_bench_quick_runs():
    env = {k: v for k, v in os.environ.items() if k != "DASHBOARD_DB_PATH"}
    r = subprocess.run([sys.executable, "-m", "dashboard_api.bench", "--quick"],
                       capture_output=True, text=True, timeout=180, env=env)
    assert r.returncode == 0, r.stderr
    assert "events/sec" in r.stdout
    assert "ingest+detect" in r.stdout and "drain x4" in r.stdout
