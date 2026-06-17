"""The load benchmark runs end-to-end and reports throughput. Run in a subprocess
so it uses its own isolated temp DB (never the test DB)."""
import subprocess
import sys


def test_bench_quick_runs():
    r = subprocess.run([sys.executable, "-m", "dashboard_api.bench", "--quick"],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    assert "events/sec" in r.stdout
    assert "ingest+detect" in r.stdout and "drain x4" in r.stdout
