#!/usr/bin/env bash
# ============================================================
#  ThreatOrbit - run every test suite on Linux (and macOS).
#  Needs only: Python 3.11+.       ./linux-test.sh
# ============================================================
set -u
cd "$(dirname "$0")"

PYBIN=""
for c in python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 \
       && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
        PYBIN="$c"; break
    fi
done
if [ -z "$PYBIN" ]; then
    echo "[ERROR] Python 3.11+ was not found (Ubuntu: sudo apt install python3 python3-venv)." >&2
    exit 1
fi

if [ ! -x .venv/bin/python ]; then
    echo "Creating Python virtualenv (.venv, first run only)..."
    "$PYBIN" -m venv .venv || { echo "[ERROR] python3-venv missing? (sudo apt install python3-venv)" >&2; exit 1; }
fi
PY=".venv/bin/python"

echo "Installing test dependencies (fast after the first run)..."
# The -dev files carry httpx2, which the FastAPI test suites REQUIRE (their
# pytest.ini turns the Starlette TestClient deprecation into an error, so a
# missing httpx2 fails the run loudly). threat_api is Flask - no dev file.
"$PY" -m pip install -q -r dashboard_api/requirements.txt \
                        -r threat_api/requirements.txt \
                        -r log_api/requirements.txt \
                        -r dashboard_api/requirements-dev.txt \
                        -r log_api/requirements-dev.txt \
    || { echo "[ERROR] Installing Python packages failed - see above." >&2; exit 1; }

FAILED=0

echo; echo "===== Dashboard API tests ====="
"$PY" -m pytest dashboard_api/tests -q || FAILED=1

echo; echo "===== Threat API tests ====="
(cd threat_api && "../$PY" -m pytest -q) || FAILED=1

echo; echo "===== Log API tests ====="
(cd log_api && "../$PY" -m pytest -q) || FAILED=1

echo
if [ "$FAILED" -eq 0 ]; then
    echo " ============================"
    echo "  ALL TESTS PASSED"
    echo " ============================"
else
    echo " =========================================="
    echo "  SOME TESTS FAILED - scroll up for details"
    echo " =========================================="
fi
exit "$FAILED"
