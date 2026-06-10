@echo off
setlocal
title ThreatOrbit tests
cd /d "%~dp0"

REM ============================================================
REM  ThreatOrbit - run every test suite on Windows.
REM  Needs only: Python 3.11+ (python.org). Double-click and wait.
REM ============================================================

set "PY=python"
%PY% --version >nul 2>nul
if errorlevel 1 set "PY=py -3"
%PY% --version >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on this computer.
    echo.
    echo   1. Download it from  https://www.python.org/downloads/
    echo   2. During setup, tick "Add python.exe to PATH"
    echo   3. Run this file again
    echo.
    pause
    exit /b 1
)

echo Installing test dependencies (fast after the first run)...
%PY% -m pip install -q -r dashboard_api\requirements.txt -r threat_api\requirements.txt -r log_api\requirements.txt
if errorlevel 1 (
    echo [ERROR] Installing Python packages failed - see the messages above.
    pause
    exit /b 1
)

set FAILED=0

echo.
echo ===== Dashboard API tests =====
%PY% -m pytest dashboard_api\tests -q
if errorlevel 1 set FAILED=1

echo.
echo ===== Threat API tests =====
pushd threat_api
%PY% -m pytest -q
if errorlevel 1 set FAILED=1
popd

echo.
echo ===== Log API tests =====
pushd log_api
%PY% -m pytest -q
if errorlevel 1 set FAILED=1
popd

echo.
if %FAILED%==0 (
    echo  ============================
    echo   ALL TESTS PASSED
    echo  ============================
) else (
    echo  ==========================================
    echo   SOME TESTS FAILED - scroll up for details
    echo  ==========================================
)
pause
exit /b %FAILED%
