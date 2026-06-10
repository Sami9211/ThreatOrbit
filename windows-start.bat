@echo off
setlocal
title ThreatOrbit launcher
cd /d "%~dp0"

REM ============================================================
REM  ThreatOrbit - one-click local start for Windows.
REM  Needs only: Python 3.11+ (python.org) and Node.js LTS
REM  (nodejs.org). Double-click this file and wait.
REM
REM  Serves a PRODUCTION build of the website (instant page
REM  loads) and starts the three real-data APIs.
REM ============================================================

REM ---- find Python (python on PATH, or the py launcher) ----
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

REM ---- find Node.js ----
where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found on this computer.
    echo.
    echo   1. Download the LTS version from  https://nodejs.org/
    echo   2. Install it with the default options
    echo   3. Run this file again
    echo.
    pause
    exit /b 1
)

echo [1/6] Installing Python packages (fast after the first run)...
%PY% -m pip install -q -r dashboard_api\requirements.txt -r threat_api\requirements.txt -r log_api\requirements.txt
if errorlevel 1 (
    echo [ERROR] Installing Python packages failed - see the messages above.
    pause
    exit /b 1
)

echo [2/6] Installing web app packages (first run only - takes a few minutes)...
if not exist frontend\node_modules (
    pushd frontend
    call npm install
    if errorlevel 1 (
        popd
        echo [ERROR] npm install failed - see the messages above.
        pause
        exit /b 1
    )
    popd
)

echo [3/6] Building the website for fast loading (about a minute)...
pushd frontend
call npm run build
if errorlevel 1 (
    popd
    echo [ERROR] Building the website failed - see the messages above.
    pause
    exit /b 1
)
popd

echo [4/6] Starting the three data APIs - each gets its own window...
REM DASHBOARD_DATA_MODE=live -> start with NO demo data and auto-ingest real
REM threat intelligence from the OSINT engine in the background.
start "ThreatOrbit - Dashboard API (port 8002)" cmd /k "set SERVICES_API_KEY=local-dev-key&& set DASHBOARD_DATA_MODE=live&& %PY% -m uvicorn dashboard_api.main:app --port 8002"
start "ThreatOrbit - Threat API (port 8000)" cmd /k "set APP_API_KEY=local-dev-key&& set ENABLE_SCHEDULER=true&& %PY% -m threat_api.main"
start "ThreatOrbit - Log API (port 8001)" cmd /k "set APP_API_KEY=local-dev-key&& %PY% -m uvicorn log_api.main:app --port 8001"

echo [5/6] Starting the website (port 3000)...
start "ThreatOrbit - Website (port 3000)" cmd /k "%PY% scripts\serve_frontend.py 3000"

echo [6/6] Opening your browser in 8 seconds...
timeout /t 8 >nul
start http://localhost:3000

echo.
echo  ============================================================
echo   ThreatOrbit is running in 4 separate windows.
echo.
echo     Website     http://localhost:3000
echo     Dashboard   click "Sign in" on the site, or go to
echo                 http://localhost:3000/dashboard
echo     Sign in     admin@threatorbit.space   ChangeMe123!
echo                 (or create your own account at /signup)
echo.
echo   REAL DATA: the dashboard starts empty and fills itself
echo   from live OSINT feeds within a couple of minutes (needs
echo   internet). Watch Feeds -> Sources, or press "Sync now".
echo.
echo   To STOP ThreatOrbit: close the 4 windows it opened.
echo  ============================================================
echo.
pause
