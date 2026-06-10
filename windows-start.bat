@echo off
setlocal
title ThreatOrbit launcher
cd /d "%~dp0"

REM ============================================================
REM  ThreatOrbit - one-click local start for Windows.
REM  Needs only: Python 3.11+ (python.org) and Node.js LTS
REM  (nodejs.org). Double-click this file and wait.
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

echo [1/5] Installing Python packages (fast after the first run)...
%PY% -m pip install -q -r dashboard_api\requirements.txt -r threat_api\requirements.txt -r log_api\requirements.txt
if errorlevel 1 (
    echo [ERROR] Installing Python packages failed - see the messages above.
    pause
    exit /b 1
)

echo [2/5] Installing web app packages (first run only - takes a few minutes)...
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

echo [3/5] Starting the three APIs - each gets its own window...
start "ThreatOrbit - Dashboard API (port 8002)" cmd /k "set SERVICES_API_KEY=local-dev-key&& %PY% -m uvicorn dashboard_api.main:app --port 8002"
start "ThreatOrbit - Threat API (port 8000)" cmd /k "set APP_API_KEY=local-dev-key&& set ENABLE_SCHEDULER=false&& %PY% -m threat_api.main"
start "ThreatOrbit - Log API (port 8001)" cmd /k "set APP_API_KEY=local-dev-key&& %PY% -m uvicorn log_api.main:app --port 8001"

echo [4/5] Starting the web app - its own window...
start "ThreatOrbit - Web app (port 3000)" /d "%~dp0frontend" cmd /k "npm run dev"

echo [5/5] Opening your browser in 15 seconds (first start can take a little longer)...
timeout /t 15 >nul
start http://localhost:3000/dashboard

echo.
echo  ============================================================
echo   ThreatOrbit is running in 4 separate windows.
echo.
echo     Web site    http://localhost:3000
echo     Dashboard   http://localhost:3000/dashboard
echo     Sign in     admin@threatorbit.space   ChangeMe123!
echo.
echo   To STOP ThreatOrbit: close the 4 windows it opened.
echo   If the browser shows an error, wait a few seconds and
echo   refresh - the web app may still be starting.
echo  ============================================================
echo.
pause
