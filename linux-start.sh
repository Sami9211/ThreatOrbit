#!/usr/bin/env bash
# ============================================================
#  ThreatOrbit - one-command start for Linux (and macOS).
#  Needs only: Python 3.11+ and Node.js 18+ (LTS recommended).
#
#      ./linux-start.sh              real live data (default)
#      ./linux-start.sh --synthetic  live pipeline + simulated telemetry
#      ./linux-start.sh --demo       seeded showcase data
#      ./linux-start.sh stop         stop everything it started
#      ./linux-start.sh status       show what is running
#
#  Default mode is LIVE with the synthetic engine OFF: the
#  dashboard starts empty and fills itself with REAL threat
#  intelligence from the OSINT/NVD connectors on their sync
#  intervals (needs internet). SIEM alerts appear as soon as
#  you forward real logs (docs/GOING_LIVE.md) - nothing is
#  fabricated. Serves a PRODUCTION build of the website.
# ============================================================
set -u
cd "$(dirname "$0")"

RUN_DIR=".run"
SERVICES=(dashboard threat log frontend)

say()  { printf '%s\n' "$*"; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Kill a process AND everything it spawned. The recorded pid is not always the
# process holding the port: the website is launched through `npx`, which runs
# `next start` as a child, so signalling only the recorded pid left the server
# listening on :3000 after `stop` reported success.
kill_tree() {
    local pid=$1 sig=${2:-TERM} kid
    for kid in $(pgrep -P "$pid" 2>/dev/null); do
        kill_tree "$kid" "$sig"
    done
    kill -"$sig" "$pid" 2>/dev/null
}

# Is anything listening on this port? Read straight from the kernel rather than
# through ss/lsof/fuser, none of which is guaranteed present (a minimal Fedora
# install has none of them) and any of which can come up empty while the port is
# genuinely taken - observed with `next start`, whose listener shows in
# /proc/net/tcp but which `lsof -i` did not report at all. A check that fails
# open is worse than no check: it passes, and the service then cannot bind.
# Returns 0 in use, 1 free, 2 undetermined.
port_in_use() {
    local port=$1 hex f files=""
    hex=$(printf ':%04X' "$port")
    # tcp6 is absent on IPv6-less hosts; passing a missing file makes awk abort
    # before END, which silently reported every port as free.
    for f in /proc/net/tcp /proc/net/tcp6; do [ -r "$f" ] && files="$files $f"; done
    [ -n "$files" ] || return 2
    # shellcheck disable=SC2086
    awk -v suf="$hex" '$4=="0A" && substr($2, length($2)-length(suf)+1) == suf { f=1 }
                       END { exit(f?0:1) }' $files
}

# Best-effort pid attribution for a port. May legitimately come back empty even
# when the port IS in use - occupancy is decided by port_in_use, never by this.
port_holders() {
    local port=$1
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v p=":$port\$" '$4 ~ p' \
            | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u
    elif command -v lsof >/dev/null 2>&1; then
        lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null
    elif command -v fuser >/dev/null 2>&1; then
        fuser "$port"/tcp 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$'
    fi
}

# Print "<pid> <command>" for each holder we could identify, indented.
describe_holders() {
    local pid
    for pid in $(port_holders "$1"); do
        say "    $(ps -o pid=,args= -p "$pid" 2>/dev/null | cut -c1-100)"
    done
}

stop_all() {
    local stopped=0 pid pidfile svc
    for svc in "${SERVICES[@]}"; do
        pidfile="$RUN_DIR/$svc.pid"
        [ -f "$pidfile" ] || continue
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill_tree "$pid" TERM
            # Give it a moment to shut down cleanly, then insist.
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.5
            done
            if kill -0 "$pid" 2>/dev/null; then
                say "$svc did not exit on request - forcing"
                kill_tree "$pid" KILL
            fi
            stopped=$((stopped+1))
            say "stopped $svc (pid $pid)"
        fi
        rm -f "$pidfile"
    done
    [ "$stopped" -eq 0 ] && say "nothing was running (no live pids in $RUN_DIR/)"

    # Verify rather than assume. A leftover listener is exactly the state that
    # makes the next start fail with "port already in use", and deleting the
    # project directory removes the pid files without stopping anything - so
    # `stop` can have nothing to go on while the services are still up.
    local port leftovers=0
    for port in 8000 8001 8002 3000; do
        if port_in_use "$port"; then
            leftovers=1
            say "port $port is STILL in use:"
            describe_holders "$port"
        fi
    done
    if [ "$leftovers" = 1 ]; then
        say ""
        say "These were not started by this script run (no matching pid file), so it"
        say "will not kill them blind. To stop them:  kill <pid>   (then -9 if needed)"
    fi
    exit 0
}

status_all() {
    for svc in "${SERVICES[@]}"; do
        local pidfile="$RUN_DIR/$svc.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            say "$svc: running (pid $(cat "$pidfile"))"
        else
            say "$svc: not running"
        fi
    done
    exit 0
}

# ---- mode selection ----------------------------------------------------
DATA_MODE="live"; ENGINE="off"; MODE_LABEL="LIVE - real data only"
case "${1:-}" in
    stop)         stop_all ;;
    status)       status_all ;;
    --demo)       DATA_MODE="demo"; ENGINE="on";  MODE_LABEL="DEMO - seeded showcase data" ;;
    --synthetic)  DATA_MODE="live"; ENGINE="on";  MODE_LABEL="LIVE + simulated telemetry (pipeline test)" ;;
    "")           : ;;
    *)            fail "unknown option '$1' (use: --demo | --synthetic | stop | status)" ;;
esac

# ---- find Python 3.11+ --------------------------------------------------
PYBIN=""
for c in python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1; then
        if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
            PYBIN="$c"; break
        fi
    fi
done
[ -n "$PYBIN" ] || fail "Python 3.11+ was not found.
  Ubuntu/Debian:  sudo apt install python3 python3-venv python3-pip
  Fedora/RHEL:    sudo dnf install python3"

# ---- find Node.js -------------------------------------------------------
command -v npm >/dev/null 2>&1 || fail "Node.js was not found.
  Install the LTS release from https://nodejs.org/ or your package manager
  (Ubuntu: sudo apt install nodejs npm - needs Node 18+)."

# ---- virtualenv (avoids PEP 668 'externally managed' pip errors) --------
if [ ! -x .venv/bin/python ]; then
    say "[1/6] Creating Python virtualenv (.venv, first run only)..."
    "$PYBIN" -m venv .venv || fail "creating the virtualenv failed.
  On Ubuntu/Debian install it first:  sudo apt install python3-venv"
fi
PY=".venv/bin/python"

say "[2/6] Installing Python packages (fast after the first run)..."
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r dashboard_api/requirements.txt \
                        -r threat_api/requirements.txt \
                        -r log_api/requirements.txt \
    || fail "installing Python packages failed - see the messages above."

say "[3/6] Installing web app packages (first run only - takes a few minutes)..."
if [ ! -d frontend/node_modules ]; then
    (cd frontend && npm install) || fail "npm install failed - see the messages above."
fi

say "[4/6] Building the website for fast loading (about a minute)..."
(cd frontend && npm run build) || fail "building the website failed - see the messages above."

# ---- start the services -------------------------------------------------
mkdir -p "$RUN_DIR"
for port in 8000 8001 8002 3000; do
    if port_in_use "$port"; then
        # Name the process where we can. "port already in use" alone sends
        # people hunting, and the usual cause is a previous run whose pid files
        # went with a deleted project directory, leaving `stop` nothing to act on.
        say "port $port is held by:"
        describe_holders "$port"
        fail "port $port is already in use - run './linux-start.sh stop' first,
  or stop the process listed above (kill <pid>)."
    fi
done

say "[5/6] Starting the three data APIs + website ($MODE_LABEL)..."
SERVICES_API_KEY="${SERVICES_API_KEY:-local-dev-key}" \
DASHBOARD_DATA_MODE="$DATA_MODE" DASHBOARD_ENGINE="$ENGINE" \
    nohup "$PY" -m uvicorn dashboard_api.main:app --host 0.0.0.0 --port 8002 \
    > "$RUN_DIR/dashboard.log" 2>&1 & echo $! > "$RUN_DIR/dashboard.pid"

APP_API_KEY="${APP_API_KEY:-local-dev-key}" ENABLE_SCHEDULER=true \
    nohup "$PY" -m threat_api.main \
    > "$RUN_DIR/threat.log" 2>&1 & echo $! > "$RUN_DIR/threat.pid"

APP_API_KEY="${APP_API_KEY:-local-dev-key}" \
    nohup "$PY" -m uvicorn log_api.main:app --host 0.0.0.0 --port 8001 \
    > "$RUN_DIR/log.log" 2>&1 & echo $! > "$RUN_DIR/log.pid"

# Node SSR server (was a static file server over frontend/out). `next start`
# serves the .next build and applies the security headers from next.config.
nohup sh -c 'cd frontend && exec npx --no-install next start -p 3000' \
    > "$RUN_DIR/frontend.log" 2>&1 & echo $! > "$RUN_DIR/frontend.pid"

say "[6/6] Waiting for the services to come up..."
for port in 8002 8000 8001 3000; do
    ok=0
    for _ in $(seq 1 45); do
        if curl -fsS -o /dev/null "http://127.0.0.1:$port/health" 2>/dev/null \
           || { [ "$port" = 3000 ] && curl -fsS -o /dev/null "http://127.0.0.1:3000/" 2>/dev/null; }; then
            ok=1; break
        fi
        sleep 1
    done
    [ "$ok" = 1 ] || fail "service on port $port did not come up - check $RUN_DIR/*.log"
done

command -v xdg-open >/dev/null 2>&1 && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] \
    && xdg-open http://localhost:3000 >/dev/null 2>&1 &

cat <<BANNER

 ============================================================
  ThreatOrbit is running ($MODE_LABEL).

    Website     http://localhost:3000
    Dashboard   http://localhost:3000/dashboard
    Sign in     admin@threatorbit.space   ChangeMe123!
                (or create your own account at /signup)

    Logs        $RUN_DIR/dashboard.log  .../threat.log
                .../log.log  .../frontend.log
    Stop        ./linux-start.sh stop
    Status      ./linux-start.sh status

  REAL DATA: CTI/feeds fill from live OSINT + NVD connectors
  within a couple of minutes (needs internet) and keep syncing
  on each connector's interval. SIEM stays empty until you
  forward real logs - the runbook is docs/GOING_LIVE.md.
  Nothing on the dashboard is fabricated in this mode.
 ============================================================
BANNER
