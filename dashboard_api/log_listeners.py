"""Long-running log collectors - a syslog UDP listener and a file/dir watcher.

These make "production logs stream in" literal: instead of pasting lines into
the UI, a forwarder can send syslog to a UDP port, or drop/append files into a
watched directory, and the lines flow through the same `ingest_lines` pipeline
(parse → events → detection + threat-intel matching → alerts).

Both are off by default and enabled by env in live mode:
  DASHBOARD_SYSLOG_PORT   (e.g. 5514; 0/unset = disabled)
  DASHBOARD_LOG_WATCH_DIR (a directory to tail; unset = disabled)

The core is socket/thread-free and unit-tested (`ingest_datagram`,
`scan_log_dir`); the listeners are thin loops around it.
"""
import logging
import os
import socket
import threading
import time

logger = logging.getLogger("dashboard_api.log_listeners")

SYSLOG_PORT = int(os.environ.get("DASHBOARD_SYSLOG_PORT", "0") or "0")
WATCH_DIR = os.environ.get("DASHBOARD_LOG_WATCH_DIR", "")
WATCH_INTERVAL = int(os.environ.get("DASHBOARD_LOG_WATCH_SECONDS", "10") or "10")


def ingest_datagram(data: bytes, source: str = "syslog-udp") -> dict:
    """Decode a syslog datagram (possibly multi-line) and ingest its lines."""
    from dashboard_api.ingest import ingest_lines
    text = data.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {"parsed": 0, "alerts": 0}
    return ingest_lines(lines, "auto", source)


def scan_log_dir(directory: str, offsets: dict[str, int], source: str = "file-watch") -> dict:
    """Tail every readable file in `directory` from its last byte offset, ingest
    the new lines, and return {offsets, ingested, alerts}. `offsets` is the
    per-file byte position carried between polls (mutated + returned)."""
    if not directory or not os.path.isdir(directory):
        return {"offsets": offsets, "ingested": 0, "alerts": 0}
    new_lines: list[str] = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
            start = offsets.get(path, 0)
            if size < start:          # file truncated/rotated → re-read from 0
                start = 0
            if size == start:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(start)
                chunk = fh.read()
                offsets[path] = fh.tell()
            new_lines.extend(ln for ln in chunk.splitlines() if ln.strip())
        except OSError:
            continue
    if not new_lines:
        return {"offsets": offsets, "ingested": 0, "alerts": 0}
    from dashboard_api.ingest import ingest_lines
    result = ingest_lines(new_lines, "auto", source)
    return {"offsets": offsets, "ingested": result["parsed"], "alerts": result["alerts"]}


def _syslog_loop(port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    logger.info("Syslog UDP listener bound on :%d", port)
    while True:
        try:
            data, _addr = sock.recvfrom(65535)
            if data:
                ingest_datagram(data)
        except Exception:
            logger.exception("syslog datagram ingest failed")
            time.sleep(0.5)


def _watch_loop(directory: str, interval: int):
    offsets: dict[str, int] = {}
    # Prime offsets to current end-of-file so we only ingest NEW appends.
    if os.path.isdir(directory):
        for name in os.listdir(directory):
            p = os.path.join(directory, name)
            if os.path.isfile(p):
                try:
                    offsets[p] = os.path.getsize(p)
                except OSError:
                    pass
    logger.info("Log directory watcher started on %s (every %ds)", directory, interval)
    while True:
        try:
            scan_log_dir(directory, offsets)
        except Exception:
            logger.exception("log dir scan failed")
        time.sleep(max(2, interval))


def start_listeners() -> dict:
    """Start whichever collectors are configured (live mode). Returns what ran."""
    started = {"syslog": False, "fileWatch": False}
    if SYSLOG_PORT > 0:
        threading.Thread(target=_syslog_loop, args=(SYSLOG_PORT,), daemon=True).start()
        started["syslog"] = True
    if WATCH_DIR:
        threading.Thread(target=_watch_loop, args=(WATCH_DIR, WATCH_INTERVAL), daemon=True).start()
        started["fileWatch"] = True
    return started


def listener_status() -> dict:
    return {"syslogPort": SYSLOG_PORT or None, "syslogEnabled": SYSLOG_PORT > 0,
            "watchDir": WATCH_DIR or None, "watchEnabled": bool(WATCH_DIR),
            "watchIntervalSeconds": WATCH_INTERVAL}
