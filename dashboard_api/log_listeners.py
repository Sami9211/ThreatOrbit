"""Long-running log collectors - a syslog UDP listener and a file/dir watcher.

These make "production logs stream in" literal: instead of pasting lines into
the UI, a forwarder can send syslog to a UDP port, or drop/append files into a
watched directory, and the lines flow through the same `ingest_lines` pipeline
(parse → events → detection + threat-intel matching → alerts).

Both are off by default and enabled by env in live mode:
  DASHBOARD_SYSLOG_PORT      (UDP, e.g. 5514; 0/unset = disabled)
  DASHBOARD_SYSLOG_TLS_PORT  (TLS, RFC 5425, e.g. 6514; needs cert+key below)
  DASHBOARD_SYSLOG_TLS_CERT  (PEM server certificate)
  DASHBOARD_SYSLOG_TLS_KEY   (PEM private key)
  DASHBOARD_SYSLOG_TLS_CA    (optional PEM CA → require client certs = mTLS)
  DASHBOARD_LOG_WATCH_DIR    (a directory to tail; unset = disabled)

The core is socket/thread-free and unit-tested (`ingest_datagram`,
`deframe_syslog`, `scan_log_dir`); the listeners are thin loops around it.
"""
import logging
import os
import socket
import threading
import time

logger = logging.getLogger("dashboard_api.log_listeners")

SYSLOG_PORT = int(os.environ.get("DASHBOARD_SYSLOG_PORT", "0") or "0")
SYSLOG_TLS_PORT = int(os.environ.get("DASHBOARD_SYSLOG_TLS_PORT", "0") or "0")
SYSLOG_TLS_CERT = os.environ.get("DASHBOARD_SYSLOG_TLS_CERT", "")
SYSLOG_TLS_KEY = os.environ.get("DASHBOARD_SYSLOG_TLS_KEY", "")
SYSLOG_TLS_CA = os.environ.get("DASHBOARD_SYSLOG_TLS_CA", "")
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


def deframe_syslog(buf: bytes) -> tuple[list[str], bytes]:
    """Split a TCP/TLS syslog byte stream into complete messages (RFC 6587).

    Supports **octet-counting** framing (``MSGLEN SP MSG`` - the method RFC 5425
    mandates for syslog over TLS) AND **non-transparent** newline framing, so it
    accepts both well-behaved RFC 5425 senders and simpler newline emitters.
    Returns ``(messages, remainder)`` where remainder is the incomplete trailing
    bytes to carry into the next read (a frame may span TCP segments)."""
    messages: list[str] = []
    while buf:
        # Octet-counting: leading ASCII digits, a single space, then exactly
        # that many bytes of message.
        i = 0
        while i < len(buf) and 0x30 <= buf[i] <= 0x39:   # '0'-'9'
            i += 1
        if 0 < i < len(buf) and buf[i] == 0x20:
            length = int(buf[:i])
            start, end = i + 1, i + 1 + length
            if end > len(buf):
                break                                    # frame not fully arrived
            messages.append(buf[start:end].decode("utf-8", errors="replace"))
            buf = buf[end:]
            continue
        if i > 0 and i == len(buf):
            break                                        # digits only so far - wait
        # Non-transparent framing: up to the next newline.
        nl = buf.find(b"\n")
        if nl < 0:
            break                                        # line not yet terminated
        line = buf[:nl].decode("utf-8", errors="replace").strip()
        if line:
            messages.append(line)
        buf = buf[nl + 1:]
    return messages, buf


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


def _handle_tls_conn(ctx, raw_sock, addr):
    """Wrap an accepted socket in TLS and ingest its octet/newline-framed
    messages until the peer closes. One thread per connection."""
    from dashboard_api.ingest import ingest_lines
    try:
        conn = ctx.wrap_socket(raw_sock, server_side=True)
    except Exception:
        try:
            raw_sock.close()
        except Exception:
            pass
        return
    buf = b""
    try:
        while True:
            chunk = conn.recv(65535)
            if not chunk:
                break
            buf += chunk
            messages, buf = deframe_syslog(buf)
            lines = [m for m in messages if m.strip()]
            if lines:
                ingest_lines(lines, "auto", "syslog-tls")
    except Exception:
        logger.exception("syslog TLS connection from %s failed", addr)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _syslog_tls_loop(port: int, certfile: str, keyfile: str, cafile: str = ""):
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if cafile:                                    # mutual TLS: require a client cert
        ctx.load_verify_locations(cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    logger.info("Syslog TLS listener bound on :%d (RFC 5425%s)", port,
                ", mTLS" if cafile else "")
    while True:
        try:
            raw_sock, addr = srv.accept()
            threading.Thread(target=_handle_tls_conn, args=(ctx, raw_sock, addr),
                             daemon=True).start()
        except Exception:
            logger.exception("syslog TLS accept failed")
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
    from dashboard_api import leader
    while True:
        try:
            # HA: if several replicas watch a shared directory, only the leader
            # ingests, or every appended line would be ingested N times.
            if leader.is_leader():
                scan_log_dir(directory, offsets)
        except Exception:
            logger.exception("log dir scan failed")
        time.sleep(max(2, interval))


def start_listeners() -> dict:
    """Start whichever collectors are configured (live mode). Returns what ran."""
    started = {"syslog": False, "syslogTls": False, "fileWatch": False}
    if SYSLOG_PORT > 0:
        threading.Thread(target=_syslog_loop, args=(SYSLOG_PORT,), daemon=True).start()
        started["syslog"] = True
    if SYSLOG_TLS_PORT > 0 and SYSLOG_TLS_CERT and SYSLOG_TLS_KEY:
        threading.Thread(target=_syslog_tls_loop,
                         args=(SYSLOG_TLS_PORT, SYSLOG_TLS_CERT, SYSLOG_TLS_KEY, SYSLOG_TLS_CA),
                         daemon=True).start()
        started["syslogTls"] = True
    elif SYSLOG_TLS_PORT > 0:
        logger.warning("DASHBOARD_SYSLOG_TLS_PORT set but cert/key missing - TLS listener not started")
    if WATCH_DIR:
        threading.Thread(target=_watch_loop, args=(WATCH_DIR, WATCH_INTERVAL), daemon=True).start()
        started["fileWatch"] = True
    return started


def listener_status() -> dict:
    tls_ready = bool(SYSLOG_TLS_PORT > 0 and SYSLOG_TLS_CERT and SYSLOG_TLS_KEY)
    return {"syslogPort": SYSLOG_PORT or None, "syslogEnabled": SYSLOG_PORT > 0,
            "syslogTlsPort": SYSLOG_TLS_PORT or None, "syslogTlsEnabled": tls_ready,
            "syslogTlsMtls": bool(tls_ready and SYSLOG_TLS_CA),
            "watchDir": WATCH_DIR or None, "watchEnabled": bool(WATCH_DIR),
            "watchIntervalSeconds": WATCH_INTERVAL}
