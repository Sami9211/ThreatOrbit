#!/usr/bin/env python3
"""ThreatOrbit log collector - a lightweight, dependency-free shipping agent.

"POST your logs here" is not an enterprise answer; this is the agent that does
the POSTing. It tails one or more log files, persists read offsets so a restart
neither re-ships nor drops lines (at-least-once), handles log rotation, batches
lines, and ships them to the SIEM ingest endpoint authenticated with a scoped
API key. It honours ingest backpressure (HTTP 429 + Retry-After) and supports
TLS/mTLS for enrolment-grade transport security.

Stdlib only (urllib/ssl/json) so it drops onto any host with Python 3.8+ and no
pip step. Configure with env vars or flags:

  THREATORBIT_URL        base URL of the dashboard API (e.g. https://soc.acme:8002)
  THREATORBIT_API_KEY    a write-scoped API key (to_sk_live_…) from Settings → API
  THREATORBIT_PATHS      comma-separated file globs to tail (e.g. /var/log/auth.log,/var/log/nginx/*.log)
  THREATORBIT_FORMAT     parser hint: auto|json|apache|nginx|kv|syslog|generic (default auto)
  THREATORBIT_SOURCE     source label attached to events (default: hostname)
  THREATORBIT_BATCH      max lines per request (default 500, hard cap 5000)
  THREATORBIT_INTERVAL   poll seconds between tails (default 5)
  THREATORBIT_STATE      checkpoint file (default /var/lib/threatorbit/collector.state)
  THREATORBIT_CA         CA bundle to verify the server cert (TLS)
  THREATORBIT_CLIENT_CERT / THREATORBIT_CLIENT_KEY   client cert/key for mTLS enrolment
  THREATORBIT_INSECURE   "1" to skip TLS verification (lab only - never in prod)

Run:  python3 threatorbit_collector.py            # daemon loop
      python3 threatorbit_collector.py --once     # single pass (cron-friendly)
      python3 threatorbit_collector.py --dry-run  # tail + checkpoint, print instead of ship
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

HARD_LINE_CAP = 5000          # server rejects > 5000 lines/request
DEFAULT_STATE = "/var/lib/threatorbit/collector.state"


# -- checkpoint store --------------------------------------------------------
class Checkpoint:
    """Per-file {inode, offset} progress, persisted as JSON. Survives restarts
    so we resume exactly where we left off and never re-ship a line."""

    def __init__(self, path: str):
        self.path = path
        self.data: dict[str, dict] = {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            self.data = {}

    def offset_for(self, file_path: str, inode: int) -> int:
        rec = self.data.get(file_path)
        # Rotation: a new inode (or a file shorter than our offset) means the log
        # was rotated/truncated - start from the top of the new file.
        if not rec or rec.get("inode") != inode:
            return 0
        return int(rec.get("offset", 0))

    def set(self, file_path: str, inode: int, offset: int) -> None:
        self.data[file_path] = {"inode": inode, "offset": offset}

    def save(self) -> None:
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh)
        os.replace(tmp, self.path)   # atomic: a crash never corrupts the state


# -- file tailing ------------------------------------------------------------
def read_new_lines(file_path: str, start_offset: int, max_lines: int):
    """Read up to `max_lines` complete lines from `start_offset`. Returns
    (lines, new_offset, inode). A trailing partial line (no newline yet) is left
    unread so we never ship half a record - its bytes stay before new_offset."""
    st = os.stat(file_path)
    inode = st.st_ino
    if start_offset > st.st_size:        # truncated since last read → restart
        start_offset = 0
    lines: list[str] = []
    offset = start_offset
    with open(file_path, "rb") as fh:
        fh.seek(start_offset)
        for raw in fh:
            if not raw.endswith(b"\n"):
                break                    # incomplete final line; wait for the rest
            offset += len(raw)
            text = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
            if text:
                lines.append(text)
            if len(lines) >= max_lines:
                break
    return lines, offset, inode


def discover(globs: list[str]) -> list[str]:
    out: list[str] = []
    for g in globs:
        out.extend(sorted(p for p in glob.glob(g.strip()) if os.path.isfile(p)))
    # stable, de-duplicated
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


# -- shipping ----------------------------------------------------------------
class Shipper:
    def __init__(self, base_url: str, api_key: str, fmt: str, source: str,
                 ssl_ctx: ssl.SSLContext | None = None, timeout: int = 30):
        self.url = base_url.rstrip("/") + "/siem/ingest"
        self.api_key = api_key
        self.fmt = fmt
        self.source = source
        self.ssl_ctx = ssl_ctx
        self.timeout = timeout

    def ship(self, lines: list[str]) -> None:
        """POST a batch. Raises on failure (caller backs off and retries without
        advancing the checkpoint → at-least-once). Honours 429 Retry-After."""
        payload = json.dumps({"lines": lines, "format": self.fmt, "source": self.source}).encode()
        req = urllib.request.Request(self.url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("X-API-Key", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry = int(e.headers.get("Retry-After", "5") or 5)
                raise Backpressure(retry) from e
            raise


class Backpressure(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"ingest backpressure, retry after {retry_after}s")
        self.retry_after = retry_after


def build_ssl_context(ca: str | None, client_cert: str | None,
                      client_key: str | None, insecure: bool) -> ssl.SSLContext | None:
    if not (ca or client_cert or insecure):
        return None                      # plain http or default trust store
    ctx = ssl.create_default_context(cafile=ca or None)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert:                       # mTLS enrolment: present our identity
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key or client_cert)
    return ctx


# -- orchestration -----------------------------------------------------------
def run_pass(globs, checkpoint: Checkpoint, shipper: Shipper, batch: int,
             dry_run: bool, log=print) -> int:
    """One tail-and-ship sweep over all matched files. Returns lines shipped."""
    shipped = 0
    for path in discover(globs):
        try:
            inode = os.stat(path).st_ino
            offset = checkpoint.offset_for(path, inode)
            while True:
                lines, new_offset, inode = read_new_lines(path, offset, batch)
                if not lines:
                    break
                if dry_run:
                    for ln in lines:
                        log(f"[dry-run] {path}: {ln}")
                else:
                    shipper.ship(lines)
                checkpoint.set(path, inode, new_offset)
                checkpoint.save()        # advance only after a successful ship
                shipped += len(lines)
                offset = new_offset
                if len(lines) < batch:
                    break
        except Backpressure as bp:
            log(f"backpressure on {path}: pausing {bp.retry_after}s")
            time.sleep(bp.retry_after)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as e:
            log(f"error on {path}: {e} (will retry next pass, checkpoint unchanged)")
    return shipped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ThreatOrbit log collector")
    ap.add_argument("--once", action="store_true", help="single pass then exit")
    ap.add_argument("--dry-run", action="store_true", help="print lines instead of shipping")
    ap.add_argument("--url", default=os.environ.get("THREATORBIT_URL", ""))
    ap.add_argument("--api-key", default=os.environ.get("THREATORBIT_API_KEY", ""))
    ap.add_argument("--paths", default=os.environ.get("THREATORBIT_PATHS", ""))
    ap.add_argument("--format", default=os.environ.get("THREATORBIT_FORMAT", "auto"))
    ap.add_argument("--source", default=os.environ.get("THREATORBIT_SOURCE", socket.gethostname()))
    ap.add_argument("--batch", type=int, default=int(os.environ.get("THREATORBIT_BATCH", "500")))
    ap.add_argument("--interval", type=float, default=float(os.environ.get("THREATORBIT_INTERVAL", "5")))
    ap.add_argument("--state", default=os.environ.get("THREATORBIT_STATE", DEFAULT_STATE))
    args = ap.parse_args(argv)

    globs = [p for p in args.paths.split(",") if p.strip()]
    if not globs:
        print("error: no paths to tail (set --paths or THREATORBIT_PATHS)", file=sys.stderr)
        return 2
    if not args.dry_run and (not args.url or not args.api_key):
        print("error: --url and --api-key are required unless --dry-run", file=sys.stderr)
        return 2

    batch = max(1, min(args.batch, HARD_LINE_CAP))
    checkpoint = Checkpoint(args.state)
    ssl_ctx = build_ssl_context(
        os.environ.get("THREATORBIT_CA"), os.environ.get("THREATORBIT_CLIENT_CERT"),
        os.environ.get("THREATORBIT_CLIENT_KEY"), os.environ.get("THREATORBIT_INSECURE") == "1")
    shipper = Shipper(args.url, args.api_key, args.format, args.source, ssl_ctx)

    if args.once:
        n = run_pass(globs, checkpoint, shipper, batch, args.dry_run)
        print(f"shipped {n} line(s)")
        return 0

    print(f"threatorbit-collector: tailing {globs} → {args.url or '(dry-run)'} as '{args.source}'")
    try:
        while True:
            run_pass(globs, checkpoint, shipper, batch, args.dry_run)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("shutting down")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
