"""Consistent backup & restore for the ThreatOrbit SQLite databases (DR tooling).

Takes a live-safe, point-in-time snapshot of each database with SQLite's online
backup API (no need to stop the service), verifies it with PRAGMA
integrity_check, and bundles the snapshots into a timestamped tar.gz. Restore
verifies each snapshot before it overwrites a live file and refuses to clobber
without --force.

Scope vs `dashboard_api/ops.py`: ops.py is the *dashboard-only* in-app snapshot
behind `GET /config/backup` (+ `python -m dashboard_api.ops backup|verify`); THIS
module is the full-stack DR tool - it snapshots **all three** service databases,
bundles them into one archive, and (the piece ops.py left to a manual runbook)
performs a **verified restore**, exercised by an automated round-trip drill.

Pure stdlib - no app imports - so it runs as a standalone tool inside or outside
the container:

    python -m dashboard_api.backup backup  --out ./backups \\
        --db dashboard=/data/dashboard.db --db threat=/data/threat_api.db \\
        --db log=/data/log_api.db
    python -m dashboard_api.backup restore --archive backups/<file>.tar.gz \\
        --db dashboard=/data/dashboard.db ... [--force]

Runbook (RPO/RTO, scheduling, Docker volumes): docs/BACKUP_RESTORE.md.
"""
import argparse
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def verify(path: str) -> None:
    """Raise unless `path` is a structurally-sound SQLite database."""
    try:
        conn = sqlite3.connect(path)
        try:
            row = conn.execute("PRAGMA integrity_check").fetchone()
        finally:
            conn.close()
    except sqlite3.Error as e:
        raise RuntimeError(f"cannot open {path} as a database: {e}")
    if not row or row[0] != "ok":
        raise RuntimeError(f"integrity check failed for {path}: {row[0] if row else 'no result'}")


def snapshot(src: str, dest: str) -> None:
    """Live-safe consistent copy of `src` → `dest` via the online backup API,
    then verify the snapshot."""
    src_conn = sqlite3.connect(src)
    try:
        dest_conn = sqlite3.connect(dest)
        try:
            src_conn.backup(dest_conn)   # atomic, consistent even while in use
        finally:
            dest_conn.close()
    finally:
        src_conn.close()
    verify(dest)


def backup_all(dbs: dict, out_dir: str) -> str:
    """Snapshot each {name: path} database and bundle them into a timestamped
    tar.gz under `out_dir`. Missing sources are skipped. Returns the archive
    path; raises if nothing was found to back up."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    archive = str(Path(out_dir) / f"threatorbit-backup-{stamp}.tar.gz")
    with tempfile.TemporaryDirectory() as work:
        members = []
        for name, path in dbs.items():
            if not os.path.exists(path):
                print(f"  skip {name}: {path} not found", file=sys.stderr)
                continue
            snap = os.path.join(work, f"{name}.db")
            snapshot(path, snap)
            members.append((snap, f"{name}.db"))
        if not members:
            raise RuntimeError("no databases found to back up")
        with tarfile.open(archive, "w:gz") as tar:
            for snap, arc in members:
                tar.add(snap, arcname=arc)
    return archive


def restore(archive: str, targets: dict, force: bool = False) -> list:
    """Restore {name: dest_path} from a backup archive. Each snapshot is
    integrity-checked before it overwrites a live file; an existing file is kept
    unless `force`. Stale WAL/SHM sidecars of the replaced file are removed.
    Returns the list of restored names."""
    restored = []
    with tempfile.TemporaryDirectory() as work:
        with tarfile.open(archive, "r:gz") as tar:
            _safe_extract(tar, work)
        for name, dest in targets.items():
            snap = os.path.join(work, f"{name}.db")
            if not os.path.exists(snap):
                print(f"  skip {name}: not present in archive", file=sys.stderr)
                continue
            verify(snap)
            if os.path.exists(dest) and not force:
                raise RuntimeError(f"{dest} already exists; pass --force to overwrite")
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            for sidecar in ("-wal", "-shm"):
                p = dest + sidecar
                if os.path.exists(p):
                    os.remove(p)
            shutil.copyfile(snap, dest)
            restored.append(name)
    return restored


def _safe_extract(tar: tarfile.TarFile, path: str) -> None:
    """Extract guarding against path traversal (zip-slip) in archive members."""
    base = os.path.realpath(path)
    for m in tar.getmembers():
        target = os.path.realpath(os.path.join(path, m.name))
        if target != base and not target.startswith(base + os.sep):
            raise RuntimeError(f"refusing unsafe archive member: {m.name}")
    tar.extractall(path)


def _parse_dbs(items) -> dict:
    out = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit(f"--db expects name=path, got {it!r}")
        name, path = it.split("=", 1)
        out[name.strip()] = path.strip()
    return out


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="ThreatOrbit SQLite backup / restore")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup", help="snapshot databases into a tar.gz")
    b.add_argument("--out", default="./backups")
    b.add_argument("--db", action="append", metavar="name=path", required=True)
    r = sub.add_parser("restore", help="restore databases from a tar.gz")
    r.add_argument("--archive", required=True)
    r.add_argument("--db", action="append", metavar="name=path", required=True)
    r.add_argument("--force", action="store_true", help="overwrite existing files")
    args = p.parse_args(argv)
    if args.cmd == "backup":
        print(backup_all(_parse_dbs(args.db), args.out))
    else:
        names = restore(args.archive, _parse_dbs(args.db), args.force)
        print("restored:", ", ".join(names) or "(nothing)")


if __name__ == "__main__":
    main()
