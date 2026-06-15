"""Backup / restore (DR tooling) tests - the data-survival proof.

A real database is snapshotted, archived, and restored byte-for-byte; integrity
verification catches corruption; restore won't clobber without --force; and the
archive extractor refuses path-traversal members.
"""
import sqlite3
import tarfile

import pytest

from dashboard_api import backup


def _make_db(path, rows):
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    conn.executemany("INSERT INTO t (v) VALUES (?)", [(r,) for r in rows])
    conn.commit()
    conn.close()


def _read(path):
    conn = sqlite3.connect(str(path))
    try:
        return [r[0] for r in conn.execute("SELECT v FROM t ORDER BY id").fetchall()]
    finally:
        conn.close()


def test_backup_restore_roundtrip(tmp_path):
    src = tmp_path / "dash.db"
    _make_db(src, ["alpha", "bravo", "charlie"])
    archive = backup.backup_all({"dashboard": str(src)}, str(tmp_path / "backups"))
    assert archive.endswith(".tar.gz")

    dest = tmp_path / "restored" / "dash.db"
    restored = backup.restore(archive, {"dashboard": str(dest)}, force=True)
    assert restored == ["dashboard"]
    assert _read(dest) == ["alpha", "bravo", "charlie"]


def test_backup_skips_missing_and_errors_when_empty(tmp_path):
    with pytest.raises(RuntimeError, match="no databases"):
        backup.backup_all({"nope": str(tmp_path / "absent.db")}, str(tmp_path / "b"))


def test_verify_detects_corruption(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"this is not a sqlite database, at all")
    with pytest.raises(RuntimeError):
        backup.verify(str(bad))


def test_restore_refuses_overwrite_without_force(tmp_path):
    src = tmp_path / "s.db"
    _make_db(src, ["x"])
    archive = backup.backup_all({"dashboard": str(src)}, str(tmp_path / "b"))
    existing = tmp_path / "live.db"
    _make_db(existing, ["keep-me"])
    with pytest.raises(RuntimeError, match="--force"):
        backup.restore(archive, {"dashboard": str(existing)}, force=False)
    assert _read(existing) == ["keep-me"]  # untouched


def test_restore_drops_stale_wal_sidecars(tmp_path):
    src = tmp_path / "s.db"
    _make_db(src, ["fresh"])
    archive = backup.backup_all({"dashboard": str(src)}, str(tmp_path / "b"))
    dest = tmp_path / "live.db"
    _make_db(dest, ["old"])
    (tmp_path / "live.db-wal").write_bytes(b"stale-wal")
    backup.restore(archive, {"dashboard": str(dest)}, force=True)
    assert _read(dest) == ["fresh"]
    assert not (tmp_path / "live.db-wal").exists()


def test_safe_extract_blocks_path_traversal(tmp_path):
    # Hand-craft an archive with a member that escapes the extraction dir.
    payload = tmp_path / "evil.db"
    payload.write_bytes(b"x")
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(str(payload), arcname="../escaped.db")
    with pytest.raises(RuntimeError, match="unsafe archive member"):
        backup.restore(str(archive), {"escaped": str(tmp_path / "out.db")}, force=True)
