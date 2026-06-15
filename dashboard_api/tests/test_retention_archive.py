"""Retention archival: when an archive dir is configured, purged rows are
written to compressed NDJSON cold storage BEFORE deletion, so compliance keeps
raw logs cheaply. Disabled (the default) leaves retention as pure purge.
"""
import glob
import gzip
import json
import uuid

from dashboard_api import archive, config
from dashboard_api.db import get_conn


def test_archive_rows_writes_ndjson_gz(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DIR", str(tmp_path))
    rows = [{"id": "a1", "ts": "2020-01-01", "title": "old one"},
            {"id": "a2", "ts": "2020-01-02", "title": "old two"}]
    path = archive.archive_rows("alerts", rows)
    assert path and path.endswith(".ndjson.gz")
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        back = [json.loads(line) for line in fh]
    assert [r["id"] for r in back] == ["a1", "a2"]
    monkeypatch.setattr(config, "ARCHIVE_DIR", "")          # disabled → no-op
    assert archive.archive_rows("alerts", rows) is None
    assert archive.archive_rows("alerts", []) is None       # nothing to write


def test_retention_archives_before_purge(client, auth, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ARCHIVE_DIR", str(tmp_path))
    marker = f"ARCH-{uuid.uuid4().hex[:6]}"
    with get_conn() as conn:
        for i in range(3):
            conn.execute(
                "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
                "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
                "VALUES (?, '2020-01-01T00:00:00+00:00', ?, 'low','new','undetermined','',10,"
                "'R','r',?, '',1,0,'org-default')",
                (f"{marker}-{i}", f"{marker} {i}", marker))
        conn.commit()

    out = client.post("/config/retention/enforce", headers=auth).json()
    assert out["archiveDir"] == str(tmp_path)
    assert out["archived"]["alerts"] >= 3

    # the rows are gone from the live table…
    with get_conn() as conn:
        remaining = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE title LIKE ?",
                                 (f"%{marker}%",)).fetchone()["n"]
    assert remaining == 0

    # …but preserved in gzipped cold storage
    files = glob.glob(str(tmp_path / "alerts-*.ndjson.gz"))
    assert files, "no archive file written"
    with gzip.open(files[0], "rt", encoding="utf-8") as fh:
        titles = [json.loads(line).get("title", "") for line in fh]
    assert sum(1 for t in titles if marker in t) == 3
