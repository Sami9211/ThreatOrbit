"""Retention archival: when an archive dir and/or an object store (S3) is
configured, purged rows are written to compressed NDJSON cold storage BEFORE
deletion, so compliance keeps raw logs cheaply. Disabled (the default) leaves
retention as pure purge.
"""
import glob
import gzip
import hashlib
import json
import uuid

import pytest

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


def test_sigv4_signature_matches_aws_s3_get_example():
    """KAT: the AWS S3 'GET Object' worked example (empty payload). The
    canonical-request hash equals AWS's published value and the signature is
    cross-checked against botocore - so the signing pipeline is provably correct
    without a runtime dependency on an AWS SDK."""
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    headers = {"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
               "x-amz-content-sha256": empty, "x-amz-date": "20130524T000000Z"}
    sh, scope, sig = archive._sign(
        "GET", "/test.txt", headers, empty, "us-east-1", "s3",
        "20130524T000000Z", "20130524", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    assert sh == "host;range;x-amz-content-sha256;x-amz-date"
    assert scope == "20130524/us-east-1/s3/aws4_request"
    assert sig == "67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900"


def _configure_s3(monkeypatch, *, archive_dir="", endpoint=""):
    monkeypatch.setattr(config, "ARCHIVE_DIR", archive_dir)
    monkeypatch.setattr(config, "ARCHIVE_S3_BUCKET", "cold-logs")
    monkeypatch.setattr(config, "ARCHIVE_S3_PREFIX", "to/archive")
    monkeypatch.setattr(config, "ARCHIVE_S3_REGION", "us-east-1")
    monkeypatch.setattr(config, "ARCHIVE_S3_ENDPOINT", endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secretexamplekey")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)


def test_archive_rows_writes_signed_object_to_s3(monkeypatch):
    _configure_s3(monkeypatch)
    captured = {}
    monkeypatch.setattr(archive, "_http_put",
                        lambda url, body, headers: captured.update(url=url, body=body, headers=headers))

    rows = [{"id": "a1", "ts": "2020-01-01", "title": "old"}]
    ret = archive.archive_rows("alerts", rows)
    assert ret.startswith("s3://cold-logs/to/archive/alerts/") and ret.endswith(".ndjson.gz")
    # the object body is gzip of the NDJSON
    assert gzip.decompress(captured["body"]).decode() == archive._ndjson(rows)
    h = {k.lower(): v for k, v in captured["headers"].items()}
    assert h["host"] == "cold-logs.s3.us-east-1.amazonaws.com"
    assert h["content-type"] == "application/gzip"
    assert h["x-amz-content-sha256"] == hashlib.sha256(captured["body"]).hexdigest()
    assert h["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/")
    assert "SignedHeaders=" in h["authorization"] and "Signature=" in h["authorization"]
    assert captured["url"].startswith("https://cold-logs.s3.us-east-1.amazonaws.com/to/archive/alerts/")


def test_archive_rows_path_style_endpoint(monkeypatch):
    # S3-compatible store (MinIO/R2): path-style URL against the custom endpoint.
    _configure_s3(monkeypatch, endpoint="https://minio.local:9000")
    captured = {}
    monkeypatch.setattr(archive, "_http_put",
                        lambda url, body, headers: captured.update(url=url, headers=headers))
    archive.archive_rows("events", [{"id": "e1"}])
    assert captured["url"].startswith("https://minio.local:9000/cold-logs/to/archive/events/")
    assert {k.lower(): v for k, v in captured["headers"].items()}["host"] == "minio.local:9000"


def test_archive_rows_local_and_s3_both(tmp_path, monkeypatch):
    _configure_s3(monkeypatch, archive_dir=str(tmp_path))
    monkeypatch.setattr(archive, "_http_put", lambda *a, **k: None)
    ret = archive.archive_rows("events", [{"id": "e1"}])
    assert str(tmp_path) in ret and "s3://cold-logs/" in ret
    assert archive.targets() == {"dir": str(tmp_path), "s3": "s3://cold-logs/to/archive"}


def test_s3_put_failure_raises_oserror_so_purge_is_aborted(monkeypatch):
    _configure_s3(monkeypatch)
    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(archive, "_http_put", boom)
    with pytest.raises(OSError):
        archive.archive_rows("alerts", [{"id": "a1"}])


def test_per_table_retention_windows(client, auth):
    """Each table can have its own retention window (retention_days_<table>),
    falling back to the global default - so events can be kept shorter than alerts."""
    import datetime as _dt
    marker = "TIER-" + uuid.uuid4().hex[:6]
    old = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=20)).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute("INSERT INTO events (id,ts,category,event_type,raw,processed) VALUES (?,?,?,?,?,1)",
                     (f"ev-{marker}", old, "test", "log", marker))
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
            "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
            "VALUES (?,?,?, 'low','new','undetermined','',10,'R','r',?, '',1,0,'org-default')",
            (f"al-{marker}", old, marker, marker))
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('retention_days_events','7')")
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('data_retention_days','90')")
        conn.commit()
    try:
        out = client.post("/config/retention/enforce", headers=auth).json()
        assert out["perTableDays"]["events"] == 7 and out["perTableDays"]["alerts"] == 90
        with get_conn() as conn:
            ev = conn.execute("SELECT COUNT(*) c FROM events WHERE raw=?", (marker,)).fetchone()["c"]
            al = conn.execute("SELECT COUNT(*) c FROM alerts WHERE title=?", (marker,)).fetchone()["c"]
        assert ev == 0   # 20-day-old event purged under the 7-day window
        assert al == 1   # 20-day-old alert kept under the 90-day window
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key='retention_days_events'")
            conn.execute("DELETE FROM alerts WHERE title=?", (marker,))
            conn.commit()
