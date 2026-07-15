"""Opt-in PII/secret redaction at the ingest seam: the configured categories
are masked in raw log text BEFORE persistence; off by default (verbatim);
structured pivot fields always survive for detection.
"""
import uuid

from dashboard_api import config, redaction
from dashboard_api.db import get_conn


# -- the pure redactor ---------------------------------------------------------

def test_disabled_is_verbatim():
    line = "login jdoe@corp.example password=hunter2 4111 1111 1111 1111"
    assert redaction.redact(line, categories=[]) == line
    assert redaction.redact(None, categories=["email"]) is None


def test_email_masks_local_part_keeps_domain():
    out = redaction.redact("mail from jane.doe+x@phish.example rejected",
                           categories=["email"])
    assert "jane.doe" not in out
    assert "[redacted]@phish.example" in out   # domain kept: it's the pivot


def test_secret_values_replaced_key_kept():
    out = redaction.redact(
        'POST /login password=hunter2 api_key=abc123 Authorization: Bearer eyJhbGci.x.y',
        categories=["secret"])
    assert "hunter2" not in out and "abc123" not in out and "eyJhbGci" not in out
    # the keys stay so the line remains diagnosable
    assert "password=[REDACTED]" in out and "api_key=[REDACTED]" in out
    assert redaction.redact("key id AKIAIOSFODNN7EXAMPLE", categories=["secret"]) \
        == "key id [AWS-KEY-REDACTED]"


def test_cc_requires_luhn():
    # 4111111111111111 passes Luhn → masked, including separated forms
    assert redaction.redact("card 4111 1111 1111 1111 used",
                            categories=["cc"]) == "card [CC-REDACTED] used"
    # a 16-digit non-Luhn number (e.g. an id) is left alone
    line = "trace id 1234567890123456"
    assert redaction.redact(line, categories=["cc"]) == line


def test_ssn_dashed_form():
    assert redaction.redact("SSN 123-45-6789 on file", categories=["ssn"]) \
        == "SSN [SSN-REDACTED] on file"


# -- wired into the ingest seam ------------------------------------------------

def test_ingest_persists_redacted_raw_but_keeps_pivots(monkeypatch):
    from dashboard_api.ingest import ingest_lines
    monkeypatch.setattr(config, "LOG_REDACT", ["email", "secret"])
    mk = uuid.uuid4().hex[:8]
    # the marker rides in a neutral token (host tag) that no category touches
    line = (f"sshd-{mk}[999]: Failed password for victim@corp.example "
            f"from 203.0.113.77 password=hunter2")
    res = ingest_lines([line], "auto", f"test-{mk}")
    assert res["parsed"] == 1
    with get_conn() as conn:
        row = conn.execute("SELECT raw, src_ip FROM events WHERE raw LIKE ? "
                           "ORDER BY ts DESC LIMIT 1", (f"%sshd-{mk}%",)).fetchone()
    assert row is not None
    assert "victim@corp.example" not in row["raw"]   # PII gone from storage
    assert "hunter2" not in row["raw"]               # secret gone from storage
    assert "[redacted]@corp.example" in row["raw"]
    assert row["src_ip"] == "203.0.113.77"           # the pivot survives


def test_ingest_default_stores_verbatim(monkeypatch):
    from dashboard_api.ingest import ingest_lines
    monkeypatch.setattr(config, "LOG_REDACT", [])
    mk = uuid.uuid4().hex[:8]
    line = f"sshd[999]: Failed password for verbatim-{mk}@corp.example from 203.0.113.88"
    ingest_lines([line], "auto", f"test-{mk}")
    with get_conn() as conn:
        row = conn.execute("SELECT raw FROM events WHERE raw LIKE ? "
                           "ORDER BY ts DESC LIMIT 1", (f"%{mk}%",)).fetchone()
    assert row and f"verbatim-{mk}@corp.example" in row["raw"]
