"""Golden-input parser tests: the log parsers extract the right fields from real
syslog/apache lines and count malformed input. Audit finding D1.
"""
from log_api.parsers.apache import parse_apache
from log_api.parsers.syslog import parse_syslog


def test_syslog_rfc3164_golden():
    line = ("Jun  1 12:00:00 webhost sshd[2153]: Failed password for invalid user "
            "admin from 203.0.113.7 port 22 ssh2")
    entries, errors = parse_syslog([line])
    assert errors == 0 and len(entries) == 1
    e = entries[0]
    assert e.source_ip == "203.0.113.7"
    assert e.process == "sshd"
    assert e.hostname == "webhost"
    assert e.pid == 2153


def test_apache_combined_golden():
    line = ('203.0.113.9 - - [01/Jun/2026:12:00:00 +0000] "GET /admin HTTP/1.1" 404 512 '
            '"-" "curl/8"')
    entries, errors = parse_apache([line])
    assert errors == 0 and len(entries) == 1
    e = entries[0]
    assert e.source_ip == "203.0.113.9"
    assert e.http_method == "GET" and e.http_path == "/admin"
    assert e.http_status == 404 and e.bytes_sent == 512


def test_parsers_handle_malformed_without_crashing():
    entries, errors = parse_apache(["this is not an apache log line at all"])
    assert isinstance(errors, int)            # counted, not raised
    entries2, errors2 = parse_syslog([""])    # blank line
    assert isinstance(errors2, int)
