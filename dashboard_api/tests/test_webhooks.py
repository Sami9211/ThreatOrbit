"""Direct unit tests for dashboard_api/webhooks.py: HMAC signing/verification,
`_subscribers` event + tenant filtering, and the `_post_with_retry` delivery
primitive (monkeypatched net_guard.safe_post — no real sockets involved).

test_webhook_signing.py already covers the end-to-end HTTP delivery path
(rotate-secret, idempotent retry-then-succeed via a real local HTTP server).
This file goes one level deeper: it drives the private helpers directly so
failure modes that are awkward to provoke over a real socket (a hard SSRF
block, or every retry attempt failing) are exercised precisely.
"""
import time
import uuid

import httpx
import pytest

from dashboard_api import net_guard
from dashboard_api import tenancy
from dashboard_api import webhooks as wh
from dashboard_api.db import get_conn, dumps


def _insert_webhook(conn, *, events, status="active", org_id="org-default",
                    secret=None, url=None) -> str:
    wid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO webhooks (id,url,events,status,created_at,created_by,secret,org_id) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (wid, url or f"https://example.test/hook/{wid}", dumps(events), status,
         "2026-07-05T00:00:00+00:00", "pytest", secret, org_id),
    )
    return wid


def _delete_webhook(wid: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM webhooks WHERE id=?", (wid,))
        conn.commit()


# ── sign_payload / verify_signature ──────────────────────────────────────────────

def test_sign_verify_roundtrip_valid():
    secret = wh.new_webhook_secret()
    body = b'{"event":"alert.created","data":{"id":1}}'
    sig = wh.sign_payload(secret, body)
    assert wh.verify_signature(secret, body, sig)


def test_verify_signature_tampered_body_rejected():
    secret = wh.new_webhook_secret()
    body = b'{"a":1}'
    sig = wh.sign_payload(secret, body)
    assert not wh.verify_signature(secret, body + b"tampered", sig)


def test_verify_signature_wrong_secret_rejected():
    secret = wh.new_webhook_secret()
    body = b'{"a":1}'
    sig = wh.sign_payload(secret, body)
    assert not wh.verify_signature("whsec_" + uuid.uuid4().hex, body, sig)


def test_verify_signature_expired_timestamp_rejected():
    secret = wh.new_webhook_secret()
    body = b"{}"
    old_ts = int(time.time()) - 10_000   # well outside the default 300s tolerance
    sig = wh.sign_payload(secret, body, ts=old_ts)
    assert not wh.verify_signature(secret, body, sig)
    # the same signature verifies fine if the caller widens the tolerance
    assert wh.verify_signature(secret, body, sig, tolerance=20_000)
    # tolerance=0 disables the time check entirely
    assert wh.verify_signature(secret, body, sig, tolerance=0)


@pytest.mark.parametrize("bad_header", [
    "", "garbage", "t=123", "v1=deadbeef", "t=notanumber,v1=abc", ",", "t=,v1=",
])
def test_verify_signature_malformed_header_rejected(bad_header):
    secret = wh.new_webhook_secret()
    assert not wh.verify_signature(secret, b"{}", bad_header)


def test_verify_signature_requires_secret_and_header():
    sig = wh.sign_payload(wh.new_webhook_secret(), b"{}")
    assert not wh.verify_signature("", b"{}", sig)
    assert not wh.verify_signature(wh.new_webhook_secret(), b"{}", "")


def test_verify_signature_accepts_any_matching_v1_when_multiple_present():
    """Header can carry more than one v1= value (rotation window); any match passes."""
    secret = wh.new_webhook_secret()
    body = b'{"x":1}'
    ts = int(time.time())
    good = wh.sign_payload(secret, body, ts=ts)
    combined = good + ",v1=deadbeef"
    assert wh.verify_signature(secret, body, combined)


# ── _subscribers: event + tenant filtering ───────────────────────────────────────

def test_subscribers_filters_by_event_name():
    tag = uuid.uuid4().hex[:8]
    ev_a, ev_b = f"alert.created.{tag}", f"case.created.{tag}"
    with get_conn() as conn:
        wid_a = _insert_webhook(conn, events=[ev_a])
        wid_b = _insert_webhook(conn, events=[ev_b])
        conn.commit()
    try:
        subs_a = {s["id"] for s in wh._subscribers(ev_a)}
        subs_b = {s["id"] for s in wh._subscribers(ev_b)}
        assert wid_a in subs_a and wid_a not in subs_b
        assert wid_b in subs_b and wid_b not in subs_a
    finally:
        _delete_webhook(wid_a)
        _delete_webhook(wid_b)


def test_subscribers_excludes_paused_webhooks():
    tag = uuid.uuid4().hex[:8]
    event = f"alert.created.{tag}"
    with get_conn() as conn:
        wid = _insert_webhook(conn, events=[event], status="paused")
        conn.commit()
    try:
        assert wid not in {s["id"] for s in wh._subscribers(event)}
    finally:
        _delete_webhook(wid)


def test_subscribers_ignores_malformed_events_json():
    """A corrupt `events` column fails closed (no match) rather than raising."""
    tag = uuid.uuid4().hex[:8]
    event = f"alert.created.{tag}"
    wid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO webhooks (id,url,events,status,created_at,created_by) "
            "VALUES (?,?,?,?,?,?)",
            (wid, "https://example.test/hook", "not-json{{", "active",
             "2026-07-05T00:00:00+00:00", "pytest"))
        conn.commit()
    try:
        assert wid not in {s["id"] for s in wh._subscribers(event)}
    finally:
        _delete_webhook(wid)


def test_subscribers_tenant_scoping(monkeypatch):
    """With isolation enforced, an org only sees its own webhooks for a
    tenant-scoped event; isolation off falls back to the prior global fan-out."""
    tag = uuid.uuid4().hex[:8]
    event = f"custom.event.{tag}"
    with get_conn() as conn:
        mine = _insert_webhook(conn, events=[event], org_id="org-default")
        other = _insert_webhook(conn, events=[event], org_id="org-other")
        conn.commit()
    try:
        monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
        ids_default = {s["id"] for s in wh._subscribers(event, "org-default")}
        ids_other = {s["id"] for s in wh._subscribers(event, "org-other")}
        assert mine in ids_default and mine not in ids_other
        assert other in ids_other and other not in ids_default

        monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
        ids_unscoped = {s["id"] for s in wh._subscribers(event, "org-other")}
        assert mine in ids_unscoped and other in ids_unscoped   # global fan-out restored
    finally:
        monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
        _delete_webhook(mine)
        _delete_webhook(other)


# ── _post_with_retry ──────────────────────────────────────────────────────────────

def test_post_with_retry_succeeds_on_first_attempt(monkeypatch):
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    calls = []

    class Resp:
        status_code = 200

    def fake_safe_post(url, **kwargs):
        calls.append(url)
        return Resp()

    monkeypatch.setattr(net_guard, "safe_post", fake_safe_post)
    ok = wh._post_with_retry("https://sink.test/hook", b"{}", {"X": "1"})
    assert ok is True
    assert len(calls) == 1


def test_post_with_retry_exhausts_attempts_then_fails(monkeypatch):
    """Every attempt returns a server error: no attempt succeeds, and the
    function stops after exactly _MAX_ATTEMPTS tries (no infinite retry)."""
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    calls = []

    class Resp:
        status_code = 500

    def fake_safe_post(url, **kwargs):
        calls.append(url)
        return Resp()

    monkeypatch.setattr(net_guard, "safe_post", fake_safe_post)
    ok = wh._post_with_retry("https://sink.test/hook", b"{}", {})
    assert ok is False
    assert len(calls) == wh._MAX_ATTEMPTS


def test_post_with_retry_transient_error_then_success(monkeypatch):
    """A transient httpx error on the first attempt is retried; success on the
    second attempt short-circuits further retries."""
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    state = {"n": 0}

    class Resp:
        status_code = 200

    def fake_safe_post(url, **kwargs):
        state["n"] += 1
        if state["n"] == 1:
            raise httpx.ConnectError("connection refused")
        return Resp()

    monkeypatch.setattr(net_guard, "safe_post", fake_safe_post)
    ok = wh._post_with_retry("https://sink.test/hook", b"{}", {})
    assert ok is True
    assert state["n"] == 2


def test_post_with_retry_ssrf_blocked_never_retries(monkeypatch):
    """An SSRF-guard rejection is a permanent verdict for this URL — retrying
    won't make a blocked target become allowed, so the function must give up
    on the FIRST attempt rather than burning the retry budget."""
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    calls = []

    def fake_safe_post(url, **kwargs):
        calls.append(url)
        raise net_guard.UnsafeUrlError("URL resolves to a private or reserved address")

    monkeypatch.setattr(net_guard, "safe_post", fake_safe_post)
    ok = wh._post_with_retry("http://169.254.169.254/latest/meta-data", b"{}", {})
    assert ok is False
    assert len(calls) == 1   # no retry after an SSRF block


# ── _deliver: end-to-end status bookkeeping (monkeypatched transport) ────────────

def test_deliver_marks_webhook_active_on_success_and_failing_on_failure(monkeypatch):
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    tag = uuid.uuid4().hex[:8]
    event = f"alert.created.{tag}"
    with get_conn() as conn:
        wid = _insert_webhook(conn, events=[event])
        conn.commit()
    try:
        class OkResp:
            status_code = 200

        monkeypatch.setattr(net_guard, "safe_post", lambda url, **kw: OkResp())
        wh._deliver(event, {"x": 1}, [{"id": wid, "url": "https://sink.test/hook", "secret": None}])
        with get_conn() as conn:
            row = conn.execute("SELECT status, last_delivery FROM webhooks WHERE id=?",
                               (wid,)).fetchone()
        assert row["status"] == "active" and row["last_delivery"]

        class FailResp:
            status_code = 500

        monkeypatch.setattr(net_guard, "safe_post", lambda url, **kw: FailResp())
        wh._deliver(event, {"x": 1}, [{"id": wid, "url": "https://sink.test/hook", "secret": None}])
        with get_conn() as conn:
            row = conn.execute("SELECT status FROM webhooks WHERE id=?", (wid,)).fetchone()
        assert row["status"] == "failing"
    finally:
        _delete_webhook(wid)


def test_deliver_signs_body_only_when_secret_present(monkeypatch):
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    captured = {}

    class Resp:
        status_code = 200

    def fake_safe_post(url, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return Resp()

    monkeypatch.setattr(net_guard, "safe_post", fake_safe_post)
    wh._deliver("alert.created", {"x": 1}, [{"id": "no-such-id", "url": "https://sink.test/hook",
                                             "secret": None}])
    assert "X-ThreatOrbit-Signature" not in captured["headers"]

    secret = wh.new_webhook_secret()
    wh._deliver("alert.created", {"x": 1}, [{"id": "no-such-id", "url": "https://sink.test/hook",
                                             "secret": secret}])
    sig = captured["headers"].get("X-ThreatOrbit-Signature")
    assert sig is not None
