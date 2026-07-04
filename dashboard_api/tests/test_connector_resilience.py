"""Connector feed resilience: a huge/hostile/buggy feed response must not be
buffered unboundedly (memory-exhaustion DoS), and a connector that trips the
cap degrades gracefully — it records the error and never crashes the API.

A SIEM's threat-intel connectors fetch attacker-adjacent, third-party URLs on a
schedule. `httpx.get()`/`.post()` read the whole body into memory before
`.json()`/`.text`, so a compromised or misbehaving feed returning a multi-GB
dump would OOM the dashboard. `_read_capped` streams and rejects past
`_MAX_FEED_BYTES`; `run_connector` catches the resulting ValueError.
"""
import pytest

import dashboard_api.connectors as conn_mod


class _FakeStream:
    """Stand-in for the context manager `httpx.stream(...)` returns."""

    def __init__(self, chunks: list[bytes], ok: bool = True):
        self._chunks = chunks
        self._ok = ok

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if not self._ok:
            raise conn_mod.httpx.HTTPError("bad status")

    def iter_bytes(self):
        yield from self._chunks


def test_read_capped_rejects_oversized_body(monkeypatch):
    """A body larger than the cap raises ValueError mid-stream — it is never
    fully accumulated (we stop the moment the running total passes the bound)."""
    monkeypatch.setattr(conn_mod, "_MAX_FEED_BYTES", 1024)
    # 4 KB delivered in 512-byte chunks: the cap trips on the third chunk.
    chunks = [b"x" * 512 for _ in range(8)]
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream(chunks))
    with pytest.raises(ValueError, match="exceeds"):
        conn_mod._read_capped("GET", "https://feed.invalid/huge")


def test_read_capped_reads_under_cap(monkeypatch):
    """A body under the cap is returned intact, exposing .text and .json()."""
    monkeypatch.setattr(conn_mod, "_MAX_FEED_BYTES", 1024)
    payload = b'{"data": [{"indicator": "203.0.113.7", "kind": "ip"}]}'
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream([payload]))
    resp = conn_mod._read_capped("GET", "https://feed.invalid/small")
    assert resp.text == payload.decode()
    assert resp.json()["data"][0]["indicator"] == "203.0.113.7"


def test_read_capped_boundary_exact(monkeypatch):
    """Exactly cap bytes is allowed; one byte over is rejected."""
    monkeypatch.setattr(conn_mod, "_MAX_FEED_BYTES", 10)
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream([b"0123456789"]))
    assert conn_mod._read_capped("GET", "https://feed.invalid/exact").text == "0123456789"
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream([b"0123456789X"]))
    with pytest.raises(ValueError):
        conn_mod._read_capped("GET", "https://feed.invalid/over")


def test_connector_oversized_feed_degrades_gracefully(client, auth, monkeypatch):
    """End-to-end: a JSON connector whose feed streams past the cap records an
    error and status='error' — the run API returns cleanly, never crashes."""
    monkeypatch.setattr(conn_mod, "_MAX_FEED_BYTES", 2048)
    big = [b"y" * 4096]  # one 4 KB chunk, over the 2 KB cap
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream(big))

    c = client.post("/connectors", json={
        "name": "Flood Feed", "kind": "json", "url": "https://feed.invalid/flood",
        "field_map": {"value": "indicator", "type": "kind"}}, headers=auth)
    cid = c.json()["id"]
    run = client.post(f"/connectors/{cid}/run", headers=auth).json()
    assert "error" in run["result"]
    assert run["connector"]["status"] == "error"
    assert "exceeds" in (run["connector"].get("last_error") or run["result"]["error"])


# ── Malformed-record tolerance: one bad row must not discard a whole feed ──────

@pytest.mark.parametrize("raw,expected", [
    (75, 75), ("75", 75), ("75.0", 75), ("75%", 75), (75.9, 75),
    (None, 50), ("", 50), ("high", 50), ("n/a", 50), ({}, 50),
    (-5, 0), (250, 100), ("120", 100),
])
def test_to_confidence_coerces_messy_feed_values(raw, expected):
    assert conn_mod._to_confidence(raw) == expected


def test_to_confidence_honours_default():
    assert conn_mod._to_confidence(None, default=60) == 60
    assert conn_mod._to_confidence("junk", default=60) == 60
    assert conn_mod._to_confidence("42", default=60) == 42


def _fake_resp(data=None, text=""):
    class _R:
        def __init__(self):
            self.text = text
        def json(self):
            return data
    return _R()


def test_json_feed_bad_confidence_does_not_lose_the_feed(client, auth, monkeypatch):
    """A record whose confidence is non-numeric ('high') must still import — with
    the default confidence — instead of aborting the whole feed with a ValueError."""
    payload = {"data": [
        {"indicator": "192.0.2.171", "kind": "ip", "conf": "high"},   # junk conf
        {"indicator": "192.0.2.172", "kind": "ip", "conf": "82%"},    # percent
        {"indicator": "192.0.2.173", "kind": "ip", "conf": None},     # null
    ]}
    monkeypatch.setattr(conn_mod, "_http_get",
                        lambda url, headers=None, params=None: _fake_resp(data=payload))
    c = client.post("/connectors", json={
        "name": "Messy Feed", "kind": "json", "url": "https://feed.invalid/messy",
        "field_map": {"value": "indicator", "type": "kind", "confidence": "conf"}}, headers=auth)
    run = client.post(f"/connectors/{c.json()['id']}/run", headers=auth).json()
    assert run["connector"]["status"] == "ok"
    # All three survived parsing (none aborted the batch); total is the
    # parse-produced count, deterministic regardless of prior dedup state.
    assert run["result"]["total"] == 3
    assert run["result"]["skipped"] == 0
    # The "82%" record coerced to 82 (proves the percent path).
    hit = client.get("/cti/lookup?value=192.0.2.172", headers=auth).json()
    assert hit["found"] and hit["confidence"] == 82


def test_json_feed_non_dict_rows_are_skipped(client, auth, monkeypatch):
    """A feed array containing junk (strings, null) alongside real records imports
    the real ones and skips the junk, rather than crashing the parse."""
    payload = ["not-a-dict", None, 42,
               {"indicator": "192.0.2.181", "kind": "ip"}]
    monkeypatch.setattr(conn_mod, "_http_get",
                        lambda url, headers=None, params=None: _fake_resp(data=payload))
    c = client.post("/connectors", json={
        "name": "Junky Feed", "kind": "json", "url": "https://feed.invalid/junky",
        "field_map": {"value": "indicator", "type": "kind"}}, headers=auth)
    run = client.post(f"/connectors/{c.json()['id']}/run", headers=auth).json()
    assert run["connector"]["status"] == "ok"
    # Only the one dict row is parsed; the 3 junk elements are dropped, not
    # crashed. `total` is the parse count (deterministic vs. DB dedup state).
    assert run["result"]["total"] == 1
