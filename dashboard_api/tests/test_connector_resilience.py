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
