"""Connector feed resilience: a huge/hostile/buggy feed response must not be
buffered unboundedly (memory-exhaustion DoS), and a connector that trips the
cap degrades gracefully - it records the error and never crashes the API.

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

    def __init__(self, chunks: list[bytes], ok: bool = True, redirect_to: str | None = None):
        self._chunks = chunks
        self._ok = ok
        self.is_redirect = redirect_to is not None
        self.headers = {"location": redirect_to} if redirect_to else {}

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
    """A body larger than the cap raises ValueError mid-stream - it is never
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


def test_read_capped_follows_a_safe_redirect(monkeypatch):
    """A redirect to another public host is followed (one hop), and the final
    body is what's returned - the common CDN / http->https feed-hosting case."""
    payload = b'{"data": []}'
    calls = []

    def fake_stream(method, url, **kwargs):
        calls.append(url)
        if url == "https://feed.invalid/old":
            return _FakeStream([], redirect_to="https://feed.invalid/new")
        return _FakeStream([payload])

    monkeypatch.setattr(conn_mod.httpx, "stream", fake_stream)
    resp = conn_mod._read_capped("GET", "https://feed.invalid/old")
    assert resp.text == payload.decode()
    assert calls == ["https://feed.invalid/old", "https://feed.invalid/new"]


def test_read_capped_drops_params_after_a_redirect(monkeypatch):
    """The original request's `params`/`json` must not be resent on a redirect
    hop - the Location URL is already the fully-resolved target, so replaying
    the first request's query params on top of it (e.g. NVD's `resultsPerPage`)
    would let httpx append a stale/duplicate query string onto whatever the
    redirect target expects. `headers` (auth) still carry over."""
    seen_kwargs = []

    def fake_stream(method, url, **kwargs):
        seen_kwargs.append(kwargs)
        if url == "https://feed.invalid/old":
            return _FakeStream([], redirect_to="https://feed.invalid/new")
        return _FakeStream([b'{}'])

    monkeypatch.setattr(conn_mod.httpx, "stream", fake_stream)
    conn_mod._read_capped("GET", "https://feed.invalid/old",
                          headers={"Authorization": "Bearer x"}, params={"resultsPerPage": 100})
    assert seen_kwargs[0]["params"] == {"resultsPerPage": 100}
    assert "params" not in seen_kwargs[1]                       # not resent on the redirect hop
    assert seen_kwargs[1]["headers"] == {"Authorization": "Bearer x"}  # auth still carries over


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # cloud metadata
    "http://127.0.0.1:8002/config/api-keys",                              # loopback
    "http://10.0.0.5/internal-admin",                                     # RFC1918 private
])
def test_read_capped_blocks_redirect_to_internal_target(monkeypatch, target):
    """The core regression: a feed URL that validates fine right now (a public
    host) must not be able to 302 the dashboard into fetching an internal or
    cloud-metadata target instead. `httpx`'s own `follow_redirects=True` would
    chase this Location header with zero visibility to the SSRF guard - this
    locks in that every hop is re-validated, not just the first one.

    conftest sets DASHBOARD_ALLOW_PRIVATE_URLS=true so webhook-delivery tests
    can target a local sink; override it back to strict here, same as
    test_net_guard.py's allow_private=False, so this test asserts real
    production blocking behaviour rather than the test env's escape hatch."""
    monkeypatch.setenv("DASHBOARD_ALLOW_PRIVATE_URLS", "false")

    def fake_stream(method, url, **kwargs):
        if url == "https://feed.invalid/bait":
            return _FakeStream([], redirect_to=target)
        raise AssertionError(f"must never actually connect to the redirect target: {url}")

    monkeypatch.setattr(conn_mod.httpx, "stream", fake_stream)
    from dashboard_api.net_guard import UnsafeUrlError
    with pytest.raises(UnsafeUrlError):
        conn_mod._read_capped("GET", "https://feed.invalid/bait")


def test_read_capped_caps_redirect_chain_length(monkeypatch):
    """A redirect loop / excessively long chain must not hang forever."""
    def fake_stream(method, url, **kwargs):
        n = int(url.rsplit("/", 1)[-1])
        return _FakeStream([], redirect_to=f"https://feed.invalid/hop/{n + 1}")

    monkeypatch.setattr(conn_mod.httpx, "stream", fake_stream)
    with pytest.raises(ValueError, match="too many redirects"):
        conn_mod._read_capped("GET", "https://feed.invalid/hop/0")


def test_connector_oversized_feed_degrades_gracefully(client, auth, monkeypatch):
    """End-to-end: a JSON connector whose feed streams past the cap records an
    error and status='error' - the run API returns cleanly, never crashes."""
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


# -- Malformed-record tolerance: one bad row must not discard a whole feed ------

@pytest.mark.parametrize("raw,expected", [
    (75, 75), ("75", 75), ("75.0", 75), ("75%", 75), (75.9, 75),
    (None, 50), ("", 50), ("high", 50), ("n/a", 50), ({}, 50),
    (-5, 0), (250, 100), ("120", 100),
    # Non-finite / overflow inputs must fall back, not raise OverflowError -
    # int(float("inf")) throws, which would otherwise abort the whole import.
    ("inf", 50), ("Infinity", 50), ("-inf", 50), ("nan", 50), ("1e999", 50),
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
    """A record whose confidence is non-numeric ('high') must still import - with
    the default confidence - instead of aborting the whole feed with a ValueError."""
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


# -- Companion-service exemption (bundled OSINT connector) ------------------------

def test_companion_threat_api_url_passes_ssrf_guard(monkeypatch):
    """The bundled OSINT connector targets THREAT_API_URL - operator-set
    deployment config that is loopback/private on every non-cloud install. The
    send-time SSRF guard used to block it ("URL resolves to a private or
    reserved address"), which dead-ended the default live install's primary
    intel source. Companion URLs must pass; other private URLs must not."""
    import dashboard_api.connectors as conn_mod

    monkeypatch.setattr(conn_mod, "THREAT_API_URL", "http://127.0.0.1:8000")
    # conftest sets DASHBOARD_ALLOW_PRIVATE_URLS=true for the webhook tests;
    # turn it off here so BOTH arms genuinely assert the guard's behaviour.
    monkeypatch.setenv("DASHBOARD_ALLOW_PRIVATE_URLS", "false")
    calls = {}

    class _Resp:
        status_code = 200
        text = "[]"
        def json(self):
            return []
        def raise_for_status(self):
            return None

    def fake_read(method, url, **kw):
        calls["url"] = url
        return _Resp()

    monkeypatch.setattr(conn_mod, "_read_capped", fake_read)

    # companion base + sub-path: allowed straight through to the request
    conn_mod._http_get("http://127.0.0.1:8000/iocs", params={"limit": 5})
    assert calls["url"] == "http://127.0.0.1:8000/iocs"

    # any OTHER private target is still blocked at send time
    from dashboard_api.net_guard import UnsafeUrlError
    import pytest
    with pytest.raises(UnsafeUrlError):
        conn_mod._http_get("http://127.0.0.1:9999/steal")
    with pytest.raises(UnsafeUrlError):
        conn_mod._http_get("http://169.254.169.254/latest/meta-data/")


def test_import_uses_bounded_round_trips_not_per_row(monkeypatch):
    """IOC import must scale to enterprise feed volumes: a large batch issues a
    *bounded* number of DB round trips - one bulk INSERT plus a handful of
    chunked existence probes - never a SELECT + INSERT per indicator. This fences
    the O(N)-round-trip regression that would cap throughput far below the
    thousands-of-indicators/second an OTX-class feed demands.
    """
    import contextlib
    import math

    from dashboard_api.db import get_conn as real_get_conn

    calls = {"execute_insert": 0, "existence_probe": 0, "executemany_insert": 0}

    class _CountingConn:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, params=()):
            s = " ".join(sql.split()).upper()
            if s.startswith("INSERT INTO IOCS"):
                calls["execute_insert"] += 1        # per-row insert = the regression
            elif s.startswith("SELECT VALUE FROM IOCS WHERE VALUE IN"):
                calls["existence_probe"] += 1
            return self._inner.execute(sql, params)

        def executemany(self, sql, seq):
            if " ".join(sql.split()).upper().startswith("INSERT INTO IOCS"):
                calls["executemany_insert"] += 1    # one bulk insert for the whole batch
            return self._inner.executemany(sql, seq)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    @contextlib.contextmanager
    def _counting_get_conn():
        with real_get_conn() as c:
            yield _CountingConn(c)

    monkeypatch.setattr(conn_mod, "get_conn", _counting_get_conn)

    # More than one existence-probe chunk (_EXISTS_CHUNK == 900) to prove the
    # probe loop stays bounded rather than growing per row.
    n = conn_mod._EXISTS_CHUNK + 200
    src = "batch-perf-fence"
    indicators = [{"type": "domain", "value": f"perf-fence-{i}.example.test"} for i in range(n)]

    try:
        res = conn_mod._import(indicators, src)

        assert res["imported"] == n and res["duplicates"] == 0 and res["skipped"] == 0
        # The whole batch was written with a SINGLE bulk INSERT...
        assert calls["executemany_insert"] == 1
        # ...and NOT one INSERT per indicator.
        assert calls["execute_insert"] == 0
        # Existence checks are chunked: ceil(n / chunk) probes, not n probes.
        expected_probes = math.ceil(n / conn_mod._EXISTS_CHUNK)
        assert calls["existence_probe"] == expected_probes
        assert calls["existence_probe"] < n
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE source=?", (src,))
            c.commit()


def test_otx_fetch_paginates_subscribed_pulses(monkeypatch):
    """OTX sync must walk the paginated subscribed-pulses feed (like OpenCTI's
    connector), not stop after the first page - that is the difference between
    importing a handful of pulses and a full subscribed feed. It stops when the
    API reports no further page, and requires an API key."""
    pages = {
        1: {"results": [{"name": "P1", "tags": ["apt"], "indicators": [
                {"type": "IPv4", "indicator": "203.0.113.1"},
                {"type": "domain", "indicator": "evil-otx.test"}]}],
            "next": "https://otx/api/v1/pulses/subscribed?page=2"},
        2: {"results": [{"name": "P2", "indicators": [
                {"type": "IPv4", "indicator": "203.0.113.2"}]}],
            "next": None},
    }

    class _R:
        def __init__(self, d):
            self._d = d

        def json(self):
            return self._d

    seen_pages = []

    def fake_get(url, headers=None, params=None):
        assert headers.get("X-OTX-API-KEY") == "the-key"      # key, fixed endpoint
        assert url.endswith("/api/v1/pulses/subscribed")
        seen_pages.append(params["page"])
        return _R(pages.get(params["page"], {"results": [], "next": None}))

    monkeypatch.setattr(conn_mod, "_http_get", fake_get)

    out = conn_mod._fetch_otx({"api_key": "the-key"})
    assert {o["value"] for o in out} == {"203.0.113.1", "evil-otx.test", "203.0.113.2"}
    assert seen_pages == [1, 2]                                # page 1 (has next) -> 2 (next None -> stop)

    # No key -> refuses (never a silent empty sync)
    import pytest
    with pytest.raises(ValueError):
        conn_mod._fetch_otx({})


def test_import_indicators_shares_alert_budget_across_subbatches(monkeypatch):
    """A large feed split into sub-batches must still honour the *per-run* SIEM
    alert cap - the budget is shared across sub-batches, not reset each chunk -
    so a big critical-heavy pull can't flood the alert queue."""
    from dashboard_api.db import get_conn as real_get_conn
    import dashboard_api.detections as det

    raised = []
    monkeypatch.setattr(det, "alert_from_intel", lambda conn, **kw: raised.append(kw["value"]))
    monkeypatch.setattr(conn_mod, "_IMPORT_BATCH", 10)        # force multiple sub-batches

    src = "budget-fence"
    inds = [{"type": "ip", "value": f"203.0.113.{i}", "confidence": 95}   # 95 -> critical
            for i in range(25)]
    try:
        res = conn_mod.import_indicators(inds, src)
        assert res["imported"] == 25 and res["skipped"] == 0 and res["duplicates"] == 0
        # 25 criticals across 3 sub-batches, but the per-run cap still holds.
        assert res["alertsRaised"] == conn_mod._MAX_INTEL_ALERTS_PER_RUN
        assert len(raised) == conn_mod._MAX_INTEL_ALERTS_PER_RUN
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE source=?", (src,))
            c.commit()


def test_taxii_client_pulls_and_paginates_collection(monkeypatch):
    """The TAXII 2.1 client connector pulls STIX indicators from a collection's
    objects endpoint, walks the `more`/`next` pagination, and parses each
    indicator with the shared STIX parser (non-indicator objects are skipped)."""
    pages = {
        None: {"objects": [
            {"type": "indicator", "name": "bad-ip",
             "pattern": "[ipv4-addr:value = '203.0.113.7']", "labels": ["malicious"]},
            {"type": "indicator", "name": "bad-domain",
             "pattern": "[domain-name:value = 'evil-taxii.test']"},
            {"type": "malware", "name": "not-an-indicator"}],       # skipped
            "more": True, "next": "cursor-2"},
        "cursor-2": {"objects": [
            {"type": "indicator", "pattern": "[url:value = 'http://bad.test/x']"}],
            "more": False},
    }

    class _R:
        def __init__(self, d):
            self._d = d

        def json(self):
            return self._d

    seen = []

    def fake_get(url, headers=None, params=None):
        assert headers["Accept"].startswith("application/taxii+json")
        assert url.endswith("/objects/")
        seen.append(params.get("next"))
        return _R(pages[params.get("next")])

    monkeypatch.setattr(conn_mod, "_http_get", fake_get)
    url = "https://taxii.example/taxii2/api/collections/abc/objects/"
    out = conn_mod._fetch_taxii({"url": url, "api_key": "Bearer tok"})
    assert {o["value"] for o in out} == {"203.0.113.7", "evil-taxii.test", "http://bad.test/x"}
    assert {o["type"] for o in out} == {"ip", "domain", "url"}
    assert seen == [None, "cursor-2"]        # page 1 (more) -> page 2 (no more -> stop)
    assert all(o["source"] == "taxii" for o in out)

    import pytest
    with pytest.raises(ValueError):
        conn_mod._fetch_taxii({})            # requires the collection URL


def test_taxii_and_stix_registered_and_presented():
    """Both STIX and the new TAXII kind are wired as fetchers and surfaced as
    connector presets (so the Add-connector UI offers TAXII)."""
    assert "taxii" in conn_mod._FETCHERS and "stix" in conn_mod._FETCHERS
    assert conn_mod.KIND_PRESETS["taxii"]["needs_url"] is True
    assert conn_mod.KIND_PRESETS["taxii"]["label"] == "TAXII 2.1 collection"
