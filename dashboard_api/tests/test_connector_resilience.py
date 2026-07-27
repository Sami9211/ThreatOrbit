"""Connector feed resilience: a huge/hostile/buggy feed response must not be
buffered unboundedly (memory-exhaustion DoS), and a connector that trips the
cap degrades gracefully - it records the error and never crashes the API.

A SIEM's threat-intel connectors fetch attacker-adjacent, third-party URLs on a
schedule. `httpx.get()`/`.post()` read the whole body into memory before
`.json()`/`.text`, so a compromised or misbehaving feed returning a multi-GB
dump would OOM the dashboard. `_read_capped` streams and rejects past
`_MAX_FEED_BYTES`; `run_connector` catches the resulting ValueError.
"""
import json
import os
import uuid

import pytest

import dashboard_api.connectors as conn_mod


class _FakeStream:
    """Stand-in for the context manager `httpx.stream(...)` returns."""

    def __init__(self, chunks: list[bytes], ok: bool = True, redirect_to: str | None = None,
                 status_code: int | None = None):
        self._chunks = chunks
        self._ok = ok
        self.is_redirect = redirect_to is not None
        self.headers = {"location": redirect_to} if redirect_to else {}
        # Real httpx responses always carry a status code; _read_capped reads it
        # to detect a 304 (conditional GET). Model it so the double stays honest.
        self.status_code = status_code if status_code is not None else (
            302 if redirect_to else (200 if ok else 500))

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


def test_threatorbit_fetch_pages_full_corpus(monkeypatch):
    """The bundled OSINT engine connector must page through /iocs (which caps
    limit at 1000/request but supports offset), not stop at the first page -
    otherwise our own engine looks weaker than it is, capped at 1000 indicators
    per sync while the store holds far more."""
    total = 2300
    store = [{"ioc_type": "ip", "value": f"198.51.{i // 256}.{i % 256}",
              "confidence": 70, "source": "abuse.ch"} for i in range(total)]

    class _R:
        def __init__(self, d):
            self._d = d

        def json(self):
            return self._d

    seen = []

    def fake_get(url, headers=None, params=None):
        off, lim = params["offset"], params["limit"]
        seen.append((off, lim))
        return _R(store[off:off + lim])

    monkeypatch.setattr(conn_mod, "_http_get", fake_get)
    out = conn_mod._fetch_threatorbit({})
    assert len(out) == total, f"only pulled {len(out)} of {total} indicators"
    assert seen[0] == (0, 1000) and seen[1] == (1000, 1000)   # offset advances
    assert len(seen) == 3                                      # 1000+1000+300 -> stops on short page


def test_registering_companion_engine_allowed_but_ssrf_still_blocked():
    """Registering the bundled OSINT engine must not be blocked by the SSRF guard.

    THREAT_API_URL is operator configuration (loopback on every non-cloud
    install), and syncing it is already allowed at send time - so create/update
    must use the SAME companion allowance, or the bundled connector can never be
    registered ("URL resolves to a private or reserved address"). The allowance
    is narrow: any OTHER private/reserved target is still refused.
    """
    from dashboard_api.config import THREAT_API_URL
    from dashboard_api.net_guard import UnsafeUrlError

    # conftest sets DASHBOARD_ALLOW_PRIVATE_URLS=true so the webhook tests can
    # post to a local sink. Clear it here so this exercises the REAL production
    # posture (the flag is read per call, so scoping it is enough).
    prev = os.environ.pop("DASHBOARD_ALLOW_PRIVATE_URLS", None)
    try:
        # The deployment's own companion service - allowed, base and sub-path.
        conn_mod.validate_feed_url(THREAT_API_URL)
        conn_mod.validate_feed_url(THREAT_API_URL + "/iocs")

        # Everything else private/reserved is still blocked - the guard still guards.
        for bad in ("http://169.254.169.254/latest/meta-data/",   # cloud metadata
                    "http://127.0.0.1:9999/steal",                # other loopback port
                    "http://10.0.0.5/internal",                   # private range
                    "http://192.168.1.1/admin"):
            with pytest.raises(UnsafeUrlError):
                conn_mod.validate_feed_url(bad)
    finally:
        if prev is not None:
            os.environ["DASHBOARD_ALLOW_PRIVATE_URLS"] = prev


def test_connector_cadence_supports_seconds_and_floors():
    """Connector cadence is configurable in SECONDS (sub-minute polling), with a
    floor so a misconfigured connector can't hammer a third-party feed. Rows
    predating interval_seconds fall back to the legacy interval_minutes."""
    assert conn_mod.connector_interval_seconds({"interval_seconds": 30}) == 30
    # legacy row (no seconds) -> minutes * 60
    assert conn_mod.connector_interval_seconds({"interval_minutes": 2}) == 120
    assert conn_mod.connector_interval_seconds({"interval_seconds": 0, "interval_minutes": 5}) == 300
    # floor protects the upstream feed
    assert conn_mod.connector_interval_seconds({"interval_seconds": 1}) == conn_mod.MIN_INTERVAL_SECONDS
    # nothing set at all -> the 60-minute default, not zero (which would spin)
    assert conn_mod.connector_interval_seconds({}) == 3600


def test_stuck_running_connector_is_recovered_and_runs_again(monkeypatch):
    """A service killed mid-sync leaves status='running'. run_due_connectors skips
    'running' rows so the connector would never sync again and the UI would show a
    permanent "sync in progress". Startup recovery must clear it."""
    from dashboard_api.db import get_conn as real_get_conn

    cid = "stuck-" + uuid.uuid4().hex[:8]
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','running',0,?)",
            (cid, "Stuck Feed", "json", "https://example.test/feed", conn_mod._now()))
        c.commit()
    try:
        recovered = conn_mod.reset_stuck_connectors()
        assert recovered >= 1
        with real_get_conn() as c:
            row = c.execute("SELECT status, last_error FROM connectors WHERE id=?", (cid,)).fetchone()
        assert row["status"] == "idle"
        assert "restarted" in (row["last_error"] or "").lower()   # honest about why
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connectors WHERE id=?", (cid,)); c.commit()


def test_connector_sync_appears_in_import_history_end_to_end(monkeypatch):
    """END-TO-END: a connector sync must land indicators AND show up in the
    Feeds → Import history.

    This is the gap that made the product look broken for days: `ioc_imports`
    (what the Import page reads) was written ONLY by the manual/MISP routes, so
    a connector could pull thousands of real indicators and the import log stayed
    empty - "nothing shows up at imports" with no way to tell why.
    """
    from dashboard_api.db import get_conn as real_get_conn

    feed = [{"type": "ip", "value": "203.0.113.201", "confidence": 70},
            {"type": "domain", "value": "e2e-import-check.test", "confidence": 70},
            {"type": "ip", "value": "203.0.113.201", "confidence": 70}]   # dup in batch
    monkeypatch.setitem(conn_mod._FETCHERS, "json", lambda c: feed)

    cid = "e2e-" + uuid.uuid4().hex[:8]
    name = "E2E Feed " + cid
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','idle',0,?)",
            (cid, name, "json", "https://example.test/feed", conn_mod._now()))
        c.commit()
    try:
        with real_get_conn() as c:
            row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
        res = conn_mod.run_connector(row, actor="tester")
        assert res.get("imported") == 2 and res.get("duplicates") == 1, res

        with real_get_conn() as c:
            # 1. the indicators are really in the store
            got = c.execute("SELECT COUNT(*) AS n FROM iocs WHERE source=?", (name,)).fetchone()["n"]
            assert got == 2, f"indicators not stored (found {got})"
            # 2. the sync is visible in the IMPORT history, with real counts
            imp = c.execute(
                "SELECT * FROM ioc_imports WHERE source=? ORDER BY ts DESC", (name,)).fetchone()
            assert imp is not None, "connector sync missing from import history"
            assert imp["imported"] == 2 and imp["duplicates"] == 1
            assert imp["method"] == "connector:json" and imp["status"] == "completed"
            # 3. and as a job (the Imports page pipeline view)
            assert c.execute("SELECT COUNT(*) AS n FROM jobs WHERE kind=?",
                             ("connector.json",)).fetchone()["n"] >= 1
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE source=?", (name,))
            c.execute("DELETE FROM ioc_imports WHERE source=?", (name,))
            c.execute("DELETE FROM connectors WHERE id=?", (cid,))
            c.commit()


def test_failed_connector_sync_is_visible_in_import_history(monkeypatch):
    """A sync that FAILS must appear in the import log with the error - silence is
    what made 'nothing shows up at imports' undiagnosable."""
    from dashboard_api.db import get_conn as real_get_conn

    def boom(c):
        raise ValueError("URL resolves to a private or reserved address (feed.test -> 0.0.0.0)")
    monkeypatch.setitem(conn_mod._FETCHERS, "json", boom)

    cid = "e2ef-" + uuid.uuid4().hex[:8]
    name = "E2E Fail " + cid
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','idle',0,?)",
            (cid, name, "json", "https://feed.test/x", conn_mod._now()))
        c.commit()
    try:
        with real_get_conn() as c:
            row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
        res = conn_mod.run_connector(row, actor="tester")
        assert "error" in res
        with real_get_conn() as c:
            imp = c.execute("SELECT * FROM ioc_imports WHERE source=?", (name,)).fetchone()
            assert imp is not None, "failed sync missing from import history"
            assert imp["status"] == "failed" and imp["imported"] == 0
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM ioc_imports WHERE source=?", (name,))
            c.execute("DELETE FROM connectors WHERE id=?", (cid,))
            c.commit()


def test_abusech_connector_parses_real_blocklist_shape(monkeypatch):
    """The keyless abuse.ch Feodo connector turns the public C2 blocklist into
    indicators. This is the connector that gives a fresh install REAL threat
    intel on first sync - no API key, no URL, no companion service - so the
    dashboard is never dependent on the SIMULATED engine for data."""
    sample = [
        {"ip_address": "45.142.212.61", "port": 443, "status": "online",
         "malware": "Emotet", "first_seen": "2026-07-01 10:00:00",
         "last_online": "2026-07-24"},
        {"ip_address": "185.99.133.72", "malware": "QakBot"},
        {"ip_address": "", "malware": "Junk"},          # skipped: no value
        "not-a-dict",                                    # skipped: malformed
    ]

    class _R:
        def json(self): return sample

    monkeypatch.setattr(conn_mod, "_http_get", lambda url, **kw: _R())
    out = conn_mod._fetch_abusech({})
    assert [o["value"] for o in out] == ["45.142.212.61", "185.99.133.72"]
    assert all(o["type"] == "ip" and o["source"] == "abuse.ch:feodo" for o in out)
    assert "Emotet" in out[0]["threat_type"] and out[0]["actor"] == "Emotet"
    assert out[0]["confidence"] == 90

    # Still runnable for connectors created before the engine absorbed these
    # feeds, but no longer offered as a separate kind in the UI.
    assert conn_mod._FETCHERS["abusech"] is conn_mod._fetch_abusech
    assert "abusech" not in conn_mod.KIND_PRESETS


def test_bulk_osint_parsers_handle_real_feed_formats():
    """Parsers for the keyless bulk feeds, against their real on-the-wire shapes."""
    # blocklist.de / CINS / ET / Tor: plain list with comments and trailing notes
    ips = conn_mod._p_iplist(
        "# CINS Army list\n\n1.2.3.4\n5.6.7.8   # noisy scanner\n;comment\n9.9.9.9\n")
    assert [v for v, _ in ips] == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]

    # ThreatFox CSV: first_seen,ioc_id,ioc_value,ioc_type,threat_type,...,malware
    tf = conn_mod._p_threatfox(
        '# comment line\n'
        '"2026-07-20","123","45.61.2.9:8080","ip:port","botnet_cc","x","y","Emotet"\n'
        '"2026-07-20","124","bad-c2.example","domain","botnet_cc","x","y","QakBot"\n')
    assert tf[0][0] == "45.61.2.9" and tf[0][1] == "Emotet"      # host:port -> host
    assert tf[1][0] == "bad-c2.example"

    # URLhaus CSV: id,dateadded,url,url_status,last_online,threat,...
    uh = conn_mod._p_urlhaus(
        '# id,dateadded,url,url_status\n'
        '"1","2026-07-20","http://evil.test/payload.bin","online","","malware_download"\n'
        '"2","2026-07-20","not-a-url","online","","x"\n')
    assert [v for v, _ in uh] == ["http://evil.test/payload.bin"]
    assert uh[0][1] == "malware_download"


def test_bulk_osint_is_parallel_and_survives_a_dead_feed(monkeypatch):
    """Volume is the point: all feeds are pulled together, and ONE dead feed must
    never zero out the sync (the old single-source engine produced ~5 indicators
    precisely because everything hung off one upstream)."""
    calls = []

    class _R:
        def __init__(self, t): self.text = t

    def fake_get(url, **kw):
        calls.append(url)
        if "cinsscore" in url:
            raise ValueError("feed unreachable")          # one dead source
        if "threatfox" in url:
            return _R('"2026","1","203.0.113.9:443","ip:port","botnet_cc","x","y","Emotet"\n')
        if "urlhaus" in url:
            return _R('"1","2026","http://bad.test/x.exe","online","","malware_download"\n')
        return _R("198.51.100.7\n198.51.100.8\n")          # plain IP lists

    monkeypatch.setattr(conn_mod, "_http_get", fake_get)
    out = conn_mod._fetch_bulk_osint({})

    assert len(calls) == len(conn_mod._BULK_FEEDS), "every feed must be attempted"
    values = {o["value"] for o in out}
    assert "203.0.113.9" in values and "http://bad.test/x.exe" in values
    assert "198.51.100.7" in values
    assert out, "a single dead feed must not zero the sync"
    assert all(o["source"].startswith("osint:") for o in out)
    # The aggregator is what the bundled engine runs; it is no longer a separate
    # UI kind, but the fetcher stays available for pre-existing connectors.
    assert conn_mod._FETCHERS["osint"] is conn_mod._fetch_bulk_osint
    assert "osint" not in conn_mod.KIND_PRESETS
    engine = conn_mod.KIND_PRESETS["threatorbit"]
    assert engine["needs_key"] is False and engine["needs_url"] is False


def test_engine_loop_still_renews_leader_lease_when_synthetic_disabled():
    """REGRESSION FENCE. The engine loop doubles as the HA leader-lease renewer,
    and `_connector_scheduler` refuses to sync anything unless a replica holds
    that lease. Returning early from the loop when synthetic generation is
    disabled therefore stopped EVERY connector from auto-syncing - the operator
    had to press "Sync now" by hand. The loop must keep running and gate only
    the generation call.
    """
    import inspect

    import dashboard_api.main as main_mod
    src = inspect.getsource(main_mod._engine_loop)

    # The leader lease must still be acquired/renewed on every tick.
    assert "leader.acquire()" in src
    # And generation must be gated INSIDE the loop, not by an early return.
    gate = src.index("SYNTHETIC_ALLOWED")
    loop = src.index("while True:")
    early_return = src[:loop].count("\n        return")
    assert early_return == 0, "engine loop returns before the leader lease is renewed"
    assert "and SYNTHETIC_ALLOWED" in src, "generation must be gated inside the loop"
    assert gate < len(src)


def test_connector_cadence_allows_one_second():
    """A 1-second cadence must survive a save. The floor used to be 5s, so setting
    1s silently snapped back to 5s."""
    assert conn_mod.MIN_INTERVAL_SECONDS <= 1
    assert conn_mod.connector_interval_seconds({"interval_seconds": 1}) == 1


def test_bulk_osint_uses_conditional_fetch_and_skips_unchanged_feeds(monkeypatch):
    """Incremental sync, OpenCTI's "connector state" idea applied to blocklists.

    These feeds have no cursor, but they serve HTTP validators. Storing
    ETag/Last-Modified per feed lets a re-sync send a conditional request: an
    unchanged feed answers 304 with no body, so there is nothing to download,
    parse or dedup. Without this, a 1-second cadence re-pulls tens of thousands
    of identical rows every tick.
    """
    seen_headers = {}

    class _R:
        def __init__(self, text="", not_modified=False, headers=None):
            self.text = text
            self.not_modified = not_modified
            self.headers = headers or {}

    # --- first sync: no state, everything is fetched and returns validators ---
    def fresh(url, headers=None, **kw):
        seen_headers[url] = headers
        return _R("198.51.100.1\n198.51.100.2\n", headers={"etag": f'W/"{url[-8:]}"'})

    monkeypatch.setattr(conn_mod, "_http_get", fresh)
    first = conn_mod._fetch_bulk_osint({})
    assert first, "first sync must import"
    assert all(h in (None, {}) for h in seen_headers.values()), "no validators on a cold sync"
    state = conn_mod._fetch_bulk_osint.last_state
    assert len(state) == len(conn_mod._BULK_FEEDS), "every feed must record its validator"

    # --- second sync: state present -> conditional request -> 304 -> no work ---
    conditional = {}

    def not_modified(url, headers=None, **kw):
        conditional[url] = headers
        return _R(not_modified=True)

    monkeypatch.setattr(conn_mod, "_http_get", not_modified)
    second = conn_mod._fetch_bulk_osint({"state": state})
    assert second == [], "an unchanged feed must produce no indicators to re-ingest"
    assert conditional, "second sync must issue requests"
    for url, hdrs in conditional.items():
        assert hdrs and "If-None-Match" in hdrs, f"no conditional header sent for {url}"
    # The validators survive so the NEXT sync is conditional too.
    assert conn_mod._fetch_bulk_osint.last_state == state


def test_bulk_osint_keeps_state_when_a_feed_errors(monkeypatch):
    """A transient failure must not discard a good validator - otherwise the next
    sync silently falls back to a full re-download."""
    class _R:
        def __init__(self): self.text = "203.0.113.5\n"; self.not_modified = False; self.headers = {}

    good = {u: {"etag": '"keep-me"'} for (_n, u, *_r) in conn_mod._BULK_FEEDS}

    def flaky(url, headers=None, **kw):
        raise ValueError("temporary upstream failure")

    monkeypatch.setattr(conn_mod, "_http_get", flaky)
    conn_mod._fetch_bulk_osint({"state": good})
    assert conn_mod._fetch_bulk_osint.last_state == good, "validators lost on a transient error"


def test_threatorbit_engine_aggregates_feeds_itself(monkeypatch):
    """The bundled engine must BE the OSINT source, not a proxy to one.

    It previously only re-served whatever the companion threat service held - a
    second-hand path to a near-empty store, which is why the "engine" imported ~5
    indicators (or none) while presenting itself as the platform's own source.
    It now aggregates the public feeds directly, and the companion is an optional
    extra that cannot zero the sync when it is down.
    """
    class _R:
        def __init__(self, text="", js=None):
            self.text = text
            self.not_modified = False
            self.headers = {}
            self._js = js

        def json(self):
            if self._js is None:
                raise ValueError("companion unavailable")
            return self._js

    def only_public_feeds(url, headers=None, **kw):
        if "/iocs" in url:                       # the companion service is DOWN
            raise ValueError("connection refused")
        return _R("198.51.100.10\n198.51.100.11\n")

    monkeypatch.setattr(conn_mod, "_http_get", only_public_feeds)
    out = conn_mod._fetch_threatorbit({})
    assert len(out) > 0, "engine must import from public feeds with no companion"
    assert all(o["source"].startswith("osint:") for o in out)
    # Incremental state is carried through the engine, not lost.
    assert isinstance(getattr(conn_mod._fetch_threatorbit, "last_state", None), dict)

    # With the companion UP, its indicators are ADDED on top of the public feeds.
    def both(url, headers=None, **kw):
        if "/iocs" in url:
            return _R(js=[{"ioc_type": "ip", "value": "203.0.113.77",
                           "confidence": 80, "source": "abuse.ch"}])
        return _R("198.51.100.10\n")

    monkeypatch.setattr(conn_mod, "_http_get", both)
    out2 = conn_mod._fetch_threatorbit({})
    values = {o["value"] for o in out2}
    assert "198.51.100.10" in values and "203.0.113.77" in values


def test_retired_connector_kinds_still_run_but_are_hidden():
    """Folding the bulk feeds into the engine must not break connectors an
    operator already created: the kinds keep working, they are just no longer
    offered in the Add-connector catalogue."""
    assert "osint" not in conn_mod.KIND_PRESETS
    assert "abusech" not in conn_mod.KIND_PRESETS
    assert "osint" in conn_mod._FETCHERS and "abusech" in conn_mod._FETCHERS
    assert "threatorbit" in conn_mod.KIND_PRESETS


def test_otx_pulse_becomes_a_report_with_attribution_and_ttps(monkeypatch):
    """The AlienVault model: a pulse is a REPORT, and indicators belong to it.

    OTX is not "some public source" - its unit of intelligence carries the
    adversary, malware families, MITRE ATT&CK techniques, targeting and the
    source reporting. Importing only the bare values (what this platform used to
    do) throws away everything that makes the intel actionable: an analyst could
    not ask what campaign an IP belonged to, who is behind it, or where the
    reporting came from.
    """
    pulse = {
        "id": "pulse-abc123",
        "name": "APT-X spearphishing infrastructure",
        "description": "Infrastructure used in a 2026 campaign.",
        "TLP": "green",
        "author_name": "researcher1",
        "created": "2026-07-01T10:00:00",
        "modified": "2026-07-20T10:00:00",
        "adversary": "APT-X",
        "malware_families": ["PlugX", "ShadowPad"],
        "attack_ids": [{"id": "T1566"}, "T1071"],       # OTX mixes both shapes
        "references": ["https://vendor.example/report-apt-x"],
        "targeted_countries": ["Germany"],
        "industries": ["Energy"],
        "tags": ["apt", "spearphishing"],
        "indicators": [
            {"type": "IPv4", "indicator": "203.0.113.44", "created": "2026-07-01T10:00:00"},
            {"type": "domain", "indicator": "apt-x-c2.example"},
        ],
    }

    class _R:
        def json(self): return {"results": [pulse], "next": None}

    monkeypatch.setattr(conn_mod, "_http_get", lambda url, **kw: _R())
    indicators = conn_mod._fetch_otx({"api_key": "k"})

    # The pulse context is emitted, not discarded.
    reports = conn_mod._fetch_otx.last_reports
    assert len(reports) == 1
    r = reports[0]
    assert r["external_id"] == "pulse-abc123" and r["tlp"] == "green"
    assert r["adversary"] == "APT-X"
    assert r["malware_families"] == ["PlugX", "ShadowPad"]
    assert sorted(r["attack_ids"]) == ["T1071", "T1566"]      # both shapes normalised
    assert r["references"] == ["https://vendor.example/report-apt-x"]
    assert r["targeted_countries"] == ["Germany"] and r["industries"] == ["Energy"]

    # Indicators carry attribution and point back at their pulse.
    assert {i["value"] for i in indicators} == {"203.0.113.44", "apt-x-c2.example"}
    assert all(i["actor"] == "APT-X" for i in indicators)
    assert all(i["report_external_id"] == "pulse-abc123" for i in indicators)

    # And the report actually persists, with the indicators linked to it.
    from dashboard_api.db import get_conn as real_get_conn
    ids = conn_mod.upsert_intel_reports(reports, "otx")
    rid = ids["pulse-abc123"]
    try:
        for i in indicators:
            i["report_id"] = rid
        res = conn_mod.import_indicators(indicators, "otx-test")
        assert res["imported"] == 2, res
        with real_get_conn() as c:
            row = c.execute("SELECT * FROM intel_reports WHERE id=?", (rid,)).fetchone()
            assert row["tlp"] == "green" and "APT-X" in row["actors"]
            assert "T1566" in row["attack_ids"] and "PlugX" in row["malware_families"]
            assert "vendor.example" in row["source_refs"]
            linked = c.execute("SELECT COUNT(*) AS n FROM iocs WHERE report_id=?", (rid,)).fetchone()["n"]
            assert linked == 2, "indicators must be linked back to their pulse"

        # Re-syncing the same pulse UPDATES it (pulses are revised upstream).
        reports[0]["title"] = "APT-X spearphishing infrastructure (rev 2)"
        again = conn_mod.upsert_intel_reports(reports, "otx")
        assert again["pulse-abc123"] == rid, "a revised pulse must not duplicate"
        with real_get_conn() as c:
            assert "rev 2" in c.execute(
                "SELECT title FROM intel_reports WHERE id=?", (rid,)).fetchone()["title"]
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE report_id=?", (rid,))
            c.execute("DELETE FROM intel_reports WHERE id=?", (rid,))
            c.commit()


def test_imported_pulse_populates_the_actor_library_and_ttps():
    """Imported attribution must reach the actor library and ATT&CK coverage.

    A pulse names an adversary and the malware/techniques/industries seen with
    it. That used to die as a text string on the indicator, so the Actors page
    and the ATT&CK navigator only ever reflected curated seed data and learned
    nothing from real imports. Multiple pulses about the same actor must ACCUMULATE
    (union), never overwrite - intel arrives in fragments.
    """
    from dashboard_api.db import get_conn as real_get_conn

    actor = "APT-Merge-Test-" + uuid.uuid4().hex[:6]
    p1 = {"adversary": actor, "title": "campaign one",
          "attack_ids": ["T1566"], "malware_families": ["PlugX"],
          "industries": ["Energy"], "created": "2026-07-01T00:00:00",
          "modified": "2026-07-01T00:00:00"}
    p2 = {"adversary": actor, "title": "campaign two",
          "attack_ids": ["T1071", "T1566"],            # one new, one repeat
          "malware_families": ["ShadowPad"],
          "industries": ["Finance"], "modified": "2026-07-20T00:00:00"}
    try:
        with real_get_conn() as c:
            aid = conn_mod.upsert_actor_from_pulse(c, p1)
            c.commit()
        assert aid
        with real_get_conn() as c:
            aid2 = conn_mod.upsert_actor_from_pulse(c, p2)
            c.commit()
        assert aid2 == aid, "the same adversary must not create a second actor"

        with real_get_conn() as c:
            row = c.execute("SELECT * FROM threat_actors WHERE id=?", (aid,)).fetchone()
        ttps = json.loads(row["ttps"])
        malware = json.loads(row["malware"])
        sectors = json.loads(row["sectors"])
        assert sorted(ttps) == ["T1071", "T1566"], f"TTPs must union, got {ttps}"
        assert sorted(malware) == ["PlugX", "ShadowPad"]
        assert sorted(sectors) == ["Energy", "Finance"]
        assert row["active"] == 1
        assert "campaign two" in (row["recent_activity"] or "")
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM threat_actors WHERE name=?", (actor,))
            c.commit()


def test_pulse_without_an_adversary_creates_no_actor():
    """Most bulk feed entries have no attribution. They must not manufacture a
    nameless actor - fabricating attribution is worse than having none."""
    from dashboard_api.db import get_conn as real_get_conn
    with real_get_conn() as c:
        before = c.execute("SELECT COUNT(*) AS n FROM threat_actors").fetchone()["n"]
        assert conn_mod.upsert_actor_from_pulse(c, {"title": "no attribution"}) is None
        assert conn_mod.upsert_actor_from_pulse(c, {"adversary": "   "}) is None
        after = c.execute("SELECT COUNT(*) AS n FROM threat_actors").fetchone()["n"]
    assert before == after
