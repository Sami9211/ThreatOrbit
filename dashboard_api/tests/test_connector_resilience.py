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
from datetime import datetime, timedelta, timezone

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
            # Real httpx raises HTTPStatusError carrying the response, and the
            # error-description layer reads .response.status_code off it to tell
            # a rejected key from an unreachable host. A bare HTTPError here
            # would let that layer pass a test it could not pass in production.
            raise conn_mod.httpx.HTTPStatusError(
                f"Client error '{self.status_code}' for url 'https://feed.invalid/x'",
                request=conn_mod.httpx.Request("GET", "https://feed.invalid/x"),
                response=conn_mod.httpx.Response(self.status_code))

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
    # Critical because of what the feed says the activity IS. Confidence used to
    # decide severity on its own (95 -> critical); it no longer does, and a test
    # that still leaned on that would be asserting a coupling we deliberately cut.
    inds = [{"type": "ip", "value": f"203.0.113.{i}", "confidence": 95,
             "threat_type": "ransomware"}
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


def test_import_publishes_live_progress_during_a_sync(monkeypatch):
    """Progress must be visible WHILE an import runs, not only after it ends.

    An import used to be atomic: the operator saw nothing until it finished, so a
    large sync in flight was indistinguishable from a hung one. A work row is
    opened up front and updated after every sub-batch, so counts climb live.
    """
    from dashboard_api.db import get_conn as real_get_conn

    # Small sub-batches so a modest fixture produces several progress updates.
    monkeypatch.setattr(conn_mod, "_IMPORT_BATCH", 10)

    tag = uuid.uuid4().hex[:6]
    src = f"work-progress-{tag}"
    inds = [{"type": "ip", "value": f"198.18.{i // 256}.{i % 256}"} for i in range(35)]

    snapshots: list[tuple[int, int]] = []
    real_update = conn_mod.update_work

    def spy(work_id, **counts):
        real_update(work_id, **counts)
        if work_id:
            with real_get_conn() as c:
                r = c.execute(
                    "SELECT processed, imported, status FROM connector_works WHERE id=?",
                    (work_id,)).fetchone()
            if r:
                snapshots.append((r["processed"], r["imported"]))
                assert r["status"] == "running", "work must still be running mid-import"

    monkeypatch.setattr(conn_mod, "update_work", spy)

    wid = conn_mod.start_work(src, None, len(inds))
    try:
        with real_get_conn() as c:
            row = c.execute("SELECT * FROM connector_works WHERE id=?", (wid,)).fetchone()
        assert row["status"] == "running" and row["expected"] == 35 and row["processed"] == 0

        res = conn_mod.import_indicators(inds, src, work_id=wid)
        assert res["imported"] == 35

        # Several intermediate updates, strictly increasing - that is the "live" part.
        assert len(snapshots) >= 3, f"expected progressive updates, got {snapshots}"
        assert [p for p, _ in snapshots] == sorted(p for p, _ in snapshots)
        assert snapshots[-1][0] == 35

        conn_mod.finish_work(wid, "completed", processed=35, imported=res["imported"])
        with real_get_conn() as c:
            done = c.execute("SELECT * FROM connector_works WHERE id=?", (wid,)).fetchone()
        assert done["status"] == "completed" and done["imported"] == 35
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works WHERE id=?", (wid,))
            c.execute("DELETE FROM iocs WHERE source=?", (src,))
            c.commit()


def test_work_progress_failures_never_break_an_import(monkeypatch):
    """Progress reporting is telemetry. If it fails, the import must still
    succeed - observability must never be able to break ingestion."""
    def boom(*a, **k):
        raise RuntimeError("works table unavailable")

    monkeypatch.setattr(conn_mod, "get_conn", boom)
    conn_mod.update_work("some-id", processed=5)      # must not raise
    conn_mod.finish_work("some-id", "completed")      # must not raise

def test_works_endpoint_puts_running_first_and_reports_measured_rate(client, auth):
    """The pipeline view answers "is it moving, and how fast?".

    Running works sort ahead of finished ones regardless of start time - during a
    big sync the in-flight run is the only row an operator cares about, and a
    plain recency sort buries it under whatever completed most recently."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:6]
    older = conn_mod.start_work(f"finished-{tag}", None, 100)
    conn_mod.finish_work(older, "completed", processed=100, imported=90)
    live = conn_mod.start_work(f"inflight-{tag}", None, 400)
    conn_mod.update_work(live, processed=100, imported=80)

    try:
        rows = client.get("/connectors/works?limit=50", headers=auth).json()
        by_id = {w["id"]: w for w in rows}
        assert live in by_id and older in by_id

        ids = [w["id"] for w in rows]
        assert ids.index(live) < ids.index(older), "in-flight work must sort first"

        running = by_id[live]
        assert running["status"] == "running"
        assert running["percent"] == 25          # 100 of 400
        assert running["ratePerSec"] > 0

        # The rate is only a measurement if the timestamps resolve below one
        # second. Whole-second timestamps collapsed start == update for any
        # import faster than a second, and the elapsed-time floor then turned
        # that divide-by-zero into a rate inflated by orders of magnitude.
        with real_get_conn() as c:
            r = c.execute("SELECT started_at, updated_at FROM connector_works WHERE id=?",
                          (live,)).fetchone()
        assert r["updated_at"] != r["started_at"], "work timestamps must be sub-second"

        # A closed work reads 100% even though `expected` was never revised.
        assert by_id[older]["percent"] == 100
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works WHERE id IN (?,?)", (older, live))
            c.commit()


def test_work_rate_is_null_rather_than_invented_when_nothing_processed(client, auth):
    """A work that has not processed anything yet has no throughput. Reporting a
    number there (by clamping the elapsed time to a floor) would manufacture a
    measurement out of a division by ~zero."""
    from dashboard_api.db import get_conn as real_get_conn

    wid = conn_mod.start_work(f"idle-{uuid.uuid4().hex[:6]}", None, 500)
    try:
        rows = client.get("/connectors/works?limit=50", headers=auth).json()
        w = next(x for x in rows if x["id"] == wid)
        assert w["processed"] == 0
        assert w["ratePerSec"] is None
        assert w["percent"] == 0
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works WHERE id=?", (wid,))
            c.commit()

def test_due_connectors_sync_on_their_own_without_anyone_pressing_sync(monkeypatch):
    """AUTOMATIC sync is the whole point of a cadence.

    The reported symptom was "they don't do it automatically, I have to manually
    click sync" - and nothing covered run_due_connectors actually *running* a due
    connector, only that it skips ones that are mid-sync. This pins the contract
    the scheduler tick depends on: elapsed cadence -> the connector runs itself,
    indicators land, and a work record describes the run.
    """
    from datetime import timedelta
    from dashboard_api.db import get_conn as real_get_conn

    feed = [{"type": "ip", "value": "203.0.113.77"}, {"type": "domain", "value": "auto-sync.test"}]
    monkeypatch.setitem(conn_mod._FETCHERS, "json", lambda c: feed)

    tag = uuid.uuid4().hex[:8]
    due_id, early_id = f"due-{tag}", f"early-{tag}"
    due_name, early_name = f"Due Feed {tag}", f"Early Feed {tag}"
    now = datetime.now(timezone.utc)
    # One connector last ran 10s ago on a 2s cadence (due); the other 10s ago on
    # an hour's cadence (not due). Both are enabled and idle.
    rows = [(due_id, due_name, 2, (now - timedelta(seconds=10)).isoformat()),
            (early_id, early_name, 3600, (now - timedelta(seconds=10)).isoformat())]
    with real_get_conn() as c:
        for cid, name, secs, last in rows:
            c.execute(
                "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
                "field_map,status,builtin,created_at,last_run) "
                "VALUES (?,?,?,?,1,?,?,'{}','idle',0,?,?)",
                (cid, name, "json", "https://example.test/feed",
                 max(1, round(secs / 60)), secs, conn_mod._now(), last))
        c.commit()
    try:
        ran = conn_mod.run_due_connectors()
        by_name = {r["connector"]: r for r in ran}

        assert due_name in by_name, f"a due connector did not auto-sync: {sorted(by_name)}"
        assert by_name[due_name].get("imported") == 2, by_name[due_name]
        # The not-due connector must be absent from THIS pass. Asserted against
        # its stored last_run rather than the return list: run_due_connectors is
        # global, so a concurrently-running test's own call can consume a due
        # connector and make the aggregate list an unreliable witness.
        with real_get_conn() as c:
            early_row = c.execute("SELECT last_run FROM connectors WHERE id=?",
                                  (early_id,)).fetchone()
        assert early_row["last_run"] == rows[1][3], (
            "a connector synced before its cadence elapsed")

        with real_get_conn() as c:
            # Indicators really landed, without any manual run.
            assert c.execute("SELECT COUNT(*) AS n FROM iocs WHERE source=?",
                             (due_name,)).fetchone()["n"] == 2
            # last_run advanced, so the next tick won't immediately re-run it.
            row = c.execute("SELECT status,last_run FROM connectors WHERE id=?",
                            (due_id,)).fetchone()
            assert row["status"] == "ok"
            assert datetime.fromisoformat(row["last_run"]) > now - timedelta(seconds=5)
            # And the run is described by a work record, not just a status flip.
            work = c.execute(
                "SELECT * FROM connector_works WHERE connector_id=? ORDER BY started_at DESC",
                (due_id,)).fetchone()
            assert work is not None, "an automatic sync produced no work record"
            assert work["status"] == "completed" and work["imported"] == 2
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE source IN (?,?)", (due_name, early_name))
            c.execute("DELETE FROM ioc_imports WHERE source IN (?,?)", (due_name, early_name))
            c.execute("DELETE FROM connector_works WHERE connector_id IN (?,?)", (due_id, early_id))
            c.execute("DELETE FROM connectors WHERE id IN (?,?)", (due_id, early_id))
            c.commit()


def test_a_one_second_cadence_is_stored_and_honoured(monkeypatch):
    """"If I set sync time to 1 second and save, it goes back to 5 seconds."

    The floor used to be 5s, so the value an operator saved was not the value the
    system kept. Whatever is accepted must survive the round trip and be the
    interval the scheduler actually uses."""
    from dashboard_api.db import get_conn as real_get_conn

    assert conn_mod.MIN_INTERVAL_SECONDS <= 1, "a 1s cadence must be accepted"
    assert conn_mod.connector_interval_seconds({"interval_seconds": 1}) == 1

    cid = "onesec-" + uuid.uuid4().hex[:8]
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,1,1,'{}','idle',0,?)",
            (cid, "One Second Feed", "json", "https://example.test/feed", conn_mod._now()))
        c.commit()
    try:
        with real_get_conn() as c:
            row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
        assert row["interval_seconds"] == 1, "the saved cadence was rewritten"
        assert conn_mod.connector_interval_seconds(row) == 1
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connectors WHERE id=?", (cid,)); c.commit()

# -- Bulk feed parsers: format mistakes here silently poison the IOC store ------

def test_hosts_parser_takes_the_domain_not_the_sinkhole_address():
    """Hosts-file feeds are `0.0.0.0 evil.example`. Reading column one (as the
    plain-list parser does) would import tens of thousands of identical
    `0.0.0.0` rows and none of the domains that are the actual indicators."""
    text = ("# comment\n"
            "0.0.0.0 localhost\n"
            "0.0.0.0 evil.example\n"
            "127.0.0.1 phish.test\n"
            "0.0.0.0 trailing-dot.example.\n"
            "\n"
            "malformed-single-column\n")
    values = [v for v, _ in conn_mod._p_hosts(text)]
    assert values == ["evil.example", "phish.test", "trailing-dot.example"]
    assert "0.0.0.0" not in values and "localhost" not in values


def test_netset_parser_drops_cidr_ranges_it_cannot_match_on():
    """The IOC store matches exact values, so a CIDR string would never match a
    real observation. Importing it anyway would inflate the indicator count with
    rows that claim coverage the platform does not have."""
    pairs = conn_mod._p_netset("# hdr\n1.2.3.0/24\n8.8.8.8\n10.0.0.0/8\n9.9.9.9 note\n")
    assert [v for v, _ in pairs] == ["8.8.8.8", "9.9.9.9"]


def test_bulk_read_truncates_on_a_line_boundary_and_never_splits_a_value(monkeypatch):
    """Curated blocklists run to tens of MB while we keep only the first N
    entries, so the read stops early. Cutting mid-line would import half an
    indicator as though it were whole - the tail fragment must be dropped."""
    body = b"".join(b"evil%d.example\n" % i for i in range(4000))   # ~60 KB
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream([body[i:i + 1024]
                                                     for i in range(0, len(body), 1024)]))
    resp = conn_mod._read_capped("GET", "https://feed.invalid/big", truncate_at=8192)
    assert resp.truncated is True
    assert resp.text.endswith("\n"), "truncated body must end on a line boundary"
    lines = resp.text.splitlines()
    assert 0 < len(lines) < 4000, "expected an early stop, not the whole feed"
    # Every retained line is a complete, parseable value.
    assert all(le.startswith("evil") and le.endswith(".example") for le in lines)


def test_truncation_is_opt_in_so_operator_feeds_still_fail_loudly(monkeypatch):
    """The size cap is a DoS guard for operator-supplied feeds. Silently
    importing a prefix of a hostile multi-GB response would defeat it, so a read
    without an explicit truncate_at must still refuse."""
    monkeypatch.setattr(conn_mod, "_MAX_FEED_BYTES", 2048)
    monkeypatch.setattr(conn_mod.httpx, "stream",
                        lambda *a, **k: _FakeStream([b"y" * 4096]))
    with pytest.raises(ValueError, match="exceeds"):
        conn_mod._read_capped("GET", "https://feed.invalid/flood")


def test_bulk_catalogue_is_well_formed_and_covers_more_than_ip_addresses():
    """A malformed tuple here fails at fetch time, on a background thread, for
    one feed only - the kind of breakage that shows up as a quietly smaller
    sync. Also pins the type coverage: an IP-only catalogue cannot answer "is
    this domain in my proxy log known-bad?", which is the L1 question."""
    seen_urls = set()
    for entry in conn_mod._BULK_FEEDS:
        assert len(entry) == 6, f"malformed feed entry: {entry}"
        name, url, parser, forced, conf, threat = entry
        assert name and threat, entry
        assert url.startswith("https://"), f"{name} must be fetched over TLS"
        assert url not in seen_urls, f"{name} duplicates an existing feed URL"
        seen_urls.add(url)
        assert parser in conn_mod._BULK_PARSERS, f"{name} uses unknown parser {parser!r}"
        assert forced is None or forced in conn_mod._IOC_TYPES, f"{name}: bad type {forced!r}"
        assert 0 < conf <= 100, f"{name}: confidence {conf} out of range"

    # Forced-type feeds plus auto-detecting ones must between them cover more
    # than addresses; the catalogue was once entirely IP blocklists.
    forced_types = {e[3] for e in conn_mod._BULK_FEEDS if e[3]}
    assert {"url"} <= forced_types
    assert any(e[3] is None for e in conn_mod._BULK_FEEDS), "no domain-bearing feeds"
    assert len(conn_mod._BULK_FEEDS) >= 12

def test_aggregating_connector_reports_a_real_running_total(monkeypatch):
    """An aggregating connector records each indicator under its ORIGINATING
    feed, so the connector's own name appears in no source string. Counting by
    `source LIKE '%name%'` therefore reported 0 for the bundled engine no matter
    how much it imported."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:8]
    feed = [{"type": "ip", "value": "203.0.113.90", "source": f"osint:Some Feed {tag}"},
            {"type": "domain", "value": f"agg-{tag}.test", "source": f"osint:Other Feed {tag}"}]
    monkeypatch.setitem(conn_mod._FETCHERS, "json", lambda c: list(feed))

    cid = f"agg-{tag}"
    name = f"Aggregating Engine {tag}"
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','idle',0,?)",
            (cid, name, "json", "https://example.test/feed", conn_mod._now()))
        c.commit()
        row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
    try:
        res = conn_mod.run_connector(row, actor="tester")
        assert res["imported"] == 2, res
        assert res["connectorTotal"] == 2, (
            f"aggregating connector reported a total of {res['connectorTotal']}")

        # A second run adds nothing new, and the running total stays truthful.
        with real_get_conn() as c:
            row2 = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
        res2 = conn_mod.run_connector(row2, actor="tester")
        assert res2["imported"] == 0 and res2["duplicates"] == 2
        assert res2["connectorTotal"] == 2
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE source LIKE ?", (f"%{tag}%",))
            c.execute("DELETE FROM ioc_imports WHERE source=?", (name,))
            c.execute("DELETE FROM connector_works WHERE connector_id=?", (cid,))
            c.execute("DELETE FROM connectors WHERE id=?", (cid,))
            c.commit()


def test_connector_name_with_sql_wildcards_does_not_skew_its_total(monkeypatch):
    """`%` and `_` are LIKE wildcards. A connector named "%" matched every
    source in the store and reported the entire IOC table as its own total."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:8]
    monkeypatch.setitem(conn_mod._FETCHERS, "json",
                        lambda c: [{"type": "ip", "value": "203.0.113.91"}])
    cid, name = f"wild-{tag}", f"%_{tag}"
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','idle',0,?)",
            (cid, name, "json", "https://example.test/feed", conn_mod._now()))
        c.commit()
        row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
        everything = c.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
    try:
        res = conn_mod.run_connector(row, actor="tester")
        assert res["connectorTotal"] <= 1, "a wildcard name claimed other sources' indicators"
        assert res["connectorTotal"] != everything or everything <= 1
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM iocs WHERE source=?", (name,))
            c.execute("DELETE FROM ioc_imports WHERE source=?", (name,))
            c.execute("DELETE FROM connector_works WHERE connector_id=?", (cid,))
            c.execute("DELETE FROM connectors WHERE id=?", (cid,))
            c.commit()

def test_ioc_browse_order_is_index_driven_not_a_full_sort():
    """Paging the CTI list must not re-sort the whole table per request.

    With no index matching `ORDER BY <sort>, id`, SQLite built a temp B-tree over
    every row on every page load: at 310k indicators that cost ~1.6s per page and
    grew with each sync, so the store got slower to read the better the feeds got.
    Asserted on the query PLAN rather than a wall-clock threshold, which is the
    property that actually holds regardless of machine speed."""
    from dashboard_api.db_backend import is_postgres
    if is_postgres():                       # pragma: no cover - planner text differs
        pytest.skip("EXPLAIN QUERY PLAN is SQLite-specific")
    from dashboard_api.db import get_conn as real_get_conn

    # Only the DEFAULT browse order is indexed - see the schema comment. The
    # other sorts are unindexed on purpose, because each extra index halved bulk
    # import throughput at a million rows.
    with real_get_conn() as c:
        plan = " ".join(
            str(r[-1]) for r in
            c.execute("EXPLAIN QUERY PLAN SELECT * FROM iocs "
                      "ORDER BY last_seen DESC, id DESC LIMIT 100 OFFSET 500").fetchall())
        assert "TEMP B-TREE" not in plan.upper(), (
            f"the default browse order falls back to a full sort: {plan}")
        assert "INDEX" in plan.upper(), f"the default browse order is unindexed: {plan}"

        # The list's total for the severity+confidence filter must be answerable
        # from an index alone; without the composite it fetched every matching
        # row off disk purely to re-check severity.
        plan = " ".join(str(r[-1]) for r in c.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM iocs "
            "WHERE severity=? AND confidence>=?", ("high", 70)).fetchall())
        assert "COVERING INDEX" in plan.upper(), f"count is not covered: {plan}"

# -- Failure messages: the two failures operators actually hit look identical ---

def test_rejected_key_and_unreachable_host_do_not_look_the_same(monkeypatch):
    """A rejected API key and a host this machine cannot reach have completely
    different fixes, and httpx's own message distinguishes neither - it reports
    a URL and links to MDN. Days were lost to exactly this ambiguity: a network
    blocking the feed domain read as an API-key problem."""
    otx = {"kind": "otx", "name": "OTX", "url": "https://otx.alienvault.com"}

    rejected = conn_mod.describe_fetch_error(
        conn_mod.httpx.HTTPStatusError(
            "Client error '403 Forbidden' for url 'https://otx.alienvault.com/api/v1/x'",
            request=conn_mod.httpx.Request("GET", "https://otx.alienvault.com/api/v1/x"),
            response=conn_mod.httpx.Response(403)), otx)
    assert "key" in rejected.lower() and "403" in rejected

    unreachable = conn_mod.describe_fetch_error(
        conn_mod.httpx.ConnectError("[Errno -2] Name or service not known"), otx)
    assert "not an API-key problem" in unreachable
    assert "otx.alienvault.com" in unreachable
    assert "403" not in unreachable
    assert rejected != unreachable

    # Rate limiting is neither of the above and must not read as a broken key.
    limited = conn_mod.describe_fetch_error(
        conn_mod.httpx.HTTPStatusError(
            "429", request=conn_mod.httpx.Request("GET", "https://otx.alienvault.com/x"),
            response=conn_mod.httpx.Response(429)), otx)
    assert "rate-limit" in limited.lower() and "key" not in limited.lower().split("this key")[0]


def test_keyless_feed_403_is_not_reported_as_an_api_key_problem():
    """A keyless blocklist cannot have a bad key. Telling the operator to check
    one sends them looking for a setting that does not exist."""
    msg = conn_mod.describe_fetch_error(
        conn_mod.httpx.HTTPStatusError(
            "403", request=conn_mod.httpx.Request("GET", "https://feed.test/x"),
            response=conn_mod.httpx.Response(403)),
        {"kind": "threatorbit", "name": "Engine", "url": "https://feed.test"})
    assert "API key" not in msg
    assert "403" in msg


def test_connector_run_records_the_actionable_message_not_the_raw_httpx_text(monkeypatch):
    """End-to-end: what lands in last_error is what the operator reads."""
    from dashboard_api.db import get_conn as real_get_conn

    def boom(*a, **k):
        raise conn_mod.httpx.ConnectError("[Errno -2] Name or service not known")
    monkeypatch.setitem(conn_mod._FETCHERS, "json", boom)

    cid = "unreach-" + uuid.uuid4().hex[:8]
    name = f"Unreachable {cid}"
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,interval_seconds,"
            "field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,60,60,'{}','idle',0,?)",
            (cid, name, "json", "https://blocked.example/feed", conn_mod._now()))
        c.commit()
        row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
    try:
        res = conn_mod.run_connector(row, actor="tester")
        assert "not an API-key problem" in res["error"]
        assert "blocked.example" in res["error"]
        with real_get_conn() as c:
            stored = c.execute("SELECT status,last_error FROM connectors WHERE id=?",
                               (cid,)).fetchone()
        assert stored["status"] == "error"
        assert "not an API-key problem" in stored["last_error"]
        assert "MDN" not in stored["last_error"] and "developer.mozilla" not in stored["last_error"]
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM ioc_imports WHERE source=?", (name,))
            c.execute("DELETE FROM connector_works WHERE connector_id=?", (cid,))
            c.execute("DELETE FROM connectors WHERE id=?", (cid,))
            c.commit()


def test_otx_with_no_subscriptions_says_so_instead_of_importing_nothing_quietly(monkeypatch):
    """A key that authenticates against an account following nobody returns an
    empty feed forever. Reported as "0 imported, no error" the connector looks
    healthy and never delivers - the operator has no way to know the fix is on
    the OTX side."""
    class _Resp:
        def json(self): return {"results": [], "next": None}
    monkeypatch.setattr(conn_mod, "_http_get", lambda *a, **k: _Resp())

    with pytest.raises(ValueError, match="subscribed to no pulses"):
        conn_mod._fetch_otx({"api_key": "valid-key", "url": None, "kind": "otx"})


def test_otx_still_imports_normally_when_the_account_has_pulses(monkeypatch):
    """The empty-feed guard must not fire on a working account."""
    pulse = {"id": "p1", "name": "Campaign X", "adversary": "APT-Test",
             "malware_families": ["TestLoader"], "tags": ["test"],
             "indicators": [{"type": "IPv4", "indicator": "203.0.113.55"},
                            {"type": "domain", "indicator": "otx-live.test"}]}

    class _Resp:
        def json(self): return {"results": [pulse], "next": None}
    monkeypatch.setattr(conn_mod, "_http_get", lambda *a, **k: _Resp())

    out = conn_mod._fetch_otx({"api_key": "valid-key", "url": None, "kind": "otx"})
    assert [i["value"] for i in out] == ["203.0.113.55", "otx-live.test"]
    assert all(i["actor"] == "APT-Test" for i in out)
    assert conn_mod._fetch_otx.last_reports[0]["title"] == "Campaign X"

# -- Rolling history must stay bounded ------------------------------------------

def test_work_history_is_bounded_and_never_deletes_a_running_import(monkeypatch):
    """One work row lands per sync, and cadences go down to one second - three
    connectors at 1s write ~260k history rows a day between the three tables.
    Unbounded, the record of the imports outgrows the indicators themselves.

    The exemption matters as much as the cap: deleting the row a long import is
    still publishing progress to would make it vanish from the pipeline view
    mid-flight."""
    import dashboard_api.db as db_mod
    from dashboard_api.db import get_conn as real_get_conn

    monkeypatch.setattr(db_mod, "HISTORY_KEEP_WORKS", 5)
    tag = uuid.uuid4().hex[:8]

    with real_get_conn() as c:      # isolate the count from other tests' rows
        c.execute("DELETE FROM connector_works"); c.commit()

    inflight = conn_mod.start_work(f"long-import-{tag}", None, 1_000_000)
    try:
        for i in range(12):
            wid = conn_mod.start_work(f"quick-{tag}-{i}", None, 10)
            conn_mod.finish_work(wid, "completed", processed=10, imported=10)

        with real_get_conn() as c:
            rows = c.execute("SELECT id, status FROM connector_works").fetchall()
        ids = {r["id"] for r in rows}

        assert inflight in ids, "an in-flight work was trimmed away mid-import"
        finished = [r for r in rows if r["status"] != "running"]
        assert len(finished) <= 5, f"history grew past the cap: {len(finished)} rows"

        # And the survivor set is the NEWEST runs, not an arbitrary five.
        with real_get_conn() as c:
            kept = [r["connector"] for r in c.execute(
                "SELECT connector FROM connector_works WHERE status!='running' "
                "ORDER BY started_at DESC").fetchall()]
        assert kept[0] == f"quick-{tag}-11", f"newest run was trimmed: {kept}"
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works"); c.commit()


def test_job_and_import_history_are_bounded_too(monkeypatch):
    """Same rolling-window rule for the other two per-sync tables."""
    import dashboard_api.db as db_mod
    from dashboard_api.db import get_conn as real_get_conn, record_ioc_import, record_job

    monkeypatch.setattr(db_mod, "HISTORY_KEEP_JOBS", 4)
    monkeypatch.setattr(db_mod, "HISTORY_KEEP_IMPORTS", 4)
    with real_get_conn() as c:
        c.execute("DELETE FROM jobs"); c.execute("DELETE FROM ioc_imports"); c.commit()
    try:
        with real_get_conn() as c:
            for i in range(10):
                record_job(c, "connector.json", "completed", {"n": i})
                record_ioc_import(c, f"src-{i}", "connector:json", 1, 0, 0, "tester")
            c.commit()
            jobs = c.execute("SELECT COUNT(*) AS n FROM jobs").fetchone()["n"]
            imps = c.execute("SELECT COUNT(*) AS n FROM ioc_imports").fetchone()["n"]
        assert jobs <= 4, f"jobs grew past the cap: {jobs}"
        assert imps <= 4, f"import history grew past the cap: {imps}"
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM jobs"); c.execute("DELETE FROM ioc_imports"); c.commit()

def test_incomplete_schema_is_reported_against_the_table_that_is_missing():
    """`_safe_schema` swallows per-statement failures on purpose, so a broken
    statement leaves tables missing silently. The first symptom of an index
    declared above its table was `no such table: events` from an unrelated
    migration. The check names what is actually missing."""
    import dashboard_api.db as db_mod

    from dashboard_api.db_backend import is_postgres
    # The catalogue query differs per backend; assert against whichever one this
    # run actually uses rather than hardcoding SQLite's. Pinning sqlite_master
    # made this fail on the Postgres job for a check that was working correctly.
    catalogue = "pg_tables" if is_postgres() else "sqlite_master"

    class _FakeConn:
        def execute(self, sql, *a):
            assert catalogue in sql, f"expected a {catalogue} query, got: {sql}"
            return self
        def fetchall(self):
            return [{"name": "users"}]        # everything else "missing"

    with pytest.raises(RuntimeError, match="schema is incomplete"):
        db_mod._verify_schema(_FakeConn())


def test_schema_verification_passes_on_a_real_initialised_database():
    """And it must not cry wolf against the database the suite is running on."""
    import dashboard_api.db as db_mod
    from dashboard_api.db import get_conn as real_get_conn
    with real_get_conn() as c:
        db_mod._verify_schema(c)              # raises if any declared table is absent

def test_proxy_refusal_is_not_reported_as_a_credential_problem():
    """A proxy refusing the tunnel raises ProxyError with NO .response, so it
    reached the operator as the bare string "403 Forbidden" - which reads exactly
    like a rejected API key and is the one thing it cannot be. Found by running a
    real boot against a network that blocks the feed, not by reading the code."""
    msg = conn_mod.describe_fetch_error(
        conn_mod.httpx.ProxyError("403 Forbidden"),
        {"kind": "nvd", "name": "NVD CVE Feed",
         "url": "https://services.nvd.nist.gov/rest/json/cves/2.0"})
    assert "not an API-key problem" in msg
    assert "proxy" in msg.lower()
    assert "services.nvd.nist.gov" in msg
    assert not msg.startswith("403")


@pytest.mark.parametrize("exc", [
    conn_mod.httpx.ReadError("connection reset"),
    conn_mod.httpx.RemoteProtocolError("server disconnected"),
    conn_mod.httpx.ConnectError("[Errno -2] Name or service not known"),
])
def test_every_transport_failure_reads_as_a_reachability_problem(exc):
    """The whole RequestError family means "the request never completed", which
    is never a credential problem regardless of which subclass it is."""
    msg = conn_mod.describe_fetch_error(exc, {"kind": "otx", "name": "OTX",
                                              "url": "https://otx.alienvault.com"})
    assert "not an API-key problem" in msg

def test_a_failed_sync_is_not_reported_as_100_percent(client, auth):
    """100% has to mean "got through all of it".

    A fetch that failed before it knew how much there was recorded expected=0,
    and percent fell through to "not running, therefore 100" - which the
    pipeline view drew as a FULL bar. A dead feed rendered as a finished one,
    in red. Seen in a browser against the real stack, not in a unit test."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:6]
    dead = conn_mod.start_work(f"dead-feed-{tag}", None, 0)
    conn_mod.finish_work(dead, "failed", "could not reach the feed")
    done = conn_mod.start_work(f"good-feed-{tag}", None, 0)
    conn_mod.finish_work(done, "completed", processed=5, imported=5)
    try:
        rows = {w["id"]: w for w in client.get("/connectors/works?limit=50",
                                               headers=auth).json()}
        assert rows[dead]["percent"] == 0, (
            f"a failed sync that processed nothing reported {rows[dead]['percent']}%")
        # A completed run with no expected count is still genuinely finished.
        assert rows[done]["percent"] == 100
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works WHERE id IN (?,?)", (dead, done))
            c.commit()

def test_schema_splitter_does_not_break_statements_on_comment_semicolons():
    """`SCHEMA.split(";")` is not a SQL parser and the schema is full of prose.

    One comment - `-- ingest source name (collector|syslog-udp|…; 'engine' for
    synthetic)` - contains a semicolon, which cut the `events` CREATE TABLE in
    half. Postgres reported `syntax error at end of input` and never created the
    table; 25 of the 89 naive fragments were not statements at all. SQLite hid
    it because the whole script normally goes through executescript()."""
    from dashboard_api.db import SCHEMA, split_statements

    stmts = split_statements(SCHEMA)
    starts = ("CREATE", "ALTER", "INSERT", "DROP")
    bad = [s[:80] for s in stmts if not s.upper().startswith(starts)]
    assert not bad, f"splitter produced non-statements: {bad}"

    # The table the comment-semicolon actually broke, kept whole.
    events = [s for s in stmts if "CREATE TABLE IF NOT EXISTS events" in s]
    assert len(events) == 1, "events CREATE TABLE was split or lost"
    assert events[0].rstrip().endswith(")"), "events CREATE TABLE is truncated"

    # Every table the schema declares survives the split.
    import re
    declared = set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA))
    split_out = set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)",
                               "\n".join(stmts)))
    assert declared == split_out, f"lost tables: {sorted(declared - split_out)}"


@pytest.mark.parametrize("sql,expect", [
    ("SELECT 1; -- trailing; comment\nSELECT 2;", ["SELECT 1", "SELECT 2"]),
    ("INSERT INTO t VALUES ('a;b');", ["INSERT INTO t VALUES ('a;b')"]),
    ("/* block; comment */ SELECT 1;", ["SELECT 1"]),
    ("SELECT 1", ["SELECT 1"]),                        # no trailing semicolon
    ("  \n -- only a comment;\n ", []),                # nothing executable
])
def test_schema_splitter_handles_strings_and_comments(sql, expect):
    """Semicolons inside string literals and comments are data, not separators."""
    from dashboard_api.db import split_statements
    assert [s.strip() for s in split_statements(sql)] == expect

# -- Provider rate limits: the floor belongs to the provider --------------------

def test_a_managed_provider_refuses_a_cadence_it_cannot_serve(client, auth):
    """NVD allows 5 requests per rolling 30s without a key. A 1s cadence earns a
    steady stream of 429s and imports nothing - which is exactly what the field
    report showed. The create path REFUSES rather than silently clamping, and
    names the provider and the reason: "minimum 30s" with no explanation reads
    as an arbitrary platform restriction rather than NVD's rule."""
    r = client.post("/connectors", json={
        "name": f"NVD too fast {uuid.uuid4().hex[:6]}", "kind": "nvd",
        "interval_seconds": 1}, headers=auth)
    assert r.status_code == 400, r.text
    detail = r.json()["error"]
    assert "30s" in detail and "5 requests per 30s" in detail
    assert "You asked for 1s" in detail


def test_an_operator_owned_source_may_still_sync_every_second(client, auth):
    """The floor is the PROVIDER's, not the platform's. A custom JSON endpoint is
    the operator's own server - their call, and the sub-second cadence work
    exists precisely so they can."""
    r = client.post("/connectors", json={
        "name": f"My feed {uuid.uuid4().hex[:6]}", "kind": "json",
        "url": "https://example.test/feed", "interval_seconds": 1}, headers=auth)
    assert r.status_code == 201, r.text
    assert r.json()["interval_seconds"] == 1
    client.delete(f"/connectors/{r.json()['id']}", headers=auth)


def test_editing_a_connector_is_held_to_the_same_floor(client, auth):
    """The PATCH path clamped where create refused. Two different answers to the
    same question is how "I set 1 second and it went back to 5" happened."""
    from dashboard_api.db import get_conn as real_get_conn
    cid = "floor-" + uuid.uuid4().hex[:8]
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,"
            "interval_seconds,field_map,status,builtin,created_at) "
            "VALUES (?,?,?,NULL,1,720,43200,'{}','idle',0,?)",
            (cid, f"NVD edit {cid}", "nvd", conn_mod._now()))
        c.commit()
    try:
        bad = client.patch(f"/connectors/{cid}", json={"interval_seconds": 2}, headers=auth)
        assert bad.status_code == 400 and "30s" in bad.json()["error"]
        ok = client.patch(f"/connectors/{cid}", json={"interval_seconds": 60}, headers=auth)
        assert ok.status_code == 200 and ok.json()["interval_seconds"] == 60
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connectors WHERE id=?", (cid,)); c.commit()


def test_a_429_backs_off_and_the_scheduler_waits(monkeypatch):
    """A 429 is the provider saying when to return. Retrying on the next tick is
    how a connector spends its life rate-limited and imports nothing."""
    from dashboard_api.db import get_conn as real_get_conn

    def rate_limited(*a, **k):
        raise conn_mod.httpx.HTTPStatusError(
            "429", request=conn_mod.httpx.Request("GET", "https://feed.test/x"),
            response=conn_mod.httpx.Response(429, headers={"Retry-After": "120"}))
    monkeypatch.setitem(conn_mod._FETCHERS, "json", rate_limited)

    cid = "backoff-" + uuid.uuid4().hex[:8]
    name = f"Limited {cid}"
    with real_get_conn() as c:
        c.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,"
            "interval_seconds,field_map,status,builtin,created_at) "
            "VALUES (?,?,?,?,1,1,1,'{}','idle',0,?)",
            (cid, name, "json", "https://feed.test/x", conn_mod._now()))
        c.commit()
        row = dict(c.execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone())
    try:
        res = conn_mod.run_connector(row, actor="tester")
        assert "rate-limit" in res["error"].lower()

        with real_get_conn() as c:
            nxt = c.execute("SELECT next_allowed_at FROM connectors WHERE id=?",
                            (cid,)).fetchone()["next_allowed_at"]
        assert nxt, "a 429 recorded no backoff - the next tick would retry straight into it"
        wait = (datetime.fromisoformat(nxt) - datetime.now(timezone.utc)).total_seconds()
        assert 100 < wait <= 130, f"Retry-After: 120 not honoured (waiting {wait:.0f}s)"

        # And the scheduler actually skips it, despite a 1s cadence.
        ran = [r["connector"] for r in conn_mod.run_due_connectors()]
        assert name not in ran, "scheduler ran a connector inside its backoff window"
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM ioc_imports WHERE source=?", (name,))
            c.execute("DELETE FROM connector_works WHERE connector_id=?", (cid,))
            c.execute("DELETE FROM connectors WHERE id=?", (cid,))
            c.commit()

def test_repeated_no_change_polls_collapse_into_one_row(client, auth):
    """A short cadence against feeds that publish every few minutes means most
    syncs import nothing. Each was its own pipeline entry, so the reported view
    was a wall of `5 / 5 processed · 5 already known` repeating every few
    seconds, burying the runs that actually did something."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:6]
    name = f"Polling Feed {tag}"
    ids = []
    with real_get_conn() as c:
        c.execute("DELETE FROM connector_works")     # isolate the ordering
        c.commit()
    try:
        # Six polls that found nothing, then one that actually imported.
        for _ in range(6):
            wid = conn_mod.start_work(name, None, 5)
            conn_mod.finish_work(wid, "completed", processed=5, imported=0, duplicates=5)
            ids.append(wid)
        real = conn_mod.start_work(name, None, 40)
        conn_mod.finish_work(real, "completed", processed=40, imported=40)

        rows = client.get("/connectors/works?limit=50", headers=auth).json()
        assert len(rows) == 2, f"expected the polls folded into one row, got {len(rows)}"

        newest, folded = rows[0], rows[1]
        # The run that imported something is never folded away.
        assert newest["imported"] == 40 and newest["noop"] is False
        assert "collapsed" not in newest

        assert folded["noop"] is True
        assert folded["collapsed"] == 6, f"folded {folded.get('collapsed')} of 6 polls"
        assert folded["processed"] == 30, "folded row should total the polls it stands for"
        assert folded["collapsedSince"], "a folded row must say how far back it reaches"
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works")
            c.commit()


def test_only_consecutive_polls_from_the_same_connector_fold(client, auth):
    """Folding across connectors would hide one source's silence behind
    another's, and folding across a real import would hide the import."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:6]
    with real_get_conn() as c:
        c.execute("DELETE FROM connector_works"); c.commit()
    try:
        for nm in (f"A-{tag}", f"B-{tag}", f"A-{tag}"):     # interleaved sources
            wid = conn_mod.start_work(nm, None, 5)
            conn_mod.finish_work(wid, "completed", processed=5, imported=0, duplicates=5)

        rows = client.get("/connectors/works?limit=50", headers=auth).json()
        assert len(rows) == 3, "interleaved connectors must not fold together"
        assert all("collapsed" not in r for r in rows)
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works"); c.commit()


def test_a_failed_poll_is_never_folded_away(client, auth):
    """Failures are the thing an operator most needs to see. A failed run is not
    a no-op even though it imported nothing."""
    from dashboard_api.db import get_conn as real_get_conn

    tag = uuid.uuid4().hex[:6]
    name = f"Flaky {tag}"
    with real_get_conn() as c:
        c.execute("DELETE FROM connector_works"); c.commit()
    try:
        for _ in range(3):
            wid = conn_mod.start_work(name, None, 5)
            conn_mod.finish_work(wid, "completed", processed=5, imported=0, duplicates=5)
        bad = conn_mod.start_work(name, None, 0)
        conn_mod.finish_work(bad, "failed", "could not reach the feed")

        rows = client.get("/connectors/works?limit=50", headers=auth).json()
        assert rows[0]["status"] == "failed", "the failure must stay at the top"
        assert rows[0]["noop"] is False
        assert len(rows) == 2 and rows[1]["collapsed"] == 3
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connector_works"); c.commit()


def test_one_crashing_connector_cannot_stop_the_others_from_syncing(monkeypatch):
    """A scheduler tick iterates every enabled connector in a stable order.

    run_connector swallows fetch/parse failures, but the status write and the
    fetcher dispatch around them do not - so an exception escaping there aborted
    the whole tick and every connector AFTER the failing one silently never ran.
    Because the row order is stable, the same feeds would be starved on every
    tick, while the UI showed them as merely "not due yet". That is
    indistinguishable, from the outside, from the reported symptom that
    connectors do not sync on their own.
    """
    from dashboard_api.db import get_conn as real_get_conn

    monkeypatch.setitem(conn_mod._FETCHERS, "json",
                        lambda c: [{"type": "ip", "value": "198.51.100.9"}])

    # Credential decryption happens BEFORE run_connector's try block. Rotating
    # the secret key is the ordinary way this throws for real: every connector
    # with a stored api_key starts failing there, outside every guard.
    import dashboard_api.secretstore as secretstore
    real_decrypt = secretstore.decrypt

    def decrypt_or_die(v):
        if v == "rotated-away":
            raise ValueError("stored credential was encrypted with a previous key")
        return real_decrypt(v)

    monkeypatch.setattr(secretstore, "decrypt", decrypt_or_die)

    tag = uuid.uuid4().hex[:8]
    bad_id, good_id = f"boom-{tag}", f"fine-{tag}"
    bad_name, good_name = f"boom {tag}", f"fine {tag}"
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with real_get_conn() as c:
        for cid, name, key in ((bad_id, bad_name, "rotated-away"), (good_id, good_name, None)):
            c.execute(
                "INSERT INTO connectors (id,name,kind,url,api_key,enabled,interval_minutes,"
                "interval_seconds,field_map,status,builtin,created_at,last_run) "
                "VALUES (?,?,?,?,?,1,1,60,'{}','idle',0,?,?)",
                (cid, name, "json", "https://example.test/feed", key,
                 conn_mod._now(), stale))
        c.commit()
    try:
        ran = {r["connector"]: r for r in conn_mod.run_due_connectors()}
        # The healthy connector ran even though the other one crashed...
        assert good_name in ran, f"a crashing connector starved the rest: {sorted(ran)}"
        assert ran[good_name].get("imported") == 1, ran[good_name]
        # ...and the crash was recorded rather than swallowed silently.
        assert bad_name in ran and "error" in ran[bad_name], ran.get(bad_name)
        with real_get_conn() as c:
            row = c.execute("SELECT status,last_error FROM connectors WHERE id=?",
                            (bad_id,)).fetchone()
        assert row["status"] == "error" and row["last_error"]
    finally:
        with real_get_conn() as c:
            c.execute("DELETE FROM connectors WHERE id IN (?,?)", (bad_id, good_id))
            c.execute("DELETE FROM iocs WHERE source=?", (good_name,))
            c.commit()
