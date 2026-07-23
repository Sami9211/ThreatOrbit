"""Threat-intel connector engine.

Connectors pull indicators from real sources and normalise them into the
single CTI IOC store the whole dashboard reads from - the same model OpenCTI
uses. Supported kinds:

  threatorbit  the bundled OSINT engine (threat_api: abuse.ch, RSS, OTX, …)
  nvd          NVD CVE 2.0 JSON feed (free, no key) → CVEs into the store
  otx          AlienVault OTX subscribed pulses (needs a free OTX API key)
  json         ANY JSON endpoint + a field map  → fully custom source
  csv          ANY CSV endpoint + a column map   → fully custom source
  stix         ANY STIX 2.x bundle of indicators → fully custom source

Every kind funnels through `_import()` which dedups by value and writes the
normalised indicator. `run_connector()` is what the scheduler and the
"Sync now" button call; it updates the connector's status/last_run/count and
records a job. The HTTP layer is isolated in `_http_get` / `_http_post` so
tests can drive the parsers without network access.
"""
import csv as csvmod
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone

import httpx

from dashboard_api.config import THREAT_API_URL, SERVICES_API_KEY
from dashboard_api.db import audit, dumps, get_conn, record_job

_TIMEOUT = 20.0
# Cap the response body a feed may return (DoS guard). httpx reads the whole
# body into memory before .json()/.text, so a malicious, compromised, or simply
# buggy feed returning a multi-GB dump would exhaust memory - and the per-request
# `limit` params we send are advisory (a hostile server ignores them). We stream
# and reject past this bound. 64 MB is generous for an OSINT indicator feed.
_MAX_FEED_BYTES = int(os.environ.get("DASHBOARD_MAX_FEED_BYTES", str(64 * 1024 * 1024)))
_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "cve"}
_MAX_REDIRECTS = 5


class _CappedResponse:
    """A minimal response wrapper exposing the `.json()` / `.text` the fetchers
    use, over a body already read under the size cap."""

    def __init__(self, content: bytes):
        self._content = content

    @property
    def text(self) -> str:
        return self._content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self._content)


def _read_capped(method: str, url: str, **kwargs) -> _CappedResponse:
    """Fetch with a streamed, size-bounded body read, re-validating the SSRF
    guard on every redirect hop.

    `httpx.stream(..., follow_redirects=True)` used to chase a `Location`
    header entirely inside httpx, with zero visibility to our SSRF guard: a
    custom feed URL that passes `validate_external_url` at registration/send
    time (it resolves to a public address right now) can still 302 to
    `169.254.169.254` (cloud metadata) or `127.0.0.1` (an internal service)
    the moment it - or a compromised upstream - decides to, and the dashboard
    would fetch that instead, completely unguarded. So redirects are followed
    here one hop at a time, re-running `validate_external_url` against every
    `Location` before it's followed. Raises for HTTP status, too many
    redirects, and a body exceeding `_MAX_FEED_BYTES` (so it never buffers
    unboundedly)."""
    from dashboard_api.net_guard import validate_external_url
    current = url
    hop_kwargs = kwargs
    for _ in range(_MAX_REDIRECTS + 1):
        with httpx.stream(method, current, timeout=_TIMEOUT, follow_redirects=False,
                          **hop_kwargs) as r:
            if r.is_redirect:
                location = r.headers.get("location")
                if not location:
                    r.raise_for_status()
                    raise ValueError("redirect response is missing its Location header")
                current = str(httpx.URL(current).join(location))
                validate_external_url(current)
                # The Location URL is the full, resolved target - resending the
                # original request's `params`/`json` on top of it would let
                # httpx append a stale query string onto whatever the redirect
                # target already carries. Only `headers` (e.g. auth) still
                # apply to every hop.
                hop_kwargs = {k: v for k, v in kwargs.items() if k == "headers"}
                continue
            r.raise_for_status()                    # status is known before the body
            chunks: list[bytes] = []
            total = 0
            for chunk in r.iter_bytes():
                total += len(chunk)
                if total > _MAX_FEED_BYTES:
                    raise ValueError(
                        f"feed response exceeds {_MAX_FEED_BYTES} bytes - refusing to buffer")
                chunks.append(chunk)
            return _CappedResponse(b"".join(chunks))
    raise ValueError(f"too many redirects (> {_MAX_REDIRECTS})")

# Connector presets surfaced to the UI's "Add connector" form.
KIND_PRESETS = {
    "threatorbit": {
        "label": "ThreatOrbit OSINT Engine",
        "description": "Our own engine: abuse.ch, RSS, dark-web & social OSINT, plus OTX if a key is set. Free, no key needed.",
        "needs_key": False,
        # `needs_url` = the operator must supply the endpoint. Managed providers
        # (fixed, known endpoints) set False so the UI never asks for a URL - it
        # uses `default_url` internally. Only the custom source kinds need one.
        "needs_url": False,
        "default_url": THREAT_API_URL,
        "default_interval": 30,
    },
    "nvd": {
        "label": "NVD CVE Feed",
        "description": "National Vulnerability Database - recent CVEs with CVSS severity. Free, no key (a NVD key raises rate limits).",
        "needs_key": False,
        "needs_url": False,
        "default_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "default_interval": 720,
    },
    "otx": {
        "label": "AlienVault OTX",
        "description": "Your subscribed OTX pulses. Paste your OTX API key (free at otx.alienvault.com → Settings → API); the endpoint is handled for you.",
        "needs_key": True,
        "needs_url": False,   # endpoint is fixed (otx.alienvault.com) - ask only for the key
        "default_url": "https://otx.alienvault.com",
        "default_interval": 120,
    },
    "json": {
        "label": "Custom JSON source",
        "description": "Any endpoint returning a JSON array of indicators. Map which fields hold the value/type. Build your own feed and connect it here.",
        "needs_key": False,
        "needs_url": True,
        "default_url": "",
        "default_interval": 60,
    },
    "darkweb-json": {
        "label": "Dark-web / leak feed (JSON)",
        "description": "Any leak-DB, paste-site or breach-monitor API returning JSON. Records map into dark-web findings (title/category/severity/entity/url) and credential leaks are matched against your user directory.",
        "needs_key": False,
        "needs_url": True,
        "default_url": "",
        "default_interval": 120,
    },
    "csv": {
        "label": "Custom CSV source",
        "description": "Any endpoint returning CSV. Map which columns hold the value/type.",
        "needs_key": False,
        "needs_url": True,
        "default_url": "",
        "default_interval": 60,
    },
    "stix": {
        "label": "Custom STIX 2.x bundle",
        "description": "Any endpoint returning a STIX 2.x bundle; indicator objects are imported.",
        "needs_key": False,
        "needs_url": True,
        "default_url": "",
        "default_interval": 60,
    },
}

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)


def guess_type(value: str) -> str | None:
    """Infer an IOC type from the raw value; None if not importable."""
    v = value.strip()
    if not v:
        return None
    if _CVE.match(v):
        return "cve"
    if _IPV4.match(v.split(":")[0]):
        return "ip"
    if _HASH.match(v):
        return "hash"
    if "://" in v or v.startswith(("http", "/")):
        return "url"
    if "@" in v and "." in v.split("@")[-1]:
        return "email"
    if re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", v, re.I):
        return "domain"
    return None


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_companion(url: str) -> bool:
    """True when `url` targets the deployment's own companion threat service.

    THREAT_API_URL is deployment configuration (env/compose/helm, set by the
    operator) - the same trust level as DATABASE_URL, not user input. On every
    non-cloud install it is a loopback/private address (127.0.0.1:8000 locally,
    a service name on Docker's bridge network), so the SSRF guard - which
    exists for USER-registered connector URLs - must not block it: with the
    guard applied, the bundled OSINT connector could never sync on a default
    live install ("URL resolves to a private or reserved address")."""
    base = (THREAT_API_URL or "").rstrip("/")
    return bool(base) and (url == base or url.startswith(base + "/"))


def _http_get(url: str, headers: dict | None = None, params: dict | None = None):
    # Re-validate at SEND time (not just when the connector was registered) so a
    # name can't rebind to an internal IP between configuration and fetch.
    # Redirects stay enabled here: feed URLs legitimately redirect (http→https,
    # CDN), unlike the push sinks which pin + block redirects.
    from dashboard_api.net_guard import validate_external_url
    validate_external_url(url, allow_private=True if _is_companion(url) else None)
    # Streamed, size-capped read: a hostile/buggy feed can't OOM us with a
    # multi-GB body (the `limit` params we send are advisory, ignored by a
    # hostile server), and `run_connector` records the ValueError as last_error.
    return _read_capped("GET", url, headers=headers or {}, params=params or {})


def _http_post(url: str, headers: dict | None = None, json_body: dict | None = None):
    from dashboard_api.net_guard import validate_external_url
    validate_external_url(url, allow_private=True if _is_companion(url) else None)
    return _read_capped("POST", url, headers=headers or {}, json=json_body or {})


# -- Normalisation + import -----------------------------------------------------

def _severity_from_confidence(c: int) -> str:
    return "critical" if c >= 85 else "high" if c >= 70 else "medium" if c >= 40 else "low"


def _to_confidence(raw, default: int = 50) -> int:
    """Coerce a feed-supplied confidence into an int in [0, 100].

    Real feeds are messy: confidence arrives as an int, a float, a numeric
    string ("75", "75.0", "75%"), null/empty, or plain junk ("high", "n/a").
    A single unparseable value must NOT abort the whole import - that would
    silently discard a feed's worth of good indicators - so junk falls back to
    `default` and the record is still imported. `None`/`""` also use the default;
    anything numeric is clamped into range.
    """
    if raw is None or raw == "":
        return default
    try:
        num = float(str(raw).strip().rstrip("%").strip())
    except (ValueError, TypeError):
        return default
    if num != num or num in (float("inf"), float("-inf")):   # NaN / ±inf ("inf", "1e999")
        return default
    return max(0, min(100, int(num)))


# Cap on how many SIEM alerts a single connector run may raise from critical
# indicators, so a large feed can't flood the alert queue.
_MAX_INTEL_ALERTS_PER_RUN = 10


# Chunk size for the `value IN (...)` existence probe. SQLite caps a statement
# at 999 bound variables; Postgres allows far more, so 900 is safe for both and
# keeps each existence query to a single round trip.
_EXISTS_CHUNK = 900


def _import(indicators: list[dict], source: str) -> dict:
    """Batch dedup-by-value insert of normalised indicators into the IOC store.

    Built for enterprise-scale feed throughput (OTX-in-OpenCTI-class volumes -
    thousands of indicators per second). A naive per-row `SELECT` + `INSERT`
    makes ingest cost O(N) database round trips and collapses under a large pull,
    so this instead:

      1. normalises and de-duplicates the batch in memory (one pass, no DB),
      2. resolves which values already exist with chunked `value IN (...)`
         probes (a handful of round trips, not one per row),
      3. writes every new row with a single `executemany` bulk INSERT.

    Critical indicators still raise a (capped) SIEM 'threat intel match' alert so
    the SIEM reflects newly ingested high-confidence threats."""
    from dashboard_api.detections import alert_from_intel
    now = _now()
    imported = duplicates = skipped = alerts = 0

    # 1. Normalise + intra-batch dedup in memory. `seen` collapses repeats of the
    #    same value within this batch: a later repeat of a *new* value counts as a
    #    duplicate, matching a row-by-row import that would find its own
    #    just-inserted row. `candidates` keeps feed order for stable alerting.
    candidates: list[dict] = []
    seen: set[str] = set()
    for ind in indicators:
        value = (ind.get("value") or "").strip()
        itype = (ind.get("type") or "").strip().lower() or (guess_type(value) or "")
        if not value or itype not in _IOC_TYPES:
            skipped += 1
            continue
        if value in seen:
            duplicates += 1
            continue
        seen.add(value)
        conf = _to_confidence(ind.get("confidence"))
        severity = ind.get("severity") or _severity_from_confidence(conf)
        candidates.append({
            "value": value, "itype": itype, "conf": conf, "severity": severity,
            "threat_type": ind.get("threat_type") or "",
            "actor": ind.get("actor") or "",
            "source": ind.get("source") or source,
            "row": (str(uuid.uuid4()), itype, value,
                    ind.get("threat_type") or "malicious-activity", conf, severity,
                    ind.get("source") or source, ind.get("actor") or "",
                    ind.get("first_seen") or now, ind.get("last_seen") or now,
                    dumps(list(ind.get("tags") or []))),
        })

    if not candidates:
        return {"imported": 0, "duplicates": duplicates, "skipped": skipped,
                "total": len(indicators), "alertsRaised": 0}

    with get_conn() as conn:
        # 2. Bulk existence check - chunked so each query stays within the bound
        #    variable ceiling. `row["value"]` reads on both sqlite3.Row and the
        #    Postgres row wrapper.
        existing: set[str] = set()
        values = [c["value"] for c in candidates]
        for i in range(0, len(values), _EXISTS_CHUNK):
            part = values[i:i + _EXISTS_CHUNK]
            placeholders = ",".join("?" * len(part))
            rows = conn.execute(
                f"SELECT value FROM iocs WHERE value IN ({placeholders})", tuple(part)
            ).fetchall()
            existing.update(r["value"] for r in rows)

        # 3. Everything not already present is new - bulk INSERT it in one call.
        new = [c for c in candidates if c["value"] not in existing]
        duplicates += len(candidates) - len(new)
        if new:
            conn.executemany(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [c["row"] for c in new],
            )
            imported = len(new)
            # Raise capped critical-intel alerts for the newly inserted rows only.
            for c in new:
                if alerts >= _MAX_INTEL_ALERTS_PER_RUN:
                    break
                if c["severity"] == "critical":
                    alert_from_intel(conn, value=c["value"], ioc_type=c["itype"],
                                     severity=c["severity"], confidence=c["conf"],
                                     threat_type=c["threat_type"], actor_name=c["actor"],
                                     source=c["source"])
                    alerts += 1
        conn.commit()

    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(indicators), "alertsRaised": alerts}


# -- Per-kind fetchers (return normalised indicator dicts) -----------------------

_THREATORBIT_TYPE = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash",
                     "md5": "hash", "sha1": "hash", "sha256": "hash", "email": "email"}


def _fetch_threatorbit(c: dict) -> list[dict]:
    base = (c.get("url") or THREAT_API_URL).rstrip("/")
    headers = {"X-API-Key": SERVICES_API_KEY} if SERVICES_API_KEY else {}
    rows = _http_get(f"{base}/iocs", headers=headers, params={"limit": 1000}).json()
    out = []
    for it in rows if isinstance(rows, list) else []:
        if not isinstance(it, dict):
            continue
        t = _THREATORBIT_TYPE.get((it.get("ioc_type") or "").lower())
        if not t:
            continue
        out.append({
            "type": t, "value": it.get("value"),
            "threat_type": it.get("threat_type") or "malicious-activity",
            "confidence": _to_confidence(it.get("confidence")),
            "actor": it.get("malware_family") or "",
            "source": f"threatorbit:{it.get('source') or 'osint'}",
            "tags": list(it.get("tags") or []),
            "first_seen": it.get("first_seen"), "last_seen": it.get("last_seen"),
        })
    return out


_OTX_TYPE = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
             "URL": "url", "URI": "url", "FileHash-MD5": "hash", "FileHash-SHA1": "hash",
             "FileHash-SHA256": "hash", "email": "email", "CVE": "cve"}


def _fetch_otx(c: dict) -> list[dict]:
    if not c.get("api_key"):
        raise ValueError("OTX requires an API key (otx.alienvault.com → Settings → API)")
    base = (c.get("url") or "https://otx.alienvault.com").rstrip("/")
    headers = {"X-OTX-API-KEY": c["api_key"]}
    data = _http_get(f"{base}/api/v1/pulses/subscribed",
                     headers=headers, params={"limit": 30}).json()
    out = []
    for pulse in (data.get("results", []) if isinstance(data, dict) else []):
        if not isinstance(pulse, dict):
            continue
        name = pulse.get("name", "OTX pulse")
        tags = list(pulse.get("tags") or [])[:5]
        for ind in pulse.get("indicators", []):
            if not isinstance(ind, dict):
                continue
            t = _OTX_TYPE.get(ind.get("type"))
            if not t:
                continue
            out.append({
                "type": t, "value": ind.get("indicator"),
                "threat_type": name, "confidence": 70, "source": "alienvault-otx",
                "actor": (pulse.get("adversary") or ""), "tags": tags,
            })
    return out


_NVD_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _fetch_nvd(c: dict) -> list[dict]:
    base = (c.get("url") or "https://services.nvd.nist.gov/rest/json/cves/2.0")
    headers = {"apiKey": c["api_key"]} if c.get("api_key") else {}
    data = _http_get(base, headers=headers, params={"resultsPerPage": 100}).json()
    if not isinstance(data, dict):
        raise ValueError("NVD source did not return a JSON object")
    vulns = [v for v in data.get("vulnerabilities", []) if isinstance(v, dict)]
    # Live feed → scanner catalogue: parse CPE product/version ranges so the
    # vulnerability scanner can match assets against fresh NVD records too.
    from dashboard_api.vuln_scanner import nvd_to_catalogue, upsert_catalogue
    cat_rows = nvd_to_catalogue(vulns)
    if cat_rows:
        with get_conn() as conn:
            upsert_catalogue(conn, cat_rows)
            conn.commit()
    out = []
    for item in vulns:
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        # CVSS v3.1 severity if present, else v2.
        sev = "medium"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                base_sev = metrics[key][0].get("cvssData", {}).get("baseSeverity") \
                    or metrics[key][0].get("baseSeverity", "")
                sev = _NVD_SEV.get((base_sev or "").upper(), "medium")
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break
        out.append({
            "type": "cve", "value": cid, "threat_type": desc or "Vulnerability",
            "confidence": {"critical": 95, "high": 80, "medium": 55, "low": 30}[sev],
            "severity": sev, "source": "nvd", "tags": ["cve", "nvd"],
        })
    return out


def _apply_field_map(record: dict, field_map: dict) -> dict:
    """Map an arbitrary source record onto the normalised indicator shape."""
    def pick(key, default=None):
        col = field_map.get(key)
        return record.get(col, default) if col else default
    value = pick("value")
    return {
        "value": str(value) if value is not None else "",
        "type": pick("type"),  # guess_type fills this when absent
        "threat_type": pick("threat_type") or "imported-indicator",
        "confidence": _to_confidence(pick("confidence")),
        "severity": pick("severity"),
        "actor": pick("actor") or "",
        "tags": [t.strip() for t in str(pick("tags") or "").split(",") if t.strip()],
    }


def _fetch_json(c: dict) -> list[dict]:
    if not c.get("url"):
        raise ValueError("Custom JSON connector requires a URL")
    headers = {}
    if c.get("api_key"):
        headers[c.get("auth_header") or "Authorization"] = c["api_key"]
    data = _http_get(c["url"], headers=headers).json()
    # Accept a bare array or a wrapper object with a common list key.
    if isinstance(data, dict):
        for key in ("data", "results", "indicators", "objects", "iocs", "items"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise ValueError("JSON source did not return a list of indicators")
    fm = c.get("field_map") or {"value": "value", "type": "type"}
    return [_apply_field_map(rec, fm) for rec in data if isinstance(rec, dict)]


def _fetch_csv(c: dict) -> list[dict]:
    if not c.get("url"):
        raise ValueError("Custom CSV connector requires a URL")
    headers = {}
    if c.get("api_key"):
        headers[c.get("auth_header") or "Authorization"] = c["api_key"]
    text = _http_get(c["url"], headers=headers).text
    # Skip abuse.ch-style leading comment lines starting with '#'.
    lines = [ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")]
    reader = csvmod.DictReader(lines)
    fm = c.get("field_map") or {"value": "url", "type": "type"}
    return [_apply_field_map(rec, fm) for rec in reader]


def _fetch_stix(c: dict) -> list[dict]:
    if not c.get("url"):
        raise ValueError("Custom STIX connector requires a URL")
    headers = {}
    if c.get("api_key"):
        headers[c.get("auth_header") or "Authorization"] = c["api_key"]
    bundle = _http_get(c["url"], headers=headers).json()
    if not isinstance(bundle, dict):
        raise ValueError("STIX source did not return a bundle object")
    out = []
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        # STIX patterns look like: [ipv4-addr:value = '1.2.3.4']
        pattern = obj.get("pattern", "")
        m = re.search(r"(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file:hashes[^=]*)"
                      r"[^=]*=\s*'([^']+)'", pattern)
        if not m:
            continue
        kind, value = m.group(1), m.group(2)
        t = ("ip" if "ipv" in kind else "domain" if "domain" in kind
             else "url" if "url" in kind else "email" if "email" in kind
             else "hash" if "hashes" in kind or "file" in kind else None)
        out.append({
            "type": t, "value": value,
            "threat_type": obj.get("name") or "stix-indicator",
            "confidence": _to_confidence(obj.get("confidence"), default=60),
            "source": "stix", "tags": list(obj.get("labels") or []),
        })
    return out


def _fetch_darkweb_json(c: dict) -> list[dict]:
    """Like _fetch_json but keeps the dark-web *finding* shape: the field_map
    maps source keys onto title/category/severity/entity/actor/url/detail
    (unmapped sources pass records through as-is)."""
    if not c.get("url"):
        raise ValueError("Dark-web connector requires a URL")
    headers = {}
    if c.get("api_key"):
        headers[c.get("auth_header") or "Authorization"] = c["api_key"]
    data = _http_get(c["url"], headers=headers).json()
    if isinstance(data, dict):
        for key in ("data", "results", "findings", "items"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise ValueError("Dark-web source did not return a list of findings")
    fm = c.get("field_map") or {}
    out = []
    for rec in data:
        if not isinstance(rec, dict):
            continue
        out.append({k: rec.get(col) for k, col in fm.items()} if fm else dict(rec))
    return out


_FETCHERS = {
    "threatorbit": _fetch_threatorbit, "otx": _fetch_otx, "nvd": _fetch_nvd,
    "json": _fetch_json, "csv": _fetch_csv, "stix": _fetch_stix,
    "darkweb-json": _fetch_darkweb_json,
}


# -- Orchestration ---------------------------------------------------------------

def run_connector(connector: dict, actor: str = "scheduler") -> dict:
    """Fetch + normalise + import one connector. Updates its status and records
    a job. Returns the import tally (or an {error} dict on failure)."""
    cid = connector["id"]
    # Stored credentials are encrypted at rest; fetchers need the plaintext.
    from dashboard_api.secretstore import decrypt
    connector = {**connector, "api_key": decrypt(connector.get("api_key"))}
    fetch = _FETCHERS.get(connector["kind"])
    if fetch is None:
        return {"error": f"unknown connector kind: {connector['kind']}"}

    with get_conn() as conn:
        conn.execute("UPDATE connectors SET status='running' WHERE id=?", (cid,))
        conn.commit()

    try:
        indicators = fetch(connector)
        if connector["kind"] == "darkweb-json":
            # dark-web feeds sink into findings (not the IOC store) and run
            # credential matching against the user directory.
            from dashboard_api.darkweb_logic import import_findings
            result = import_findings(indicators, connector["name"])
        else:
            result = _import(indicators, connector["name"])
        with get_conn() as conn:
            if connector["kind"] == "darkweb-json":
                total_count = conn.execute(
                    "SELECT COUNT(*) AS n FROM dark_web_findings WHERE source=?",
                    (connector["name"],)).fetchone()["n"]
            else:
                total_count = conn.execute(
                    "SELECT COUNT(*) AS n FROM iocs WHERE source LIKE ?",
                    (f"%{connector['name']}%",),
                ).fetchone()["n"]
            conn.execute(
                "UPDATE connectors SET status='ok', last_run=?, last_error=NULL, "
                "indicator_count=indicator_count+? WHERE id=?",
                (_now(), result["imported"], cid),
            )
            record_job(conn, f"connector.{connector['kind']}", "completed",
                       {"connector": connector["name"], **result, "actor": actor})
            audit(conn, actor, "connector.run", cid,
                  f"kind={connector['kind']} imported={result['imported']}")
            conn.commit()
        result["connectorTotal"] = total_count
        return result
    except Exception as e:  # network/parse/auth failure - record, never crash
        msg = str(e)[:300]
        with get_conn() as conn:
            conn.execute("UPDATE connectors SET status='error', last_run=?, last_error=? WHERE id=?",
                         (_now(), msg, cid))
            record_job(conn, f"connector.{connector['kind']}", "failed",
                       {"connector": connector["name"], "error": msg, "actor": actor})
            conn.commit()
        return {"error": msg}


def seed_builtin_connectors():
    """Ensure the bundled connectors exist (idempotent). Called on live boot."""
    now = _now()
    builtins = [
        ("ThreatOrbit OSINT Engine", "threatorbit", THREAT_API_URL, 30),
        ("NVD CVE Feed", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", 720),
    ]
    with get_conn() as conn:
        for name, kind, url, interval in builtins:
            exists = conn.execute("SELECT 1 FROM connectors WHERE kind=? AND builtin=1", (kind,)).fetchone()
            if exists:
                continue
            conn.execute(
                "INSERT INTO connectors (id,name,kind,url,api_key,auth_header,enabled,"
                "interval_minutes,field_map,status,builtin,created_at,created_by) "
                "VALUES (?,?,?,?,NULL,NULL,1,?, '{}', 'idle',1,?, 'system')",
                (str(uuid.uuid4()), name, kind, url, interval, now),
            )
        conn.commit()


def run_due_connectors() -> list[dict]:
    """Run every enabled connector whose interval has elapsed. The scheduler
    calls this on a tick; returns a summary per connector that ran."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    ran = []
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM connectors WHERE enabled=1").fetchall()
    for r in rows:
        c = dict(r)
        if c.get("field_map") and isinstance(c["field_map"], str):
            try:
                c["field_map"] = json.loads(c["field_map"])
            except (ValueError, TypeError):
                c["field_map"] = {}
        due = True
        if c.get("last_run"):
            try:
                last = datetime.fromisoformat(c["last_run"])
                due = now - last >= timedelta(minutes=c.get("interval_minutes") or 60)
            except ValueError:
                due = True
        if due and c.get("status") != "running":
            res = run_connector(c, actor="scheduler")
            ran.append({"connector": c["name"], **res})
    return ran
