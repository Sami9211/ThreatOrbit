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
  taxii        ANY TAXII 2.1 collection (paginated STIX pull, e.g. OpenCTI/MISP)

Every kind funnels through `_import()` which dedups by value and writes the
normalised indicator. `run_connector()` is what the scheduler and the
"Sync now" button call; it updates the connector's status/last_run/count and
records a job. The HTTP layer is isolated in `_http_get` / `_http_post` so
tests can drive the parsers without network access.
"""
import csv as csvmod
import io
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from dashboard_api.config import THREAT_API_URL, SERVICES_API_KEY
from dashboard_api.db import (audit, dumps, get_conn, host_of, ip_hex_of,
                              record_ioc_import, record_job)
from dashboard_api.ioc_store import insert_iocs, ioc_row

_TIMEOUT = 20.0
# Cap the response body a feed may return (DoS guard). httpx reads the whole
# body into memory before .json()/.text, so a malicious, compromised, or simply
# buggy feed returning a multi-GB dump would exhaust memory - and the per-request
# `limit` params we send are advisory (a hostile server ignores them). We stream
# and reject past this bound. 64 MB is generous for an OSINT indicator feed.
_MAX_FEED_BYTES = int(os.environ.get("DASHBOARD_MAX_FEED_BYTES", str(64 * 1024 * 1024)))
_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "cve"}
# Keyless, high-volume public blocklist. Direct dashboard pull - no companion
# service and no key - so a fresh install has REAL indicators after one sync.
ABUSECH_FEODO_URL = os.environ.get(
    "ABUSECH_FEODO_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
_MAX_REDIRECTS = 5


class _CappedResponse:
    """A minimal response wrapper exposing the `.json()` / `.text` the fetchers
    use, over a body already read under the size cap."""

    def __init__(self, content: bytes, not_modified: bool = False, headers: dict | None = None,
                 truncated: bool = False):
        self._content = content
        # True when the server answered 304 to our If-None-Match/If-Modified-Since:
        # the feed is byte-identical to the last sync, so there is nothing to parse.
        self.not_modified = not_modified
        self.headers = headers or {}
        # True when we deliberately stopped reading early (see `truncate_at`).
        self.truncated = truncated

    @property
    def text(self) -> str:
        return self._content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self._content)


def _read_capped(method: str, url: str, *, truncate_at: int | None = None,
                 **kwargs) -> _CappedResponse:
    """Fetch with a streamed, size-bounded body read, re-validating the SSRF
    guard on every redirect hop.

    `truncate_at` opts into stopping early and keeping what arrived, instead of
    refusing the response. Curated bulk blocklists are the case for it: some run
    to tens of megabytes while we only ever keep the first
    `DASHBOARD_BULK_MAX_PER_FEED` entries, so downloading the remainder buys
    nothing and a hard cap would reject the whole feed over bytes we intended to
    discard. It is opt-in precisely because it must NOT apply to operator-supplied
    feeds, where silently importing a prefix of a malformed multi-GB response is
    worse than failing loudly.

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
            if r.status_code == 304:                # conditional GET: nothing new
                return _CappedResponse(b"", not_modified=True)
            r.raise_for_status()                    # status is known before the body
            chunks: list[bytes] = []
            total = 0
            truncated = False
            for chunk in r.iter_bytes():
                total += len(chunk)
                if truncate_at is not None and total >= truncate_at:
                    chunks.append(chunk)
                    truncated = True
                    break                           # stop the transfer; we have enough
                if total > _MAX_FEED_BYTES:
                    raise ValueError(
                        f"feed response exceeds {_MAX_FEED_BYTES} bytes - refusing to buffer")
                chunks.append(chunk)
            body = b"".join(chunks)
            if truncated:
                # The cut lands mid-line. Drop the trailing fragment rather than
                # importing half an indicator as if it were a whole one.
                body = body[:body.rfind(b"\n") + 1] if b"\n" in body else b""
            return _CappedResponse(
                body, truncated=truncated,
                headers={k.lower(): v for k, v in r.headers.items()
                         if k.lower() in ("etag", "last-modified")})
    raise ValueError(f"too many redirects (> {_MAX_REDIRECTS})")

# Connector presets surfaced to the UI's "Add connector" form.
KIND_PRESETS = {
    "threatorbit": {
        "label": "ThreatOrbit OSINT Engine",
        "description": "The bundled engine. Aggregates seven curated public blocklists in parallel - abuse.ch ThreatFox/URLhaus/Feodo, blocklist.de, CINS Army, Emerging Threats and Tor exits - tens of thousands of real indicators per sync. Free, no API key, no setup. Re-syncs are incremental (unchanged feeds are skipped).",
        "needs_key": False,
        # `needs_url` = the operator must supply the endpoint. Managed providers
        # (fixed, known endpoints) set False so the UI never asks for a URL - it
        # uses `default_url` internally. Only the custom source kinds need one.
        "needs_url": False,
        "default_url": THREAT_API_URL,
        "default_interval": 30,
        # One sync fans out to 16 third-party hosts. A 1s cadence would be 16
        # requests/second at public infrastructure that costs us nothing and
        # asks nothing in return; the feeds themselves refresh in minutes.
        "min_interval": 30,
        "rate_note": "aggregates 16 public feeds - they refresh in minutes, not seconds",
    },
    "nvd": {
        "label": "NVD CVE Feed",
        "description": "National Vulnerability Database - recent CVEs with CVSS severity. Free, no key (a NVD key raises rate limits).",
        "needs_key": False,
        "needs_url": False,
        "default_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "default_interval": 720,
        # NVD allows 5 requests per rolling 30s without a key (50 with one).
        # A sync is several paged requests, so anything under ~30s earns a 429.
        "min_interval": 30,
        "rate_note": "NVD allows 5 requests per 30s without an API key",
    },
    "otx": {
        "label": "AlienVault OTX",
        "description": "Your subscribed OTX pulses. Paste your OTX API key (free at otx.alienvault.com → Settings → API); the endpoint is handled for you.",
        "needs_key": True,
        "needs_url": False,   # endpoint is fixed (otx.alienvault.com) - ask only for the key
        "default_url": "https://otx.alienvault.com",
        "default_interval": 120,
        "min_interval": 60,
        "rate_note": "OTX pulses update on the order of minutes",
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
    "taxii": {
        "label": "TAXII 2.1 collection",
        "description": "Pull indicators from any TAXII 2.1 server collection (OpenCTI, MISP, Anomali, …). Paste the collection objects URL (…/collections/<id>/objects/); add an Authorization value only if the server requires auth. The paginated feed is walked automatically.",
        "needs_key": False,
        "needs_url": True,
        "default_url": "",
        "default_interval": 60,
    },
}

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)


def strip_port(value: str) -> str:
    """`host:port` names the same host. Return the host.

    Maltrail's family trails list C2s as `66.210.228.178:443`, and several list
    the same address on two or three ports. Stored verbatim that is not an IP
    address: `ip_hex` cannot be derived from it, so it gets no subnet and no BGP
    pivot, and - the part that actually matters - it can never equal the
    `src_ip` or `dest_ip` of an event, so the whole threat-intel matching path
    is structurally unable to fire on it. Measured on one real import: 77,920
    indicators typed `ip`, every one of them with a null `ip_hex`.

    It also triples the store. One address on three ports was three indicators
    of the same thing.

    IPv6 is why the rule is "exactly one colon, digits after it" rather than
    "split on the first colon": an IPv6 address IS colons. A URL is exempt for
    the same reason in reverse - its colon belongs to the scheme.
    """
    v = (value or "").strip()
    if not v or "://" in v or v.startswith(("http", "/")):
        return v
    head, sep, tail = v.partition(":")
    if not sep or not head:
        return v
    if tail.isdigit():                       # host:port - the common case
        return head
    # `1.2.3.4:33:1099` - three of these are in the Cobalt Strike trail, an
    # address with two ports on it. More than one colon usually means IPv6, so
    # the extra condition is that the head is ITSELF a complete address and
    # everything after it is only ports.
    if _IPV4.match(head) and all(part.isdigit() for part in tail.split(":") if part != ""):
        return head
    return v


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


def validate_feed_url(url: str) -> None:
    """SSRF-validate a user-supplied feed URL for REGISTRATION (create/update).

    Single source of truth with the send-time check below: both allow the
    deployment's own companion threat service, which is operator configuration
    (THREAT_API_URL) rather than user input and is loopback/private on every
    non-cloud install. Without this, registering the bundled OSINT engine
    connector fails with "URL resolves to a private or reserved address" even
    though syncing it is explicitly allowed. Raises UnsafeUrlError otherwise."""
    from dashboard_api.net_guard import validate_external_url
    validate_external_url(url, allow_private=True if _is_companion(url) else None)


def _http_get(url: str, headers: dict | None = None, params: dict | None = None,
              truncate_at: int | None = None):
    # Re-validate at SEND time (not just when the connector was registered) so a
    # name can't rebind to an internal IP between configuration and fetch.
    # Redirects stay enabled here: feed URLs legitimately redirect (http→https,
    # CDN), unlike the push sinks which pin + block redirects.
    from dashboard_api.net_guard import validate_external_url
    validate_external_url(url, allow_private=True if _is_companion(url) else None)
    # Streamed, size-capped read: a hostile/buggy feed can't OOM us with a
    # multi-GB body (the `limit` params we send are advisory, ignored by a
    # hostile server), and `run_connector` records the ValueError as last_error.
    return _read_capped("GET", url, headers=headers or {}, params=params or {},
                        truncate_at=truncate_at)


def _http_post(url: str, headers: dict | None = None, json_body: dict | None = None):
    from dashboard_api.net_guard import validate_external_url
    validate_external_url(url, allow_private=True if _is_companion(url) else None)
    return _read_capped("POST", url, headers=headers or {}, json=json_body or {})


# -- Normalisation + import -----------------------------------------------------

# Severity = what this indicator would DO if the claim is true. It used to be a
# monotone function of confidence, which made it carry no information at all:
# two numbers, one meaning. The damage is measurable in a real 315k store -
# `malware-distribution` landed 50,181 rows at "medium" and 50,024 at "high",
# the SAME activity split purely by whichever confidence the feed happened to
# assert, and 81% of the whole store read "high". A severity that is "high" four
# times out of five is not a triage signal.
#
# So severity is now classified from the activity the feed actually names, and
# "how sure are we" lives in the intel score instead. Keys are substrings
# matched against the normalised threat type and tags; ordered most-specific
# first because "ransomware-c2" must classify as ransomware, not as C2.
#
# Matching is on TOKENS, not raw substrings. A plain `"rce" in text` test
# classified "attack-source" and "brute-force-source" as exploitation, because
# both contain the letters of "rce" - the sort of quiet miscategorisation that
# looks like it works until someone reads the numbers.
_ACTIVITY_SEVERITY: tuple[tuple[tuple[str, ...], str], ...] = (
    # Hands-on-target or destructive: an active intrusion, not a nuisance.
    (("ransom", "wiper", "apt", "targeted attack", "nation state",
      "advanced persistent"), "critical"),
    (("c2", "command and control", "beacon", "cobalt"), "critical"),
    (("exfil", "data theft"), "critical"),
    # Delivery and access: bad, but a step earlier in the chain.
    (("malware", "trojan", "stealer", "loader", "rat", "backdoor", "botnet",
      "worm", "dropper", "miner", "mining"), "high"),
    (("phish", "spoof", "harvest"), "high"),
    (("exploit", "rce", "vulnerab", "cve"), "high"),
    # Noise floor: real, but a SOC does not wake anyone for it.
    (("scan", "recon", "probe", "brute", "spray", "stuffing", "credential",
      "attack", "abuse"), "medium"),
    (("spam", "scam", "fraud", "proxy", "proxies", "tor", "vpn", "anonym"), "medium"),
    (("suspicious", "unwanted", "adware", "pup"), "low"),
)

# What a bare blocklist row is: flagged by somebody, activity unstated. It is
# NOT low (the feed does assert it is bad) and NOT high (nothing says what it
# does). Anything better would be invented.
UNCLASSIFIED_SEVERITY = "medium"


def severity_for(threat_type: str | None, tags=None) -> str:
    """Impact class of the activity a feed asserts, independent of confidence.

    Returns UNCLASSIFIED_SEVERITY when the feed names no activity, which is the
    honest answer for the bulk of any blocklist - guessing from confidence is
    what produced a store that was 81% "high".
    """
    raw = " ".join([str(threat_type or "")] + [str(t) for t in (tags or [])]).lower()
    # Punctuation to spaces, so "malware-distribution" and "malware_distribution"
    # and "CVE-2024-1234" all tokenise the same way.
    text = "".join(ch if ch.isalnum() else " " for ch in raw)
    tokens = text.split()
    if not tokens:
        return UNCLASSIFIED_SEVERITY
    for needles, sev in _ACTIVITY_SEVERITY:
        if any(_hits(n, text, tokens) for n in needles):
            return sev
    return UNCLASSIFIED_SEVERITY


def _hits(needle: str, text: str, tokens: list[str]) -> bool:
    """Phrases match the normalised text; short acronyms ("c2", "rce", "apt")
    must be a WHOLE token so they cannot hide inside an unrelated word; longer
    needles match a token prefix, so "ransom" catches "ransomware"."""
    if " " in needle:
        return needle in text
    if len(needle) <= 3:
        return needle in tokens
    return any(t.startswith(needle) for t in tokens)


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

# How sure a feed has to be before a critical-impact indicator raises a SIEM
# alert on import. 85 is the threshold severity USED to imply back when it was
# derived from confidence, so this keeps alert volume where it was while letting
# severity mean what it says.
ALERT_MIN_CONFIDENCE = int(os.environ.get("DASHBOARD_ALERT_MIN_CONFIDENCE", "85"))


# Chunk size for the `value IN (...)` existence probe. SQLite caps a statement
# at 999 bound variables; Postgres allows far more, so 900 is safe for both and
# keeps each existence query to a single round trip.
_EXISTS_CHUNK = 900

# Sub-batch size for `import_indicators()`. An OTX-scale pull can be hundreds of
# thousands of indicators; ingesting it as one in-memory list + one transaction
# would spike memory and hold the write lock for seconds. Slicing into bounded
# sub-batches keeps memory + transaction size flat at any feed volume while the
# per-batch engine still runs at tens of thousands of indicators/second.
_IMPORT_BATCH = int(os.environ.get("DASHBOARD_IMPORT_BATCH", "10000"))


def upsert_actor_from_pulse(conn, pulse: dict) -> str | None:
    """Populate the threat-actor library from imported intel.

    A pulse names an adversary and lists the malware, ATT&CK techniques and
    industries seen with it - exactly the fields the actor library already has.
    Previously that attribution died as a text string on the indicator, so the
    Actors page and the ATT&CK navigator only ever showed the curated seed data
    and never learned anything from what was actually imported.

    Merges rather than overwrites: an actor accumulates TTPs/malware/sectors
    across every pulse that mentions it, and analyst-entered fields are left
    alone. Returns the actor id, or None when the pulse names no adversary.
    """
    name = (pulse.get("adversary") or "").strip()
    if not name:
        return None
    now = _now()
    row = conn.execute(
        "SELECT * FROM threat_actors WHERE LOWER(name)=LOWER(?)", (name,)).fetchone()

    def _merge(existing, incoming):
        """Union, preserving existing order - imports add, never remove."""
        try:
            cur = json.loads(existing) if isinstance(existing, str) else (existing or [])
        except (ValueError, TypeError):
            cur = []
        seen = {str(x).lower() for x in cur}
        for v in incoming or []:
            if v and str(v).lower() not in seen:
                cur.append(v)
                seen.add(str(v).lower())
        return cur

    ttps = _merge(row["ttps"] if row else "[]", pulse.get("attack_ids"))
    malware = _merge(row["malware"] if row else "[]", pulse.get("malware_families"))
    sectors = _merge(row["sectors"] if row else "[]", pulse.get("industries"))

    if row:
        conn.execute(
            "UPDATE threat_actors SET ttps=?, malware=?, sectors=?, last_seen=?, "
            "active=1, recent_activity=? WHERE id=?",
            (dumps(ttps), dumps(malware), dumps(sectors),
             pulse.get("modified") or now,
             f"Seen in intel: {pulse.get('title') or 'pulse'}"[:200], row["id"]))
        return row["id"]

    aid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO threat_actors (id,name,aliases,type,motivations,active,first_seen,"
        "last_seen,sophistication,threat_level,sectors,ttps,malware,ioc_count,"
        "campaign_count,recent_activity) "
        "VALUES (?,?,'[]','unknown','[]',1,?,?,3,'medium',?,?,?,0,1,?)",
        (aid, name, pulse.get("created") or now, pulse.get("modified") or now,
         dumps(sectors), dumps(ttps), dumps(malware),
         f"Seen in intel: {pulse.get('title') or 'pulse'}"[:200]))
    return aid


def upsert_intel_reports(reports: list[dict], source: str) -> dict[str, str]:
    """Persist pulse-shaped intel as REPORTS and return {external_id: report_id}.

    This is the AlienVault/OpenCTI model: a pulse is a report carrying the
    attribution (adversary, malware families), the TTPs (MITRE ATT&CK ids), the
    targeting (industries, countries) and the source reporting (references).
    Without this the platform stored a bare value and a feed name, and an analyst
    had no way to ask what campaign an indicator belonged to.

    Upserted on (source, external_id) so a re-synced pulse updates in place
    instead of duplicating - pulses are revised upstream all the time.
    """
    if not reports:
        return {}
    now = _now()
    ids: dict[str, str] = {}
    with get_conn() as conn:
        for r in reports:
            ext = (r.get("external_id") or "").strip()
            if not ext:
                continue
            row = conn.execute(
                "SELECT id FROM intel_reports WHERE source=? AND external_id=?",
                (source, ext)).fetchone()
            fields = (
                r.get("title") or "Untitled pulse",
                (r.get("tlp") or "white").lower(),
                r.get("summary") or "",
                dumps([a for a in [r.get("adversary")] if a]),
                dumps(list(r.get("tags") or [])),
                r.get("author") or "",
                dumps(list(r.get("references") or [])),
                dumps(list(r.get("attack_ids") or [])),
                dumps(list(r.get("malware_families") or [])),
                dumps(list(r.get("targeted_countries") or [])),
                dumps(list(r.get("industries") or [])),
                now,
            )
            if row:
                rid = row["id"]
                conn.execute(
                    "UPDATE intel_reports SET title=?, tlp=?, summary=?, actors=?, tags=?, "
                    "author=?, source_refs=?, attack_ids=?, malware_families=?, "
                    "targeted_countries=?, industries=?, updated_at=? WHERE id=?",
                    (*fields, rid))
            else:
                rid = str(uuid.uuid4())
                conn.execute(
                    # source + external_id are the upsert key: without them a
                    # re-synced pulse would insert a duplicate every cycle.
                    "INSERT INTO intel_reports (id,title,tlp,summary,actors,tags,author,"
                    "source_refs,attack_ids,malware_families,targeted_countries,industries,"
                    "updated_at,status,body,iocs,created_at,source,external_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, 'published','','[]',?,?,?)",
                    (rid, *fields, r.get("created") or now, source, ext))
            # Attribution feeds the actor library + ATT&CK coverage, not just a
            # text field on the report.
            try:
                upsert_actor_from_pulse(conn, r)
            except Exception:
                logging.exception("actor upsert failed for pulse %s", ext)
            ids[ext] = rid
        conn.commit()
    return ids


def _now_precise() -> str:
    """Sub-second timestamp, for works only. `_now()` truncates to whole seconds,
    which is fine for "last run at" but useless for throughput: a 24k-indicator
    import that lands in 600ms would show start == end and yield a nonsense
    rate. Works keep microseconds so the reported rate is a measurement."""
    return datetime.now(timezone.utc).isoformat()


def work_view(w: dict) -> dict:
    """Derive the fields an operator reads from a stored work row.

    Lives here rather than in the router because the live stream publishes the
    same shape the REST listing returns: a console that merges a pushed work
    into its table must not have to compute percent and rate differently from
    the way the server does, or the bar jumps every time the two disagree.
    """
    exp = w.get("expected") or 0
    proc = w.get("processed") or 0
    # 100% must mean "got through all of it". A failed sync that never fetched
    # anything was reported as 100 (there was nothing expected, and it was not
    # running), which the pipeline view drew as a FULL bar in red - reading as
    # "finished" for a run that did nothing at all.
    if exp:
        w["percent"] = round(min(100, proc / exp * 100))
    else:
        w["percent"] = 100 if w.get("status") == "completed" else 0
    # Live throughput, so a slow feed is visibly slow rather than just
    # "running". Reported only when it is actually measurable: no processed
    # indicators, or no elapsed time to divide by, means we have no rate - and
    # null is honest where an invented number is not.
    w["ratePerSec"] = None
    try:
        secs = (datetime.fromisoformat(w["updated_at"])
                - datetime.fromisoformat(w["started_at"])).total_seconds()
        if proc > 0 and secs > 0:
            w["ratePerSec"] = round(proc / secs, 1)
    except (ValueError, TypeError, KeyError):
        pass
    # A completed run that brought in nothing new is a poll, not an event.
    w["noop"] = bool(w.get("status") == "completed" and not (w.get("imported") or 0))
    return w


def _publish_work(conn, work_id: str) -> None:
    """Push a work's current state to every live console.

    The imports screen had no push at all: it polled every two seconds while an
    import was in flight and every fifteen otherwise, so "is it moving?" was
    answered by a timer rather than by the import. A sync that finishes between
    ticks reads as frozen and then jumps.

    The payload is camelCase because SSE data reaches the browser as raw JSON -
    only `api()` responses pass through toCamel() - so a pushed work and a
    fetched one have to arrive already agreeing on their field names.

    Best-effort: telling somebody about an import must never be able to fail one.
    """
    try:
        row = conn.execute(
            "SELECT * FROM connector_works WHERE id=?", (work_id,)).fetchone()
        if row is None:
            return
        w = work_view(dict(row))
        from dashboard_api.events_stream import publish
        publish("connector.work", {
            "id": w["id"], "connectorId": w.get("connector_id"),
            "connector": w.get("connector"), "status": w.get("status"),
            "expected": w.get("expected") or 0, "processed": w.get("processed") or 0,
            "imported": w.get("imported") or 0, "duplicates": w.get("duplicates") or 0,
            "skipped": w.get("skipped") or 0, "message": w.get("message"),
            "startedAt": w.get("started_at"), "updatedAt": w.get("updated_at"),
            "percent": w["percent"], "ratePerSec": w["ratePerSec"], "noop": w["noop"],
        })
    except Exception:
        logging.debug("work publish failed for %s", work_id, exc_info=True)


def start_work(connector: str, connector_id: str | None, expected: int) -> str:
    """Open an in-flight work record for a sync (OpenCTI's "work" concept).

    An import used to be atomic and invisible - the operator saw nothing until it
    finished, so a 40k-indicator sync in progress looked identical to a broken
    one. The work row is updated as each sub-batch lands."""
    wid = str(uuid.uuid4())
    now = _now_precise()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO connector_works (id,connector_id,connector,status,expected,"
            "processed,imported,duplicates,skipped,started_at,updated_at) "
            "VALUES (?,?,?, 'running', ?,0,0,0,0,?,?)",
            (wid, connector_id, connector[:120], max(0, expected), now, now))
        conn.commit()
        _publish_work(conn, wid)
    return wid


def update_work(work_id: str, **counts) -> None:
    """Advance an in-flight work. Best-effort: progress reporting must never be
    able to fail an import that is otherwise succeeding."""
    if not work_id:
        return
    fields = [k for k in ("processed", "imported", "duplicates", "skipped") if k in counts]
    if not fields:
        return
    try:
        with get_conn() as conn:
            conn.execute(
                f"UPDATE connector_works SET {','.join(f'{f}=?' for f in fields)}, updated_at=? "
                "WHERE id=?",
                (*[int(counts[f]) for f in fields], _now_precise(), work_id))
            conn.commit()
            _publish_work(conn, work_id)
    except Exception:
        logging.debug("work progress update failed", exc_info=True)


def finish_work(work_id: str, status: str, message: str | None = None, **counts) -> None:
    """Close a work as completed/failed, then trim the rolling history.

    Also best-effort: bookkeeping must never fail an import that succeeded."""
    if not work_id:
        return
    try:
        with get_conn() as conn:
            sets = ["status=?", "updated_at=?"]
            vals: list = [status, _now_precise()]
            for f in ("processed", "imported", "duplicates", "skipped"):
                if f in counts:
                    sets.append(f"{f}=?"); vals.append(int(counts[f]))
            if message is not None:
                sets.append("message=?"); vals.append(str(message)[:300])
            conn.execute(f"UPDATE connector_works SET {','.join(sets)} WHERE id=?",
                         (*vals, work_id))
            # Rolling window, trimmed as runs close. A 1-second cadence writes a
            # work row every second per connector; unbounded, this table would
            # outgrow the indicators it describes. Running rows are exempt so a
            # long import can never have the row it is still writing to deleted.
            from dashboard_api.db import HISTORY_KEEP_WORKS, trim_history
            trim_history(conn, "connector_works", HISTORY_KEEP_WORKS, "started_at",
                         protect="status='running'")
            conn.commit()
            _publish_work(conn, work_id)
    except Exception:
        logging.debug("work finalisation failed", exc_info=True)


def import_indicators(indicators: list[dict], source: str,
                      work_id: str | None = None) -> dict:
    """Ingest an arbitrarily large feed in bounded sub-batches.

    Thin, scale-safe wrapper over `_import`: it slices the fetched indicators
    into `_IMPORT_BATCH`-sized chunks so a very large pull (OTX-in-OpenCTI class)
    ingests with flat memory and bounded transactions instead of one giant list /
    lock hold, while preserving exact counts and the *per-run* critical-alert cap
    (the alert budget is shared across sub-batches, not reset each chunk)."""
    totals = {"imported": 0, "duplicates": 0, "skipped": 0,
              "total": len(indicators), "alertsRaised": 0, "attributed": 0}
    budget = _MAX_INTEL_ALERTS_PER_RUN
    for i in range(0, len(indicators), _IMPORT_BATCH):
        chunk = indicators[i:i + _IMPORT_BATCH]
        r = _import(chunk, source, alert_budget=budget)
        for k in ("imported", "duplicates", "skipped", "alertsRaised", "attributed"):
            totals[k] += r.get(k, 0)
        budget -= r["alertsRaised"]
        # Publish progress after every sub-batch so the UI sees counts climb
        # during a large sync instead of one lump at the end.
        update_work(work_id, processed=min(i + len(chunk), len(indicators)),
                    imported=totals["imported"], duplicates=totals["duplicates"],
                    skipped=totals["skipped"])
    return totals


def record_source_assertions(conn, candidates: list[dict], now: str) -> None:
    """Upsert one (value, source) row per candidate, and keep intel_sources fresh.

    Best-effort: corroboration is a derived signal, and losing it must never fail
    an import that is otherwise storing indicators correctly."""
    if not candidates:
        return
    try:
        rows, sources = [], {}
        for c in candidates:
            src = (c.get("source") or "")[:200]
            if not src:
                continue
            rows.append((c["value"], src, now, now,
                         (c.get("threat_type") or "")[:120], c.get("conf"), now))
            sources[src] = now
        if not rows:
            return
        # ON CONFLICT works on both backends; a repeat sighting from the same
        # source moves last_seen forward instead of duplicating the row.
        conn.executemany(
            "INSERT INTO observable_sources (value,source_id,first_seen,last_seen,"
            "raw_label,confidence) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(value,source_id) DO UPDATE SET last_seen=?", rows)
        conn.executemany(
            "INSERT INTO intel_sources (id,name,first_seen,last_seen) "
            "VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=?",
            [(sid, sid, ts, ts, ts) for sid, ts in sources.items()])
    except Exception:
        logging.debug("recording source assertions failed", exc_info=True)


def _import(indicators: list[dict], source: str,
            *, alert_budget: int = _MAX_INTEL_ALERTS_PER_RUN) -> dict:
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
    the SIEM reflects newly ingested high-confidence threats. `alert_budget` caps
    how many this call may raise (threaded through by `import_indicators` so the
    cap stays per-run when a large feed is split across sub-batches)."""
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
        # Normalise BEFORE the type is inferred, so both the type and the stored
        # value come from the same clean string. Every connector import funnels
        # through here, which is why it is the one place worth doing it.
        value = strip_port(ind.get("value") or "")
        itype = (ind.get("type") or "").strip().lower() or (guess_type(value) or "")
        if not value or itype not in _IOC_TYPES:
            skipped += 1
            continue
        if value in seen:
            duplicates += 1
            continue
        seen.add(value)
        conf = _to_confidence(ind.get("confidence"))
        # A feed's own severity wins; otherwise classify by the activity it
        # names. Never by confidence - see _ACTIVITY_SEVERITY.
        severity = ind.get("severity") or severity_for(
            ind.get("threat_type"), ind.get("tags"))
        candidates.append({
            "value": value, "itype": itype, "conf": conf, "severity": severity,
            "threat_type": ind.get("threat_type") or "",
            "actor": ind.get("actor") or "",
            "malware_family": ind.get("malware_family") or "",
            "source": ind.get("source") or source,
            # Built by ioc_store, which owns the column list and derives host,
            # ip_hex and reg_domain. This site used to spell the INSERT out and
            # supplied two of the three - reg_domain was left NULL on every
            # import, so sibling clustering found nothing until a restart ran
            # the backfill.
            "row": ioc_row(
                type=itype, value=value,
                threat_type=ind.get("threat_type") or "malicious-activity",
                confidence=conf, severity=severity,
                source=ind.get("source") or source, actor=ind.get("actor") or "",
                malware_family=ind.get("malware_family") or "",
                first_seen=ind.get("first_seen") or now,
                last_seen=ind.get("last_seen") or now,
                tags=ind.get("tags") or [], report_id=ind.get("report_id")),
        })

    if not candidates:
        return {"imported": 0, "duplicates": duplicates, "skipped": skipped,
                "total": len(indicators), "alertsRaised": 0, "attributed": 0}

    with get_conn() as conn:
        # 2. Bulk existence check - chunked so each query stays within the bound
        #    variable ceiling. `row["value"]` reads on both sqlite3.Row and the
        #    Postgres row wrapper.
        existing: set[str] = set()
        # Values already in the store that nobody has attributed yet. Read in the
        # SAME round trips as the existence probe, because it is the same rows -
        # asking twice would double the only part of an import that is not bulk.
        unattributed: set[str] = set()
        values = [c["value"] for c in candidates]
        for i in range(0, len(values), _EXISTS_CHUNK):
            part = values[i:i + _EXISTS_CHUNK]
            placeholders = ",".join("?" * len(part))
            rows = conn.execute(
                f"SELECT value, malware_family FROM iocs WHERE value IN ({placeholders})",
                tuple(part)).fetchall()
            for r in rows:
                existing.add(r["value"])
                if not (r["malware_family"] or ""):
                    unattributed.add(r["value"])

        # 3. Record WHICH source asserted each value - for every candidate, not
        #    just the new ones. A value already in the store because feed A
        #    listed it is exactly the case that matters: feed B listing it too is
        #    corroboration, and dropping it as "a duplicate" is how 16 feeds
        #    produced one opinion. This is the only place that fact exists.
        record_source_assertions(conn, candidates, now)

        # 4. A value we already hold, that we now know the family of, gets it.
        #    Without this the whole point of the family trails is lost on any
        #    store that already holds the value: `_import` inserts new rows and
        #    counts everything else as a duplicate, so the 50,192 Maltrail
        #    domains imported before attribution existed would have stayed bare
        #    for ever - the feed would keep re-asserting a family the store kept
        #    throwing away. Grouped by family so this is a handful of statements,
        #    not one per indicator, and it only ever fills a blank: a family
        #    already recorded is never overwritten by another source's guess.
        attributed = 0
        by_family: dict[str, list[str]] = {}
        for c in candidates:
            fam = (c.get("malware_family") or "").strip().lower()
            if fam and c["value"] in unattributed:
                by_family.setdefault(fam, []).append(c["value"])
        for fam, vals in by_family.items():
            for i in range(0, len(vals), _EXISTS_CHUNK):
                part = vals[i:i + _EXISTS_CHUNK]
                marks = ",".join("?" * len(part))
                cur = conn.execute(
                    f"UPDATE iocs SET malware_family=? WHERE value IN ({marks}) "
                    "AND (malware_family IS NULL OR malware_family='')",
                    (fam, *part))
                attributed += getattr(cur, "rowcount", 0) or 0

        # 5. Everything not already present is new - bulk INSERT it in one call.
        new = [c for c in candidates if c["value"] not in existing]
        duplicates += len(candidates) - len(new)
        if new:
            imported = insert_iocs(conn, [c["row"] for c in new])
            # Raise capped critical-intel alerts for the newly inserted rows only.
            for c in new:
                if alerts >= alert_budget:
                    break
                # Critical impact AND a claim worth believing. Severity is now
                # purely about what the activity WOULD do, so on its own it no
                # longer says anything about how sure we are - and a junk feed
                # asserting "c2" at 20% confidence must not page anybody. This
                # gate did not exist before because severity was derived from
                # confidence, so "critical" already implied conf >= 85.
                if c["severity"] == "critical" and c["conf"] >= ALERT_MIN_CONFIDENCE:
                    alert_from_intel(conn, value=c["value"], ioc_type=c["itype"],
                                     severity=c["severity"], confidence=c["conf"],
                                     threat_type=c["threat_type"], actor_name=c["actor"],
                                     source=c["source"])
                    alerts += 1
        conn.commit()

    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(indicators), "alertsRaised": alerts,
            "attributed": attributed}


# -- Per-kind fetchers (return normalised indicator dicts) -----------------------

_THREATORBIT_TYPE = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash",
                     "md5": "hash", "sha1": "hash", "sha256": "hash", "email": "email"}


# The ThreatOrbit OSINT engine's /iocs endpoint caps `limit` at 1000 per request
# but supports `offset`. Paging it is what lets our own engine deliver its FULL
# corpus (abuse.ch Feodo alone is thousands of live malicious IPs) instead of the
# first page - the same treatment OTX and TAXII get.
_THREATORBIT_PAGE = 1000
_THREATORBIT_MAX_PAGES = int(os.environ.get("DASHBOARD_THREATORBIT_MAX_PAGES", "50"))


def _fetch_threatorbit(c: dict) -> list[dict]:
    """The ThreatOrbit OSINT engine: aggregate real intel from public sources.

    This used to ONLY re-serve whatever the companion threat service happened to
    hold - a second-hand path to a store that is usually near-empty, which is why
    the "engine" imported a handful of indicators (or none) while claiming to be
    the platform's own OSINT source.

    It now does the aggregation itself: it pulls the curated public blocklists
    directly (the same parallel, conditional-fetch path the bulk connector uses)
    and then *adds* anything the companion service holds, if it is reachable.
    The companion is now an optional bonus, not a single point of failure.
    """
    out: list[dict] = _fetch_bulk_osint(c)
    # Carry the bulk feeds' HTTP validators so incremental sync still applies.
    _fetch_threatorbit.last_state = getattr(_fetch_bulk_osint, "last_state", {}) or {}

    try:
        out.extend(_fetch_threat_api(c))
    except Exception as e:
        # The companion is optional. A failure here must never zero a sync that
        # already collected tens of thousands of indicators from public feeds.
        logging.info("ThreatOrbit engine: companion threat service unavailable (%s) - "
                     "public OSINT feeds still imported", e)
    return out


def _fetch_threat_api(c: dict) -> list[dict]:
    """Read indicators from the companion threat service (optional extra source)."""
    base = (c.get("url") or THREAT_API_URL).rstrip("/")
    headers = {"X-API-Key": SERVICES_API_KEY} if SERVICES_API_KEY else {}
    rows: list = []
    for page in range(_THREATORBIT_MAX_PAGES):
        batch = _http_get(f"{base}/iocs", headers=headers,
                          params={"limit": _THREATORBIT_PAGE,
                                  "offset": page * _THREATORBIT_PAGE}).json()
        if not isinstance(batch, list) or not batch:
            break
        rows.extend(batch)
        if len(batch) < _THREATORBIT_PAGE:      # short page = last page
            break
    out = []
    for it in rows:
        if not isinstance(it, dict):
            continue
        t = _THREATORBIT_TYPE.get((it.get("ioc_type") or "").lower())
        if not t:
            continue
        out.append({
            "type": t, "value": it.get("value"),
            "threat_type": it.get("threat_type") or "malicious-activity",
            "confidence": _to_confidence(it.get("confidence")),
            # The companion calls this field what it is; this side used to store
            # it as the actor.
            "malware_family": it.get("malware_family") or "",
            "actor": it.get("actor") or "",
            "source": f"threatorbit:{it.get('source') or 'osint'}",
            "tags": list(it.get("tags") or []),
            "first_seen": it.get("first_seen"), "last_seen": it.get("last_seen"),
        })
    return out


_OTX_TYPE = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
             "URL": "url", "URI": "url", "FileHash-MD5": "hash", "FileHash-SHA1": "hash",
             "FileHash-SHA256": "hash", "email": "email", "CVE": "cve"}


# OTX pull sizing. The subscribed-pulses feed is paginated; walking it the way
# OpenCTI's OTX connector does is what turns a sync from "one page, ~a handful of
# pulses" into a real feed of tens of thousands of indicators. Bounded so a sync
# can't run unbounded: at most _OTX_MAX_PAGES pages of _OTX_PAGE_LIMIT pulses, and
# a hard indicator ceiling. All three are env-tunable for larger deployments.
_OTX_PAGE_LIMIT = int(os.environ.get("DASHBOARD_OTX_PAGE_LIMIT", "50"))
_OTX_MAX_PAGES = int(os.environ.get("DASHBOARD_OTX_MAX_PAGES", "50"))
_OTX_MAX_INDICATORS = int(os.environ.get("DASHBOARD_OTX_MAX_INDICATORS", "100000"))


def _fetch_otx(c: dict) -> list[dict]:
    if not c.get("api_key"):
        raise ValueError("OTX requires an API key (otx.alienvault.com → Settings → API)")
    base = (c.get("url") or "https://otx.alienvault.com").rstrip("/")
    headers = {"X-OTX-API-KEY": c["api_key"]}
    out: list[dict] = []
    reports: list[dict] = []
    # Page through the subscribed pulses (page increments against the fixed base -
    # not by following the API-supplied `next` URL, which would widen the SSRF
    # surface) until OTX signals no further page, the page cap, or the indicator
    # ceiling. This is the difference between importing a handful of pulses and a
    # full subscribed feed.
    for page in range(1, _OTX_MAX_PAGES + 1):
        data = _http_get(f"{base}/api/v1/pulses/subscribed", headers=headers,
                         params={"limit": _OTX_PAGE_LIMIT, "page": page}).json()
        results = data.get("results", []) if isinstance(data, dict) else []
        if not results:
            # An empty FIRST page means the key authenticated (OTX would have
            # answered 401/403 otherwise) but the account follows nobody, so the
            # subscribed feed is genuinely empty and will stay empty on every
            # future sync. Reporting "0 imported, no error" would leave the
            # operator with a connector that looks healthy and never delivers -
            # this is a configuration problem on the OTX side, and it needs to
            # say so.
            if page == 1:
                raise ValueError(
                    "OTX accepted the API key but your account is subscribed to no pulses, "
                    "so there is nothing to import. Subscribe to pulses or users at "
                    "otx.alienvault.com (Browse → Pulses → Subscribe) and sync again.")
            break
        for pulse in results:
            if not isinstance(pulse, dict):
                continue
            name = pulse.get("name", "OTX pulse")
            tags = list(pulse.get("tags") or [])[:8]
            adversary = (pulse.get("adversary") or "").strip()
            malware = [m for m in (pulse.get("malware_families") or []) if m]
            # OTX returns attack_ids either as bare strings or as objects.
            attack_ids = []
            for a in (pulse.get("attack_ids") or []):
                aid = a.get("id") if isinstance(a, dict) else a
                if aid:
                    attack_ids.append(str(aid))
            refs = [r for r in (pulse.get("references") or []) if r]

            # A pulse is a REPORT, not a bag of values. Emit it so the import
            # can persist the attribution/TTPs and hang the indicators off it -
            # this is the difference between "an IP from a feed" and intel an
            # analyst can act on.
            report = {
                "external_id": pulse.get("id") or "",
                "title": name,
                "summary": (pulse.get("description") or "")[:4000],
                "tlp": (pulse.get("TLP") or pulse.get("tlp") or "white").lower(),
                "author": (pulse.get("author_name") or pulse.get("author", {}).get("username")
                           if isinstance(pulse.get("author"), dict) else pulse.get("author_name")) or "",
                "created": pulse.get("created"), "modified": pulse.get("modified"),
                "tags": tags, "references": refs, "attack_ids": attack_ids,
                "malware_families": malware, "adversary": adversary,
                "targeted_countries": [c for c in (pulse.get("targeted_countries") or []) if c],
                "industries": [i for i in (pulse.get("industries") or []) if i],
                "source": "alienvault-otx",
            }
            reports.append(report)

            for ind in pulse.get("indicators", []):
                if not isinstance(ind, dict):
                    continue
                t = _OTX_TYPE.get(ind.get("type"))
                if not t:
                    continue
                out.append({
                    "type": t, "value": ind.get("indicator"),
                    # Threat type now carries real meaning, not just the pulse title.
                    "threat_type": (malware[0] if malware else name),
                    "confidence": 70, "source": "alienvault-otx",
                    "actor": adversary, "tags": tags,
                    "report_external_id": report["external_id"],
                    "first_seen": ind.get("created") or pulse.get("created"),
                })
                if len(out) >= _OTX_MAX_INDICATORS:
                    _fetch_otx.last_reports = reports
                    return out
        # Stop when the API reports no further page (guards against a server that
        # keeps returning the same page and would otherwise loop to the cap).
        if not (isinstance(data, dict) and data.get("next")):
            break
    # Hand the pulse context to the import layer alongside the indicators.
    _fetch_otx.last_reports = reports
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


def _stix_indicator_to_ioc(obj, source: str) -> dict | None:
    """Parse one STIX 2.x `indicator` object into a normalised indicator dict, or
    None if it isn't an importable indicator. Shared by the STIX-bundle (`stix`)
    and TAXII 2.1 (`taxii`) connectors so both speak the exact same STIX dialect."""
    if not isinstance(obj, dict) or obj.get("type") != "indicator":
        return None
    # STIX patterns look like: [ipv4-addr:value = '1.2.3.4']
    m = re.search(r"(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file:hashes[^=]*)"
                  r"[^=]*=\s*'([^']+)'", obj.get("pattern", ""))
    if not m:
        return None
    kind, value = m.group(1), m.group(2)
    t = ("ip" if "ipv" in kind else "domain" if "domain" in kind
         else "url" if "url" in kind else "email" if "email" in kind
         else "hash" if "hashes" in kind or "file" in kind else None)
    if not t:
        return None
    return {
        "type": t, "value": value,
        "threat_type": obj.get("name") or "stix-indicator",
        "confidence": _to_confidence(obj.get("confidence"), default=60),
        "source": source, "tags": list(obj.get("labels") or []),
    }


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
        ioc = _stix_indicator_to_ioc(obj, "stix")
        if ioc:
            out.append(ioc)
    return out


# TAXII 2.1 client pull sizing (mirrors the OTX caps): bound how far a sync walks
# a collection so it can't run unbounded. Env-tunable for larger deployments.
_TAXII_PAGE_LIMIT = int(os.environ.get("DASHBOARD_TAXII_PAGE_LIMIT", "100"))
_TAXII_MAX_PAGES = int(os.environ.get("DASHBOARD_TAXII_MAX_PAGES", "50"))
_TAXII_MAX_INDICATORS = int(os.environ.get("DASHBOARD_TAXII_MAX_INDICATORS", "100000"))
_TAXII_ACCEPT = "application/taxii+json;version=2.1"


def _fetch_taxii(c: dict) -> list[dict]:
    """Pull STIX indicators from a TAXII 2.1 collection's objects endpoint.

    The operator supplies the collection *objects* URL
    (`…/taxii2/…/collections/<id>/objects/`); auth, when the server requires it,
    reuses the same api_key/auth_header pair as the STIX connector - paste the
    full Authorization value ("Bearer <token>" or "Basic <base64>"). The TAXII
    envelope is paginated via `more`/`next`; we walk it (bounded by the caps
    above) and parse each STIX indicator object with the shared parser. Lets
    ThreatOrbit consume any TAXII 2.1 server - OpenCTI, MISP, Anomali, etc."""
    url = c.get("url")
    if not url:
        raise ValueError("TAXII connector requires the collection objects URL "
                         "(…/collections/<id>/objects/)")
    headers = {"Accept": _TAXII_ACCEPT}
    if c.get("api_key"):
        headers[c.get("auth_header") or "Authorization"] = c["api_key"]
    out: list[dict] = []
    next_cursor = None
    for _page in range(_TAXII_MAX_PAGES):
        params = {"limit": _TAXII_PAGE_LIMIT}
        if next_cursor:
            params["next"] = next_cursor
        env = _http_get(url, headers=headers, params=params).json()
        if not isinstance(env, dict):
            raise ValueError("TAXII source did not return a JSON envelope")
        for obj in env.get("objects", []):
            ioc = _stix_indicator_to_ioc(obj, "taxii")
            if ioc:
                out.append(ioc)
                if len(out) >= _TAXII_MAX_INDICATORS:
                    return out
        # TAXII 2.1 pagination: continue only while the server flags `more`.
        if not env.get("more"):
            break
        next_cursor = env.get("next")
        if not next_cursor:
            break
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


def _fetch_abusech(c: dict) -> list[dict]:
    """abuse.ch Feodo Tracker botnet C2 blocklist - real, current, keyless.

    Exists so a fresh install has genuine threat intelligence immediately: no API
    key, no URL to configure, and no dependency on the companion threat service.
    The feed is a JSON array of active C2 hosts (typically thousands)."""
    rows = _http_get(c.get("url") or ABUSECH_FEODO_URL).json()
    if not isinstance(rows, list):
        raise ValueError("abuse.ch feed did not return a JSON array")
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        ip = (r.get("ip_address") or "").strip()
        if not ip:
            continue
        malware = (r.get("malware") or "").strip()
        out.append({
            "type": "ip", "value": ip,
            "threat_type": f"botnet-c2{f' ({malware})' if malware else ''}",
            # Confirmed-active C2 from a curated blocklist: high confidence.
            "confidence": 90,
            "actor": malware,
            "source": "abuse.ch:feodo",
            "tags": [t for t in ("abusech", "feodo", "c2", malware.lower()) if t],
            "first_seen": r.get("first_seen") or None,
            "last_seen": r.get("last_online") or None,
        })
    return out



# ---------------------------------------------------------------------------
# Bulk public OSINT: the high-volume, keyless intel source.
#
# The bundled `threatorbit` connector re-serves whatever the companion threat
# service happens to hold, which in practice was a handful of indicators. This
# pulls curated public blocklists DIRECTLY, in parallel, with no API key and no
# companion dependency - tens of thousands of real indicators per sync, which is
# what makes the platform comparable to an OpenCTI feed pull. The import engine
# handles ~39k indicators/sec, so the network fetch is the only real cost.
#
# Every feed is free and keyless. A feed that fails (blocked, moved, rate
# limited) is skipped with a warning - one bad source must never zero out a sync.
# ---------------------------------------------------------------------------

def _p_iplist(text: str) -> list[tuple[str, str]]:
    """One indicator per line, `#`/`;` comments ignored. Used by most blocklists."""
    out = []
    for line in text.splitlines():
        v = line.strip()
        if not v or v[0] in "#;":
            continue
        v = v.split()[0].strip()          # some lists append notes after the IP
        if v:
            out.append((v, ""))
        if len(out) >= _BULK_MAX_PER_FEED:
            break
    return out


def _p_threatfox(text: str) -> list[tuple[str, str]]:
    """abuse.ch ThreatFox CSV: first_seen,ioc_id,ioc_value,ioc_type,threat_type,..."""
    out = []
    for row in csvmod.reader(io.StringIO(text)):
        if not row or (row[0] or "").lstrip().startswith("#") or len(row) < 5:
            continue
        value = (row[2] or "").strip().strip('"')
        malware = (row[7] or "").strip().strip('"') if len(row) > 7 else ""
        # ThreatFox encodes host:port for C2 entries - keep the host only.
        if value.count(":") == 1 and not value.startswith("http"):
            value = value.split(":")[0]
        if value:
            out.append((value, malware))
        if len(out) >= _BULK_MAX_PER_FEED:
            break
    return out


def _p_urlhaus(text: str) -> list[tuple[str, str]]:
    """abuse.ch URLhaus CSV: id,dateadded,url,url_status,last_online,threat,tags,..."""
    out = []
    for row in csvmod.reader(io.StringIO(text)):
        if not row or (row[0] or "").lstrip().startswith("#") or len(row) < 3:
            continue
        url = (row[2] or "").strip().strip('"')
        threat = (row[5] or "").strip().strip('"') if len(row) > 5 else ""
        if url.startswith("http"):
            out.append((url, threat))
        if len(out) >= _BULK_MAX_PER_FEED:
            break
    return out


def _p_hosts(text: str) -> list[tuple[str, str]]:
    """Hosts-file format: `0.0.0.0 evil.example`. The sinkhole address in column
    one is not the indicator - the domain in column two is. Parsing these with
    the plain list parser would have imported 400k copies of `0.0.0.0`."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        host = parts[1].strip().rstrip(".")
        # Every hosts file starts with real loopback entries; they are not IOCs.
        if not host or host in ("localhost", "localhost.localdomain", "broadcasthost",
                                "local", "ip6-localhost", "ip6-loopback"):
            continue
        out.append((host, ""))
        if len(out) >= _BULK_MAX_PER_FEED:
            break
    return out


def _p_netset(text: str) -> list[tuple[str, str]]:
    """FireHOL-style netsets: single addresses mixed with CIDR ranges. Only the
    single addresses are kept - the IOC store matches exact values, so importing
    `1.2.3.0/24` as a literal string would never match anything and would report
    a coverage this platform does not actually have."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;" or "/" in s:
            continue
        out.append((s.split()[0], ""))
        if len(out) >= _BULK_MAX_PER_FEED:
            break
    return out


_BULK_PARSERS = {"iplist": _p_iplist, "threatfox": _p_threatfox, "urlhaus": _p_urlhaus,
                 "hosts": _p_hosts, "netset": _p_netset}

# name, url, parser, forced type (None = auto-detect), confidence, threat_type
_BULK_FEEDS = [
    ("abuse.ch ThreatFox", "https://threatfox.abuse.ch/export/csv/recent/",
     "threatfox", None, 85, "malware-c2"),
    ("abuse.ch URLhaus", "https://urlhaus.abuse.ch/downloads/csv_recent/",
     "urlhaus", "url", 85, "malware-distribution"),
    ("abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
     "iplist", "ip", 90, "botnet-c2"),
    ("blocklist.de", "https://lists.blocklist.de/lists/all.txt",
     "iplist", "ip", 70, "attack-source"),
    ("CINS Army", "https://cinsscore.com/list/ci-badguys.txt",
     "iplist", "ip", 70, "attack-source"),
    ("Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
     "iplist", "ip", 75, "compromised-host"),
    ("Tor exit nodes", "https://check.torproject.org/torbulkexitlist",
     "iplist", "ip", 40, "anonymiser"),
    # -- Domain / URL / phishing coverage ------------------------------------
    # The list above is almost entirely IPs, which left the CTI store unable to
    # answer the question an L1 analyst asks most often: "is this domain or link
    # in a proxy log known-bad?". These add that side, and are the bulk of the
    # volume - the previous catalogue topped out around 24k indicators a sync.
    ("Phishing.Database (active domains)",
     "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "iplist", None, 80, "phishing"),
    ("Phishing.Database (active links)",
     "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
     "iplist", "url", 80, "phishing"),
    ("Blocklist Project (ransomware)",
     "https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
     "hosts", None, 80, "ransomware"),
    ("Blocklist Project (phishing)",
     "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
     "hosts", None, 70, "phishing"),
    ("Blocklist Project (scam)",
     "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
     "hosts", None, 60, "scam"),
    ("Marcoux malicious IPs",
     "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt",
     "iplist", "ip", 70, "attack-source"),
    ("Marcoux malicious domains",
     "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt",
     "iplist", None, 65, "malware-distribution"),
    ("FireHOL level2",
     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
     "netset", "ip", 70, "attack-source"),
]


# -- Attribution: the same source, one file per malware family -------------------
#
# Everything above is a blocklist: a value, and the claim that it is bad. A live
# store built from those nine reachable feeds measured 0% attributed to a malware
# family, 0% to an actor and 0% to a report - which is exactly the complaint that
# a public CTI library holds more than this engine imports. It does, if all we
# import is values.
#
# Maltrail publishes its static trails one file PER FAMILY, so the file an entry
# appears in is its attribution, straight from the source. That turns "this
# domain is bad" into "this domain is Emotet infrastructure", which is a
# different product: it gives an indicator a name to pivot on, a page worth
# opening, and a reason an analyst can put in a case.
#
# This REPLACES the aggregated `maltrail-malware-domains.txt` convenience file
# that used to be in the list above. Same upstream project, more indicators
# (IPs and URLs too, not only domains), and every one of them attributed.
#
# One `source_id` for all of them, deliberately. Corroboration counts INDEPENDENT
# sources, and thirty-six files published by one project are one opinion. Giving
# each family its own id would have manufactured thirty-six-fold agreement out of
# a single source - the precise error this store already fixed once, when sixteen
# feeds were producing one opinion because duplicates were dropped instead of
# recorded.
_MALTRAIL_SOURCE = "Maltrail malware trails"
_MALTRAIL_FAMILY_URL = (
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/{}.txt")

# family -> (what it DOES, the threat_type that follows from it). The role is
# public, uncontroversial classification - the kind of thing every vendor write-up
# of the family agrees on - not a judgement about any individual entry. Families
# below a few hundred entries are left out: the request costs the same and buys
# almost nothing.
_MALWARE_FAMILIES: dict[str, tuple[str, str]] = {
    # Loaders and botnets - the delivery layer. A hit here usually means an
    # infection that is about to fetch something worse.
    "emotet":       ("loader/botnet", "malware-c2"),
    "trickbot":     ("banking trojan/loader", "malware-c2"),
    "qakbot":       ("banking trojan/loader", "malware-c2"),
    "icedid":       ("loader/banking trojan", "malware-c2"),
    "bazarloader":  ("loader", "malware-c2"),
    "smokeloader":  ("loader", "malware-c2"),
    "amadey":       ("loader/botnet", "malware-c2"),
    "guloader":     ("shellcode loader", "malware-distribution"),
    "matanbuchus":  ("loader", "malware-c2"),
    "latrodectus":  ("loader", "malware-c2"),
    "andromeda":    ("loader/botnet", "malware-c2"),
    "zloader":      ("loader/banking trojan", "malware-c2"),
    # Bankers.
    "dridex":       ("banking trojan", "malware-c2"),
    "ursnif":       ("banking trojan", "malware-c2"),
    "gootkit":      ("banking trojan/loader", "malware-c2"),
    "zeus":         ("banking trojan", "malware-c2"),
    "danabot":      ("banking trojan/stealer", "malware-c2"),
    # Remote access trojans - commodity, sold openly, used by everyone from
    # commodity crews to state actors. Naming the family is useful; naming an
    # operator from the family alone would be invention.
    "asyncrat":     ("remote access trojan", "malware-c2"),
    "remcos":       ("remote access trojan", "malware-c2"),
    "njrat":        ("remote access trojan", "malware-c2"),
    "nanocore":     ("remote access trojan", "malware-c2"),
    "quasarrat":    ("remote access trojan", "malware-c2"),
    "xworm":        ("remote access trojan", "malware-c2"),
    # Information stealers.
    "redline":      ("information stealer", "malware-c2"),
    "raccoon":      ("information stealer", "malware-c2"),
    "vidar":        ("information stealer", "malware-c2"),
    "azorult":      ("information stealer", "malware-c2"),
    "lokibot":      ("information stealer", "malware-c2"),
    "formbook":     ("information stealer", "malware-c2"),
    "agenttesla":   ("information stealer/keylogger", "malware-c2"),
    "arkei":        ("information stealer", "malware-c2"),
    # Post-exploitation framework. Commercial software, licensed legitimately by
    # red teams and cracked by nearly every intrusion set there is - which is why
    # it is the clearest case for keeping family and actor apart.
    "cobaltstrike": ("post-exploitation framework", "malware-c2"),
    # Spam and worm botnets.
    "tofsee":       ("spam botnet", "botnet-c2"),
    "necurs":       ("spam botnet", "botnet-c2"),
    "ramnit":       ("worm/botnet", "malware-c2"),
}

# Confidence for a family trail. Below the abuse.ch feeds (which carry a
# reporter and an expiry per entry) and above the undifferentiated aggregations,
# because the file an entry sits in is a real, specific claim and the project
# curates them - but no evidence travels with the individual line.
_FAMILY_CONFIDENCE = 72


def family_feeds() -> list[tuple[str, str, str, str]]:
    """(family, url, role, threat_type) for every tracked family."""
    return [(f, _MALTRAIL_FAMILY_URL.format(f), role, threat)
            for f, (role, threat) in _MALWARE_FAMILIES.items()]


def _bulk_source_id(name: str) -> str:
    """The `source` (and so `observable_sources.source_id`) a bulk feed writes.

    One function so that "which feeds have actually contributed?" is answered
    against the same string the importer wrote, rather than against a prefix a
    caller guessed and that silently stops matching if this changes."""
    return f"osint:{name}"


def bulk_feed_source_ids() -> set[str]:
    """Every configured bulk feed's source_id, for coverage questions.

    The family trails contribute ONE id however many files they span - see
    _MALTRAIL_SOURCE - so "how many sources actually contributed?" counts one
    project once."""
    return {_bulk_source_id(f[0]) for f in _BULK_FEEDS} | {_bulk_source_id(_MALTRAIL_SOURCE)}


# Admiralty reliability, per feed. The score treats this as a MULTIPLIER on
# whatever the feed claims, which is the right shape - but every source shipped
# ungraded at the default C, so the multiplier was uniform across all 327,981
# indicators and differentiated nothing. The observed consequence: 20 distinct
# scores across the whole store, 95% of it inside a 15-point band, and a list
# sorted by score that opened on whichever phishing domain sorted first
# alphabetically.
#
# These are OUR starting assessment, not a measurement, so each one states the
# property it is based on and an operator can change any of them (the default is
# only ever applied to a source they have not graded themselves). The property in
# question is always the same: does the feed publish per-entry evidence, is it
# curated or aggregated, and does it age its own entries out. That is a judgement
# about the SOURCE, not about whether a given entry is correct.
#
# Deliberately no A: "completely reliable" is a claim about a long history with
# no known failures, and it is not ours to award to a public list.
_FEED_RELIABILITY: dict[str, tuple[str, str]] = {
    # -- B, usually reliable: per-entry provenance, actively maintained --------
    "abuse.ch ThreatFox":
        ("B", "Per-IOC submissions carrying a reporter, a malware family and the "
              "submitter's own confidence; entries are reviewed and expire."),
    "abuse.ch URLhaus":
        ("B", "Each URL is tracked with a status and re-checked, so a dead entry "
              "is retired rather than left to age in place."),
    "abuse.ch Feodo Tracker":
        ("B", "Tracks the C2 servers of specific named botnets rather than "
              "generic badness - a narrow claim about identified infrastructure."),
    "Tor exit nodes":
        ("B", "Published by the Tor Project itself, so it is first-party and "
              "authoritative for exactly what it asserts. That being a Tor exit "
              "is not by itself a threat is a question of severity, not of "
              "whether the source is right."),
    # -- C, fairly reliable: real observation or vetted composition, but no
    #    evidence attached to the individual entry ---------------------------
    "blocklist.de":
        ("C", "Automated abuse reports from participating servers - a real "
              "observation, but high-volume and short-lived."),
    "CINS Army":
        ("C", "Derived from Sentinel IPS sensor telemetry via a scoring "
              "heuristic; observed, but the per-entry reasoning is not published."),
    "Emerging Threats":
        ("C", "Maintained conservatively and kept small, which is a good sign, "
              "but individual entries arrive without evidence."),
    "FireHOL level2":
        ("C", "A composition of vetted upstream lists with published inclusion "
              "criteria and a stated false-positive policy."),
    "Blocklist Project (ransomware)":
        ("C", "Narrow and specific enough that inclusion is itself informative."),
    "Maltrail malware trails":
        ("C", "Curated one file per malware family, so the file an entry appears "
              "in IS its attribution - a specific claim rather than a general "
              "one. No evidence or expiry travels with the individual line, "
              "which is what keeps it below the abuse.ch feeds."),
    # -- D, not usually reliable: bulk aggregation with no per-entry provenance.
    #    Useful in volume; a single entry is a weak claim on its own. ---------
    "Phishing.Database (active domains)":
        ("D", "Tens of thousands of entries aggregated from several upstreams; "
              "'active' is a periodic re-check, not evidence for the entry."),
    "Phishing.Database (active links)":
        ("D", "Same aggregation and the same re-check, at URL granularity."),
    "Marcoux malicious IPs":
        ("D", "A bulk dump compiled from other lists; no provenance survives "
              "the aggregation."),
    "Marcoux malicious domains":
        ("D", "As above, at domain granularity."),
    "Blocklist Project (phishing)":
        ("D", "Broad hosts-format aggregation covering a very general category."),
    "Blocklist Project (scam)":
        ("D", "Broadest category in the set, and the least specific claim."),
}


def feed_reliability_defaults() -> dict[str, tuple[str, str]]:
    """Shipped Admiralty grade + stated reason, keyed by source_id."""
    return {_bulk_source_id(name): gr for name, gr in _FEED_RELIABILITY.items()}


# Deliberately NOT included: the undifferentiated multi-million-entry hosts
# aggregations (e.g. Blocklist Project's `malware`/`abuse` lists). They exceed
# the per-feed cap several times over, so we would import whatever happens to
# sort first alphabetically - a biased sample rather than a representative one -
# and their contents are broad enough that the extra rows would mostly add noise
# to analyst lookups. Volume is only worth having when it is volume of signal.

# Per-feed cap keeps one huge list from dominating a sync (and bounds memory);
# raise DASHBOARD_BULK_MAX_PER_FEED for a fuller pull.
_BULK_MAX_PER_FEED = int(os.environ.get("DASHBOARD_BULK_MAX_PER_FEED", "50000"))
_BULK_WORKERS = int(os.environ.get("DASHBOARD_BULK_WORKERS", "8"))
# Stop downloading a curated blocklist once we have comfortably more bytes than
# the per-feed entry cap can use. Several of these feeds run to tens of MB while
# we keep only the first _BULK_MAX_PER_FEED entries, so reading the rest costs
# bandwidth and time for rows that are discarded on arrival. ~120 bytes/entry is
# a generous allowance for the widest of these formats (a full phishing URL).
_BULK_FEED_MAX_BYTES = int(os.environ.get(
    "DASHBOARD_BULK_FEED_MAX_BYTES", str(max(4 * 1024 * 1024, _BULK_MAX_PER_FEED * 120))))


def _fetch_bulk_osint(c: dict) -> list[dict]:
    """Pull every curated public blocklist in parallel and normalise the lot.

    Parallel because these are network-bound: fetched serially the sync would
    take as long as the sum of every chain, while the DB side ingests the lot at
    tens of thousands per second. The network is the only real cost here."""
    from concurrent.futures import ThreadPoolExecutor

    # OpenCTI keeps a per-connector "state" so a re-run doesn't re-ingest what it
    # already has. These blocklists have no cursor, but they DO serve HTTP
    # validators - so we store ETag/Last-Modified per feed and send a conditional
    # request. An unchanged feed answers 304 with no body: nothing to download,
    # nothing to parse, nothing to dedup. That is what makes a short cadence
    # sensible instead of re-pulling tens of thousands of identical rows.
    state = c.get("state") or {}
    if isinstance(state, str):
        try:
            state = json.loads(state)
        except (ValueError, TypeError):
            state = {}
    new_state: dict = {}
    unchanged: list[str] = []

    def one(feed):
        name, url, parser, forced, conf, threat = feed
        prev = state.get(url) or {}
        cond = {}
        if prev.get("etag"):
            cond["If-None-Match"] = prev["etag"]
        if prev.get("last_modified"):
            cond["If-Modified-Since"] = prev["last_modified"]
        try:
            resp = _http_get(url, headers=cond or None, truncate_at=_BULK_FEED_MAX_BYTES)
            if getattr(resp, "not_modified", False):
                new_state[url] = prev            # keep the validator; feed unchanged
                unchanged.append(name)
                return []
            h = getattr(resp, "headers", {}) or {}
            if h.get("etag") or h.get("last-modified"):
                new_state[url] = {"etag": h.get("etag"),
                                  "last_modified": h.get("last-modified")}
            pairs = _BULK_PARSERS[parser](resp.text)
        except Exception as e:                    # one dead feed must not zero the sync
            logging.warning("bulk OSINT feed %s failed: %s", name, e)
            new_state[url] = prev                 # don't lose a good validator on a blip
            return []
        rows = []
        for value, note in pairs:
            t = forced or guess_type(value)
            if not t or t not in _IOC_TYPES:
                continue
            rows.append({
                "type": t, "value": value,
                "threat_type": f"{threat}{f' ({note})' if note else ''}",
                "confidence": conf,
                # Only ThreatFox produces a note here, and what it produces is a
                # malware family. It used to be written into `actor`, so the
                # attribution column filled up with the names of commodity tools
                # and the store reported an adversary it had never identified.
                "malware_family": note or "",
                "actor": "",
                "source": _bulk_source_id(name),
                "tags": ["osint", "public-feed"] + ([f"malware:{note.lower()}"] if note else []),
            })
        return rows

    def one_family(feed):
        """One malware-family trail. Same conditional-GET contract as `one`;
        what differs is that every row comes out ATTRIBUTED - the file is the
        family, straight from the source, rather than a label we inferred."""
        family, url, role, threat = feed
        prev = state.get(url) or {}
        cond = {}
        if prev.get("etag"):
            cond["If-None-Match"] = prev["etag"]
        if prev.get("last_modified"):
            cond["If-Modified-Since"] = prev["last_modified"]
        try:
            resp = _http_get(url, headers=cond or None, truncate_at=_BULK_FEED_MAX_BYTES)
            if getattr(resp, "not_modified", False):
                new_state[url] = prev
                unchanged.append(family)
                return []
            h = getattr(resp, "headers", {}) or {}
            if h.get("etag") or h.get("last-modified"):
                new_state[url] = {"etag": h.get("etag"),
                                  "last_modified": h.get("last-modified")}
            pairs = _p_iplist(resp.text)
        except Exception as e:
            # A family that 404s (renamed or retired upstream) must not cost the
            # other thirty-five, and must not look like a failed sync.
            logging.warning("malware family trail %s failed: %s", family, e)
            new_state[url] = prev
            return []
        rows = []
        for value, _ in pairs:
            t = guess_type(value)
            if not t or t not in _IOC_TYPES:
                continue
            rows.append({
                "type": t, "value": value,
                "threat_type": f"{threat} ({family})",
                "confidence": _FAMILY_CONFIDENCE,
                # The family goes in its own field. It is NOT the actor: every
                # RAT and stealer in this catalogue is sold to whoever pays, and
                # Cobalt Strike is licensed software. Writing the family into
                # `actor` - which is what the ThreatFox path used to do - turns a
                # fact the source published into an attribution nobody can
                # defend.
                "malware_family": family,
                "actor": "",
                "source": _bulk_source_id(_MALTRAIL_SOURCE),
                "tags": ["osint", "public-feed", f"malware:{family}", role],
            })
        return rows

    out: list[dict] = []
    families = family_feeds()
    with ThreadPoolExecutor(max_workers=_BULK_WORKERS) as pool:
        blocklists = pool.map(one, _BULK_FEEDS)
        attributed = pool.map(one_family, families)
        for rows in blocklists:
            out.extend(rows)
        for rows in attributed:
            out.extend(rows)
    total_feeds = len(_BULK_FEEDS) + len(families)
    if unchanged:
        logging.info("bulk OSINT: %d/%d feeds unchanged since last sync (%s)",
                     len(unchanged), total_feeds, ", ".join(unchanged))
    # Hand the refreshed validators back so run_connector can persist them.
    _fetch_bulk_osint.last_state = new_state
    return out


_FETCHERS = {
    "threatorbit": _fetch_threatorbit, "otx": _fetch_otx, "nvd": _fetch_nvd,
    "json": _fetch_json, "csv": _fetch_csv, "stix": _fetch_stix,
    "taxii": _fetch_taxii,
    # Retired kinds: the engine now aggregates these feeds itself, so they are
    # no longer offered in the UI - but existing connectors must keep working.
    "abusech": _fetch_abusech, "osint": _fetch_bulk_osint, "darkweb-json": _fetch_darkweb_json,
}


# -- Orchestration ---------------------------------------------------------------

def describe_fetch_error(exc: Exception, connector: dict) -> str:
    """Turn a transport exception into something an operator can act on.

    The raw text was httpx's own: "Client error '403 Forbidden' for url
    'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=1'" plus a
    link to MDN. That does not distinguish the two failures operators actually
    hit - a key the provider rejected, and a provider this host cannot reach at
    all - and those have completely different fixes. Guessing wrong sends people
    hunting a bad key when their network is blocking the domain, or the reverse.
    """
    kind = connector.get("kind", "")
    label = KIND_PRESETS.get(kind, {}).get("label", kind or "This source")
    needs_key = KIND_PRESETS.get(kind, {}).get("needs_key", False)

    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status in (401, 403):
        if needs_key:
            return (f"{label} rejected the API key (HTTP {status}). Check the key is correct "
                    f"and pasted in full, and that it is still active with the provider.")
        return (f"{label} refused the request (HTTP {status}). The endpoint may require "
                f"authentication, or this host may be blocked by the provider.")
    if status == 429:
        return (f"{label} is rate-limiting this key (HTTP 429). The next scheduled sync "
                f"will retry; lengthening the interval will stop it recurring.")
    if status == 404:
        return f"{label} returned HTTP 404 - the feed URL looks wrong or the feed has moved."
    if status and status >= 500:
        return f"{label} is having server trouble (HTTP {status}). This is on their side; it will retry."
    if isinstance(exc, httpx.TimeoutException):
        return (f"Timed out talking to {label}. The host is reachable but slow or "
                f"partially blocked - check any proxy or firewall on this machine.")
    if isinstance(exc, httpx.RequestError):
        # Every transport failure, not just ConnectError: a proxy refusing the
        # tunnel raises ProxyError with no `.response` at all, and reached this
        # function as the bare string "403 Forbidden" - which reads exactly like
        # a rejected credential and is the one thing it cannot be. ReadError and
        # RemoteProtocolError are the same class of problem. None are key issues.
        host = ""
        try:
            host = httpx.URL(connector.get("url") or "").host or ""
        except (ValueError, TypeError):
            pass
        where = f" ({host})" if host else ""
        detail = str(exc).strip()
        via = " A proxy on this machine refused the connection." if isinstance(
            exc, httpx.ProxyError) else ""
        return (f"Could not reach {label}{where} from this machine.{via} DNS, a proxy or a "
                f"firewall is blocking it - this is not an API-key problem. Other connectors "
                f"are unaffected."
                + (f" [{detail[:80]}]" if detail else ""))
    return str(exc)[:300]


def _retry_after_from(exc: Exception, connector: dict) -> str | None:
    """When a 429 says we may try again, as an ISO timestamp - else None.

    Prefers the provider's own `Retry-After` (seconds, or an HTTP date). Falls
    back to twice the connector's cadence, capped, so a provider that rate-limits
    without saying for how long still gets breathing room."""
    resp = getattr(exc, "response", None)
    if getattr(resp, "status_code", None) != 429:
        return None
    wait = None
    raw = (getattr(resp, "headers", {}) or {}).get("retry-after")
    if raw:
        try:
            wait = int(float(str(raw).strip()))
        except (TypeError, ValueError):
            try:
                from email.utils import parsedate_to_datetime
                when = parsedate_to_datetime(str(raw))
                wait = int((when - datetime.now(timezone.utc)).total_seconds())
            except Exception:
                wait = None
    if wait is None:
        wait = min(3600, max(60, connector_interval_seconds(connector) * 2))
    wait = max(1, min(wait, 86400))
    return (datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(seconds=wait)).isoformat()


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

    import time as _time
    _t0 = _time.perf_counter()
    try:
        indicators = fetch(connector)
        if connector["kind"] == "darkweb-json":
            # dark-web feeds sink into findings (not the IOC store) and run
            # credential matching against the user directory.
            from dashboard_api.darkweb_logic import import_findings
            result = import_findings(indicators, connector["name"])
        else:
            # Pulse-shaped sources (OTX) hand back report context alongside the
            # indicators. Persist the reports first so every indicator can carry
            # its report_id - attribution and TTPs travel WITH the value.
            pulses = getattr(fetch, "last_reports", None)
            if pulses:
                rid_by_ext = upsert_intel_reports(pulses, connector["kind"])
                for ind in indicators:
                    ext = ind.get("report_external_id")
                    if ext and ext in rid_by_ext:
                        ind["report_id"] = rid_by_ext[ext]
                fetch.last_reports = None          # don't leak into the next run
            # Open a work now that we know how much was fetched, so the UI can
            # show real progress (processed/expected) while this runs.
            work_id = start_work(connector["name"], cid, len(indicators))
            try:
                result = import_indicators(indicators, connector["name"], work_id=work_id)
                finish_work(work_id, "completed", processed=len(indicators), **{
                    k: result.get(k, 0) for k in ("imported", "duplicates", "skipped")})
            except Exception:
                finish_work(work_id, "failed", "import failed")
                raise
        with get_conn() as conn:
            # Persist the connector's state (HTTP validators) so the NEXT run can
            # ask "changed?" instead of re-downloading everything.
            new_state = getattr(fetch, "last_state", None)
            if new_state:
                conn.execute(
                    "UPDATE connectors SET status='ok', last_run=?, last_error=NULL, "
                    "indicator_count=indicator_count+?, state=? WHERE id=?",
                    (_now(), result["imported"], dumps(new_state), cid),
                )
            else:
                conn.execute(
                    "UPDATE connectors SET status='ok', last_run=?, last_error=NULL, "
                    "indicator_count=indicator_count+? WHERE id=?",
                    (_now(), result["imported"], cid),
                )
            record_job(conn, f"connector.{connector['kind']}", "completed",
                       {"connector": connector["name"], **result, "actor": actor})
            # Also log it as an IMPORT. The Feeds → Import history reads
            # ioc_imports; without this a connector could pull thousands of
            # indicators and the operator would still see an empty import log.
            record_ioc_import(conn, connector["name"], f"connector:{connector['kind']}",
                              result.get("imported", 0), result.get("duplicates", 0),
                              result.get("skipped", 0), actor,
                              duration_ms=int((_time.perf_counter() - _t0) * 1000))
            audit(conn, actor, "connector.run", cid,
                  f"kind={connector['kind']} imported={result['imported']}")
            conn.commit()
            # Running total for this connector, read back after the update.
            #
            # This used to count `iocs WHERE source LIKE '%<connector name>%'`,
            # which reported 0 for every aggregating connector: the bundled
            # engine records each indicator under its originating feed
            # (`osint:Maltrail malware domains`), so the connector's own name
            # appears in no source string - a sync of 310,788 indicators
            # reported a total of zero. The pattern was also unsafe as a
            # match: `%` and `_` in a connector name are LIKE wildcards, and a
            # short name matched any source that merely contained it.
            if connector["kind"] == "darkweb-json":
                total_count = conn.execute(
                    "SELECT COUNT(*) AS n FROM dark_web_findings WHERE source=?",
                    (connector["name"],)).fetchone()["n"]
            else:
                row = conn.execute("SELECT indicator_count FROM connectors WHERE id=?",
                                   (cid,)).fetchone()
                total_count = (row["indicator_count"] if row else 0) or 0
        result["connectorTotal"] = total_count
        return result
    except Exception as e:  # network/parse/auth failure - record, never crash
        msg = describe_fetch_error(e, connector)[:300]
        # A 429 is the provider telling us when to come back. Retrying into it on
        # the next tick is how a connector spends its life rate-limited and
        # imports nothing; honour Retry-After (or back off a sensible default)
        # and let the scheduler skip until then.
        retry_at = _retry_after_from(e, connector)
        if retry_at:
            try:
                with get_conn() as conn:
                    conn.execute("UPDATE connectors SET next_allowed_at=? WHERE id=?",
                                 (retry_at, cid))
                    conn.commit()
            except Exception:
                logging.debug("recording rate-limit backoff failed", exc_info=True)
        # If the failure happened during the fetch there is no work yet; record
        # one so a failed sync is visible in the pipeline view too.
        try:
            if "work_id" not in dir():
                finish_work(start_work(connector["name"], cid, 0), "failed", msg)
        except Exception:
            logging.debug("failed-work record failed", exc_info=True)
        with get_conn() as conn:
            conn.execute("UPDATE connectors SET status='error', last_run=?, last_error=? WHERE id=?",
                         (_now(), msg, cid))
            record_job(conn, f"connector.{connector['kind']}", "failed",
                       {"connector": connector["name"], "error": msg, "actor": actor})
            # A failed sync belongs in the import log too - silence is what made
            # "nothing shows up at imports" impossible to diagnose.
            record_ioc_import(conn, connector["name"], f"connector:{connector['kind']}",
                              0, 0, 0, actor, error=msg,
                              duration_ms=int((_time.perf_counter() - _t0) * 1000))
            conn.commit()
        return {"error": msg}


def seed_builtin_connectors():
    """Ensure the bundled connectors exist (idempotent). Called on live boot."""
    now = _now()
    builtins = [
        # Keyless + high-volume + no companion dependency: this is what makes a
        # fresh install show REAL indicators after one sync, instead of only the
        # simulated engine data.
        # One engine. It aggregates the public feeds itself; seeding separate
        # "bulk"/"abuse.ch" connectors alongside it just imported the same
        # indicators twice under different names.
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


# Floor on how often a connector may poll. Sub-minute cadence is supported, but
# a hard floor keeps a misconfigured connector from hammering a third-party feed
# (and getting the deployment rate-limited or banned).
MIN_INTERVAL_SECONDS = int(os.environ.get("DASHBOARD_MIN_CONNECTOR_SECONDS", "1"))

# How long a connector may sit at status='running' before the scheduler assumes
# the run died and retries it. Generous vs the bounded fetch (_TIMEOUT per HTTP
# hop, plus paging), so a healthy long sync is never pre-empted - but a wedged
# one recovers on its own instead of needing a restart.
STUCK_RUNNING_AFTER = int(os.environ.get("DASHBOARD_CONNECTOR_STUCK_SECONDS", "900"))


def min_interval_for(kind: str) -> int:
    """The shortest cadence a provider tolerates.

    The global floor is 1s, which is right for a source the operator runs
    themselves - it is their server. It is wrong for a managed third party: NVD
    permits 5 requests per rolling 30s without a key, so a 1s cadence earns a
    steady stream of HTTP 429 and imports nothing. The floor belongs to the
    provider, not to the platform."""
    return int(KIND_PRESETS.get(kind, {}).get("min_interval", MIN_INTERVAL_SECONDS))


def interval_floor_reason(kind: str) -> str | None:
    """Why a provider imposes its floor, for the message shown to the operator.
    'Minimum 30s' with no reason reads as an arbitrary restriction."""
    return KIND_PRESETS.get(kind, {}).get("rate_note")


def connector_interval_seconds(c: dict) -> int:
    """A connector's sync cadence in seconds.

    `interval_seconds` is the source of truth; rows predating it (or set to 0)
    fall back to the legacy `interval_minutes`. Never returns less than the
    provider's own floor."""
    secs = int(c.get("interval_seconds") or 0)
    if secs <= 0:
        secs = int(c.get("interval_minutes") or 60) * 60
    return max(min_interval_for(c.get("kind", "")), secs)


def reset_stuck_connectors() -> int:
    """Clear connectors left mid-sync by a crash/kill (status='running').

    `run_due_connectors` skips anything already 'running' so a sync can't overlap
    itself - but that means a process killed mid-sync leaves the row stuck at
    'running' FOREVER: the UI shows a permanent "sync in progress" and the
    connector never syncs again. Called at startup, when nothing can legitimately
    be running yet. Returns how many rows were recovered."""
    with get_conn() as conn:
        n = conn.execute(
            "UPDATE connectors SET status='idle', "
            "last_error='Interrupted - the service restarted mid-sync' "
            "WHERE status='running'").rowcount
        conn.commit()
    return n or 0


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
        for jcol, default in (("field_map", {}), ("state", {})):
            if isinstance(c.get(jcol), str):
                try:
                    c[jcol] = json.loads(c[jcol])
                except (ValueError, TypeError):
                    c[jcol] = default
        # A provider that returned 429 told us when to come back; until then this
        # connector is not due no matter what its cadence says.
        if c.get("next_allowed_at"):
            try:
                if now < datetime.fromisoformat(c["next_allowed_at"]):
                    continue
            except (ValueError, TypeError):
                pass
        due = True
        if c.get("last_run"):
            try:
                last = datetime.fromisoformat(c["last_run"])
                due = now - last >= timedelta(seconds=connector_interval_seconds(c))
            except ValueError:
                due = True
        # Skip a connector that is genuinely mid-sync, but don't let 'running'
        # become a permanent state: a hung fetch (or a kill between the status
        # write and the result write) would otherwise wedge this feed forever.
        # After STUCK_RUNNING_AFTER with no completion, treat it as dead and
        # re-run - the fetch itself is bounded by _TIMEOUT, so a genuine sync is
        # never this old.
        stuck = False
        if c.get("status") == "running":
            try:
                last = datetime.fromisoformat(c["last_run"]) if c.get("last_run") else None
            except ValueError:
                last = None
            stuck = last is None or (now - last) >= timedelta(seconds=STUCK_RUNNING_AFTER)
        if due and (c.get("status") != "running" or stuck):
            # Fenced per connector. run_connector already swallows fetch/parse
            # failures, but the status write and the fetcher dispatch around them
            # do not - and an exception escaping here aborted the whole tick, so
            # every connector AFTER the failing one silently never ran. Row order
            # is stable, so the same feeds would be starved on every tick while
            # the UI showed them merely as "not due yet". One broken connector
            # must never be able to stop the others.
            try:
                res = run_connector(c, actor="scheduler")
            except Exception as e:                       # noqa: BLE001
                logging.getLogger(__name__).exception(
                    "connector %s crashed the scheduler tick", c.get("name"))
                res = {"error": describe_fetch_error(e, c)[:300]}
                try:
                    with get_conn() as conn:
                        conn.execute(
                            "UPDATE connectors SET status='error', last_error=? WHERE id=?",
                            (res["error"], c["id"]))
                        conn.commit()
                except Exception:                        # noqa: BLE001
                    pass                                 # never let bookkeeping stop the tick
            ran.append({"connector": c["name"], **res})
    return ran
