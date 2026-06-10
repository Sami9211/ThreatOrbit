"""Threat-intel connector engine.

Connectors pull indicators from real sources and normalise them into the
single CTI IOC store the whole dashboard reads from — the same model OpenCTI
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
import re
import uuid
from datetime import datetime, timezone

import httpx

from dashboard_api.config import THREAT_API_URL, SERVICES_API_KEY
from dashboard_api.db import audit, dumps, get_conn, record_job

_TIMEOUT = 20.0
_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "cve"}

# Connector presets surfaced to the UI's "Add connector" form.
KIND_PRESETS = {
    "threatorbit": {
        "label": "ThreatOrbit OSINT Engine",
        "description": "Our own engine: abuse.ch, RSS, dark-web & social OSINT, plus OTX if a key is set. Free, no key needed.",
        "needs_key": False,
        "default_url": THREAT_API_URL,
        "default_interval": 30,
    },
    "nvd": {
        "label": "NVD CVE Feed",
        "description": "National Vulnerability Database — recent CVEs with CVSS severity. Free, no key (a NVD key raises rate limits).",
        "needs_key": False,
        "default_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "default_interval": 720,
    },
    "otx": {
        "label": "AlienVault OTX",
        "description": "Your subscribed OTX pulses. Get a free API key at otx.alienvault.com (Settings → API).",
        "needs_key": True,
        "default_url": "https://otx.alienvault.com",
        "default_interval": 120,
    },
    "json": {
        "label": "Custom JSON source",
        "description": "Any endpoint returning a JSON array of indicators. Map which fields hold the value/type. Build your own feed and connect it here.",
        "needs_key": False,
        "default_url": "",
        "default_interval": 60,
    },
    "csv": {
        "label": "Custom CSV source",
        "description": "Any endpoint returning CSV. Map which columns hold the value/type.",
        "needs_key": False,
        "default_url": "",
        "default_interval": 60,
    },
    "stix": {
        "label": "Custom STIX 2.x bundle",
        "description": "Any endpoint returning a STIX 2.x bundle; indicator objects are imported.",
        "needs_key": False,
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


def _http_get(url: str, headers: dict | None = None, params: dict | None = None):
    r = httpx.get(url, headers=headers or {}, params=params or {}, timeout=_TIMEOUT,
                  follow_redirects=True)
    r.raise_for_status()
    return r


def _http_post(url: str, headers: dict | None = None, json_body: dict | None = None):
    r = httpx.post(url, headers=headers or {}, json=json_body or {}, timeout=_TIMEOUT,
                   follow_redirects=True)
    r.raise_for_status()
    return r


# ── Normalisation + import ─────────────────────────────────────────────────────

def _severity_from_confidence(c: int) -> str:
    return "critical" if c >= 85 else "high" if c >= 70 else "medium" if c >= 40 else "low"


def _import(indicators: list[dict], source: str) -> dict:
    """Dedup-by-value upsert of normalised indicators into the IOC store."""
    now = _now()
    imported = duplicates = skipped = 0
    with get_conn() as conn:
        for ind in indicators:
            value = (ind.get("value") or "").strip()
            itype = (ind.get("type") or "").strip().lower() or (guess_type(value) or "")
            if not value or itype not in _IOC_TYPES:
                skipped += 1
                continue
            if conn.execute("SELECT 1 FROM iocs WHERE value=?", (value,)).fetchone():
                duplicates += 1
                continue
            conf = max(0, min(100, int(ind.get("confidence") or 50)))
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), itype, value,
                 ind.get("threat_type") or "malicious-activity", conf,
                 ind.get("severity") or _severity_from_confidence(conf),
                 ind.get("source") or source, ind.get("actor") or "",
                 ind.get("first_seen") or now, ind.get("last_seen") or now,
                 dumps(list(ind.get("tags") or []))),
            )
            imported += 1
        conn.commit()
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(indicators)}


# ── Per-kind fetchers (return normalised indicator dicts) ───────────────────────

_THREATORBIT_TYPE = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash",
                     "md5": "hash", "sha1": "hash", "sha256": "hash", "email": "email"}


def _fetch_threatorbit(c: dict) -> list[dict]:
    base = (c.get("url") or THREAT_API_URL).rstrip("/")
    headers = {"X-API-Key": SERVICES_API_KEY} if SERVICES_API_KEY else {}
    rows = _http_get(f"{base}/iocs", headers=headers, params={"limit": 1000}).json()
    out = []
    for it in rows:
        t = _THREATORBIT_TYPE.get((it.get("ioc_type") or "").lower())
        if not t:
            continue
        out.append({
            "type": t, "value": it.get("value"),
            "threat_type": it.get("threat_type") or "malicious-activity",
            "confidence": int(it.get("confidence") or 50),
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
    for pulse in data.get("results", []):
        name = pulse.get("name", "OTX pulse")
        tags = list(pulse.get("tags") or [])[:5]
        for ind in pulse.get("indicators", []):
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
    out = []
    for item in data.get("vulnerabilities", []):
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
        "confidence": int(pick("confidence") or 50),
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
    out = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
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
            "confidence": int(obj.get("confidence") or 60),
            "source": "stix", "tags": list(obj.get("labels") or []),
        })
    return out


_FETCHERS = {
    "threatorbit": _fetch_threatorbit, "otx": _fetch_otx, "nvd": _fetch_nvd,
    "json": _fetch_json, "csv": _fetch_csv, "stix": _fetch_stix,
}


# ── Orchestration ───────────────────────────────────────────────────────────────

def run_connector(connector: dict, actor: str = "scheduler") -> dict:
    """Fetch + normalise + import one connector. Updates its status and records
    a job. Returns the import tally (or an {error} dict on failure)."""
    cid = connector["id"]
    fetch = _FETCHERS.get(connector["kind"])
    if fetch is None:
        return {"error": f"unknown connector kind: {connector['kind']}"}

    with get_conn() as conn:
        conn.execute("UPDATE connectors SET status='running' WHERE id=?", (cid,))
        conn.commit()

    try:
        indicators = fetch(connector)
        result = _import(indicators, connector["name"])
        with get_conn() as conn:
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
    except Exception as e:  # network/parse/auth failure — record, never crash
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
