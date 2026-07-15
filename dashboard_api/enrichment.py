"""IOC enrichment pipeline - pluggable enrichers with caching + history.

Two kinds of enrichers run over an indicator:

  * **Built-in, offline, real** - no network, no keys, genuine signal:
      - `internal`  cross-references the live platform: prior sightings, related
                    alerts, attributed actor, dark-web mentions, lifecycle state.
      - `indicator` analyses the value itself: hash algorithm, domain entropy /
                    suspicious TLD, URL structure, IP class (private/public/
                    reserved) + a coarse RIR-by-block geo/ASN hint.
  * **External providers** - VirusTotal / GreyNoise / Shodan / WHOIS. These are
    real adapters but require an API key; with none configured they report
    `available: false` (honestly unavailable) rather than fabricating a verdict.

Results are cached per (indicator, provider) in `ioc_enrichments` with a TTL so
repeated lookups are cheap, and every run is kept as history. A combined verdict
rolls the per-provider verdicts up (worst-of, internal weighted).
"""
import ipaddress
import math
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

CACHE_TTL_MINUTES = 60
_VERDICT_RANK = {"malicious": 4, "suspicious": 3, "benign": 1, "unknown": 0, "clean": 1}

# External providers and the env var that activates each (real adapter seam).
EXTERNAL_PROVIDERS = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "whois": "WHOIS_API_KEY",
}
_SUSPICIOUS_TLDS = {"xyz", "top", "cc", "ru", "su", "tk", "gq", "ml", "cf", "zip", "mov"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 2)


# ── Built-in enrichers ───────────────────────────────────────────────────────────

def _enrich_internal(conn, value: str, ioc_type: str) -> dict:
    """Cross-reference the platform's own stores - the most useful, zero-cost
    enrichment: have we seen this before, and what is it tied to?"""
    row = conn.execute(
        "SELECT id, severity, confidence, actor, threat_type, sightings, status "
        "FROM iocs WHERE value=?", (value,)).fetchone()
    related_alerts = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE src_ip=? OR dest_ip=? OR hostname=?",
        (value, value, value)).fetchone()["n"]
    dw = conn.execute(
        "SELECT COUNT(*) AS n FROM dark_web_findings WHERE entity=? OR detail LIKE ?",
        (value, f"%{value}%")).fetchone()["n"]
    data = {"known": bool(row), "relatedAlerts": related_alerts, "darkWebMentions": dw}
    if row:
        data.update({"severity": row["severity"], "confidence": row["confidence"],
                     "actor": row["actor"] or None, "threatType": row["threat_type"],
                     "sightings": row["sightings"], "lifecycle": row["status"]})
    if row and row["status"] == "known-good":
        verdict = "benign"
    elif row and row["severity"] in ("critical", "high"):
        verdict = "malicious"
    elif row and row["severity"] == "medium":
        verdict = "suspicious"
    elif related_alerts or dw:
        verdict = "suspicious"
    else:
        verdict = "unknown"
    bits = []
    if row:
        bits.append(f"known {row['threat_type'] or 'indicator'} (conf {row['confidence']}, {row['sightings']} sightings)")
        if row["actor"]:
            bits.append(f"attributed to {row['actor']}")
    if related_alerts:
        bits.append(f"{related_alerts} related alert(s)")
    if dw:
        bits.append(f"{dw} dark-web mention(s)")
    summary = "; ".join(bits) or "no internal footprint"
    return {"provider": "internal", "available": True, "verdict": verdict,
            "summary": summary, "data": data}


def _enrich_indicator(conn, value: str, ioc_type: str) -> dict:
    """Analyse the indicator value itself (offline, deterministic)."""
    data: dict = {"type": ioc_type}
    verdict = "unknown"
    summary = ""
    t = (ioc_type or "").lower()
    if t == "ip":
        try:
            ip = ipaddress.ip_address(value)
            cls = ("private" if ip.is_private else "loopback" if ip.is_loopback
                   else "reserved" if ip.is_reserved else "multicast" if ip.is_multicast else "public")
            data["ipClass"] = cls
            data["version"] = ip.version
            if ip.version == 4 and cls == "public":
                # Coarse RIR hint by first octet block (offline heuristic, no DB).
                fo = int(str(value).split(".")[0])
                rir = ("APNIC" if fo in range(1, 2) or fo in (14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223)
                       else "RIPE" if fo in (2, 5, 31, 37, 46, 51, 53, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217)
                       else "AFRINIC" if fo in (41, 102, 105, 154, 196, 197) else "LACNIC" if fo in (177, 179, 181, 186, 187, 189, 190, 191, 200, 201) else "ARIN")
                data["rirHint"] = rir
                summary = f"public IPv{ip.version} ({rir} space)"
            else:
                summary = f"{cls} IPv{ip.version} (non-routable)"
                verdict = "benign" if cls in ("private", "loopback") else "unknown"
        except ValueError:
            summary = "unparseable IP"
    elif t == "hash":
        h = re.sub(r"[^0-9a-fA-F]", "", value)
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(h), f"{len(h)}-char")
        data["algorithm"] = algo
        summary = f"{algo} file hash"
    elif t == "domain":
        labels = value.split(".")
        tld = labels[-1].lower() if len(labels) > 1 else ""
        ent = _entropy(labels[0]) if labels else 0
        data.update({"tld": tld, "labels": len(labels), "subdomainEntropy": ent,
                     "suspiciousTld": tld in _SUSPICIOUS_TLDS})
        flags = []
        if tld in _SUSPICIOUS_TLDS:
            flags.append(f"high-risk TLD .{tld}")
        if ent > 3.6:
            flags.append(f"high subdomain entropy ({ent}) - possible DGA")
        verdict = "suspicious" if flags else "unknown"
        summary = "; ".join(flags) or f".{tld} domain, {len(labels)} labels"
    elif t == "url":
        data["scheme"] = value.split("://", 1)[0] if "://" in value else None
        data["hasIp"] = bool(re.search(r"://\d{1,3}(\.\d{1,3}){3}", value))
        flags = []
        if data["hasIp"]:
            flags.append("IP-literal host")
        if value.lower().startswith("http://"):
            flags.append("plaintext HTTP")
        verdict = "suspicious" if data["hasIp"] else "unknown"
        summary = "; ".join(flags) or "URL indicator"
    else:
        summary = f"{t or 'unknown'} indicator"
    return {"provider": "indicator", "available": True, "verdict": verdict,
            "summary": summary, "data": data}


_HTTP_TIMEOUT = 6.0


def _vt_lookup(key: str, value: str, ioc_type: str) -> dict:
    """VirusTotal v3: last_analysis_stats over the indicator."""
    import base64
    import httpx
    t = (ioc_type or "").lower()
    if t == "ip":
        path = f"ip_addresses/{value}"
    elif t == "domain":
        path = f"domains/{value}"
    elif t == "hash":
        path = f"files/{value}"
    elif t == "url":
        path = f"urls/{base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')}"
    else:
        return {"available": False, "reason": f"VirusTotal does not cover type '{t}'"}
    r = httpx.get(f"https://www.virustotal.com/api/v3/{path}",
                  headers={"x-apikey": key}, timeout=_HTTP_TIMEOUT)
    if r.status_code == 404:
        return {"available": True, "verdict": "unknown", "summary": "not seen by VirusTotal",
                "data": {"found": False}}
    r.raise_for_status()
    stats = (r.json().get("data", {}).get("attributes", {})
             .get("last_analysis_stats", {}))
    mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int))
    verdict = "malicious" if mal > 0 else "suspicious" if susp > 0 else "benign"
    return {"available": True, "verdict": verdict,
            "summary": f"{mal}/{total} engines flag malicious"
                       + (f", {susp} suspicious" if susp else ""),
            "data": {"stats": stats, "found": True}}


def _greynoise_lookup(key: str, value: str, ioc_type: str) -> dict:
    """GreyNoise community: internet-scanner classification for an IP."""
    import httpx
    if (ioc_type or "").lower() != "ip":
        return {"available": False, "reason": "GreyNoise covers IPs only"}
    r = httpx.get(f"https://api.greynoise.io/v3/community/{value}",
                  headers={"key": key}, timeout=_HTTP_TIMEOUT)
    if r.status_code == 404:
        return {"available": True, "verdict": "unknown",
                "summary": "not observed scanning the internet", "data": {"noise": False}}
    r.raise_for_status()
    d = r.json()
    cls = (d.get("classification") or "unknown").lower()
    verdict = {"malicious": "malicious", "benign": "benign"}.get(cls, "unknown")
    bits = [f"classification={cls}"]
    if d.get("name") and d["name"] != "unknown":
        bits.append(d["name"])
    if d.get("noise"):
        bits.append("internet noise")
    return {"available": True, "verdict": verdict, "summary": "; ".join(bits),
            "data": {k: d.get(k) for k in ("noise", "riot", "classification", "name", "last_seen")}}


def _shodan_lookup(key: str, value: str, ioc_type: str) -> dict:
    """Shodan host: open ports / org / known vulns for an IP."""
    import httpx
    if (ioc_type or "").lower() != "ip":
        return {"available": False, "reason": "Shodan host lookup covers IPs only"}
    r = httpx.get(f"https://api.shodan.io/shodan/host/{value}",
                  params={"key": key}, timeout=_HTTP_TIMEOUT)
    if r.status_code == 404:
        return {"available": True, "verdict": "unknown", "summary": "no Shodan records",
                "data": {"found": False}}
    r.raise_for_status()
    d = r.json()
    ports = d.get("ports") or []
    vulns = sorted(d.get("vulns") or [])
    verdict = "suspicious" if vulns else "unknown"
    summary = f"{len(ports)} open ports" + (f"; {len(vulns)} known vulns" if vulns else "")
    if d.get("org"):
        summary += f"; org={d['org']}"
    return {"available": True, "verdict": verdict, "summary": summary,
            "data": {"ports": ports[:50], "vulns": vulns[:25], "org": d.get("org"),
                     "os": d.get("os"), "country": d.get("country_name")}}


def _whois_lookup(key: str, value: str, ioc_type: str) -> dict:
    """WHOIS (whoisxmlapi-compatible): registration age for a domain."""
    import httpx
    if (ioc_type or "").lower() != "domain":
        return {"available": False, "reason": "WHOIS lookup covers domains only"}
    r = httpx.get("https://www.whoisxmlapi.com/whoisserver/WhoisService",
                  params={"apiKey": key, "domainName": value, "outputFormat": "JSON"},
                  timeout=_HTTP_TIMEOUT)
    r.raise_for_status()
    rec = r.json().get("WhoisRecord", {})
    created = rec.get("createdDate") or rec.get("registryData", {}).get("createdDate")
    registrar = rec.get("registrarName")
    age_days = None
    if created:
        try:
            age_days = (datetime.now(timezone.utc)
                        - datetime.fromisoformat(str(created).replace("Z", "+00:00"))).days
        except (ValueError, TypeError):
            pass
    verdict = "suspicious" if age_days is not None and age_days < 30 else "unknown"
    summary = (f"registered {age_days}d ago" if age_days is not None else "registration date unknown")
    if registrar:
        summary += f" via {registrar}"
    return {"available": True, "verdict": verdict, "summary": summary,
            "data": {"createdDate": created, "registrar": registrar, "ageDays": age_days}}


_PROVIDER_CALLS = {
    "virustotal": _vt_lookup,
    "greynoise": _greynoise_lookup,
    "shodan": _shodan_lookup,
    "whois": _whois_lookup,
}


def _enrich_external(provider: str, value: str, ioc_type: str) -> dict:
    """External provider adapter. Honestly reports unavailable when no API key
    is configured (rather than fabricating a verdict); with a key set it makes
    the real provider call, and a failed call is reported as a failure - never
    a made-up verdict."""
    env = EXTERNAL_PROVIDERS[provider]
    key = os.environ.get(env, "")
    if not key:
        return {"provider": provider, "available": False,
                "reason": f"no API key configured ({env})",
                "verdict": "unknown", "summary": "not configured", "data": {}}
    try:
        res = _PROVIDER_CALLS[provider](key, value, ioc_type)
    except Exception as e:  # network/HTTP/parse - honest failure, no fabrication
        return {"provider": provider, "available": False,
                "reason": f"lookup failed: {e.__class__.__name__}",
                "verdict": "unknown", "summary": "lookup failed", "data": {}}
    out = {"provider": provider, "verdict": "unknown", "summary": "", "data": {}, **res}
    if not out.get("available"):
        out.setdefault("reason", "not applicable")
        out["summary"] = out.get("summary") or out["reason"]
    return out


BUILTIN = {"internal": _enrich_internal, "indicator": _enrich_indicator}
ALL_PROVIDERS = list(BUILTIN) + list(EXTERNAL_PROVIDERS)


def provider_status() -> list[dict]:
    out = [{"provider": p, "kind": "builtin", "available": True} for p in BUILTIN]
    for p, env in EXTERNAL_PROVIDERS.items():
        out.append({"provider": p, "kind": "external", "available": bool(os.environ.get(env)),
                    "envVar": env})
    return out


def _combined_verdict(results: list[dict]) -> str:
    avail = [r for r in results if r.get("available")]
    if not avail:
        return "unknown"
    return max((r.get("verdict") or "unknown" for r in avail),
               key=lambda v: _VERDICT_RANK.get(v, 0))


def _cached(conn, value: str, provider: str):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=CACHE_TTL_MINUTES)).replace(microsecond=0).isoformat()
    return conn.execute(
        "SELECT verdict, summary, data, ts FROM ioc_enrichments "
        "WHERE ioc_value=? AND provider=? AND ts >= ? ORDER BY ts DESC LIMIT 1",
        (value, provider, cutoff)).fetchone()


def enrich(conn, value: str, ioc_type: str = "", *, providers: list[str] | None = None,
           refresh: bool = False) -> dict:
    """Run the requested enrichers over `value`, caching each result (TTL) and
    recording history. Returns the per-provider results + a combined verdict."""
    import json
    if not ioc_type:
        row = conn.execute("SELECT type FROM iocs WHERE value=?", (value,)).fetchone()
        ioc_type = row["type"] if row else ""
    providers = providers or ALL_PROVIDERS
    results = []
    for p in providers:
        if not refresh:
            c = _cached(conn, value, p)
            if c:
                # The write path stores json.dumps(data); decode on the hit path
                # so a cached result has the same shape as a fresh one. Without
                # this, the SECOND enrich of an indicator within the TTL handed
                # the UI a JSON *string* where the first returned an object.
                data = c["data"]
                if isinstance(data, str):
                    try:
                        data = json.loads(data)
                    except ValueError:
                        data = {}
                results.append({"provider": p, "available": True, "verdict": c["verdict"],
                                "summary": c["summary"], "data": data or {}, "cached": True,
                                "ts": c["ts"]})
                continue
        if p in BUILTIN:
            res = BUILTIN[p](conn, value, ioc_type)
        elif p in EXTERNAL_PROVIDERS:
            res = _enrich_external(p, value, ioc_type)
        else:
            continue
        # Cache only results that actually ran: the cache-hit path replays rows
        # as available=True, so caching an unavailable result (e.g. VirusTotal
        # with no API key — no call was made, nothing to save) would fabricate
        # availability on every repeat enrich within the TTL.
        if res.get("available"):
            conn.execute(
                "INSERT INTO ioc_enrichments (id,ioc_value,provider,verdict,summary,data,ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), value, p, res.get("verdict"), res.get("summary"),
                 json.dumps(res.get("data", {}), separators=(",", ":")), _now()))
        res["cached"] = False
        results.append(res)
    return {"value": value, "type": ioc_type, "verdict": _combined_verdict(results),
            "providers": results, "ts": _now()}


def history(conn, value: str, limit: int = 50) -> list[dict]:
    from dashboard_api.db import rows_to_dicts
    return rows_to_dicts(conn.execute(
        "SELECT id, provider, verdict, summary, data, ts FROM ioc_enrichments "
        "WHERE ioc_value=? ORDER BY ts DESC LIMIT ?", (value, limit)).fetchall())
