"""Attack-surface discovery — what's exposed, and what you didn't know you had.

Two real capabilities over the live stores:

  * **Passive discovery** — mine the event stream and alert history for hosts
    that are emitting telemetry but are NOT in the asset inventory (shadow IT /
    unmanaged endpoints). Each candidate carries its observed activity (event
    + alert counts, first/last seen, a sample log line) so an analyst can vet
    it, then promote it into the inventory with one call.
  * **Exposure scoring** — a transparent, factor-based score of how reachable
    an asset is from the outside: public address, internet-facing tag, risky
    listening ports (RDP/SMB/Telnet/databases…), plaintext web, and open CVE
    findings on the exposed surface. Factors are returned with their weights so
    the score is explainable, and the internet-facing inventory ranks by it.
"""
import ipaddress
import json

# Port → (weight, label). Remote-access + database ports dominate, by design.
RISKY_PORTS = {
    3389: (25, "RDP exposed"), 23: (25, "Telnet exposed"), 445: (22, "SMB exposed"),
    21: (15, "FTP exposed"), 5900: (15, "VNC exposed"),
    3306: (18, "MySQL exposed"), 5432: (18, "PostgreSQL exposed"),
    6379: (18, "Redis exposed"), 9200: (18, "Elasticsearch exposed"),
    27017: (18, "MongoDB exposed"), 22: (8, "SSH exposed"), 25: (6, "SMTP exposed"),
    80: (6, "plaintext HTTP"), 8080: (6, "alt HTTP"),
}
W_PUBLIC_IP = 20
W_INTERNET_TAG = 15
W_CVE_CRIT = 10   # per critical CVE on an exposed asset
W_CVE_HIGH = 5


def _loads(v):
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def exposure_of(asset: dict) -> dict:
    """Transparent exposure score + contributing factors for one asset."""
    factors = []
    score = 0
    tags = [str(t).lower() for t in _loads(asset.get("tags"))]
    value = str(asset.get("value") or "")
    if _is_public_ip(value):
        score += W_PUBLIC_IP
        factors.append({"factor": "public IP address", "weight": W_PUBLIC_IP})
    elif asset.get("type") == "domain":
        score += W_PUBLIC_IP
        factors.append({"factor": "public domain", "weight": W_PUBLIC_IP})
    if "internet-facing" in tags:
        score += W_INTERNET_TAG
        factors.append({"factor": "tagged internet-facing", "weight": W_INTERNET_TAG})
    for port in _loads(asset.get("open_ports")):
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        if p in RISKY_PORTS:
            w, label = RISKY_PORTS[p]
            score += w
            factors.append({"factor": f"{label} (:{p})", "weight": w})
    exposed = score > 0
    cves = _loads(asset.get("cves")) or {}
    if exposed and isinstance(cves, dict):
        crit, high = int(cves.get("critical") or 0), int(cves.get("high") or 0)
        if crit:
            score += crit * W_CVE_CRIT
            factors.append({"factor": f"{crit} critical CVE(s) on exposed surface",
                            "weight": crit * W_CVE_CRIT})
        if high:
            score += high * W_CVE_HIGH
            factors.append({"factor": f"{high} high CVE(s) on exposed surface",
                            "weight": high * W_CVE_HIGH})
    score = min(100, score)
    band = ("critical" if score >= 70 else "high" if score >= 45
            else "moderate" if score >= 20 else "low")
    return {"score": score, "band": band, "internetFacing": exposed and
            (("internet-facing" in tags) or _is_public_ip(value) or asset.get("type") == "domain"),
            "factors": sorted(factors, key=lambda f: -f["weight"])}


def exposure_inventory(conn) -> dict:
    """Every asset scored for exposure, ranked; plus a fleet summary."""
    from dashboard_api.db import rows_to_dicts
    assets = rows_to_dicts(conn.execute(
        "SELECT id, name, type, value, criticality, risk_score, open_ports, tags, cves "
        "FROM assets").fetchall())
    items = []
    for a in assets:
        exp = exposure_of(a)
        items.append({"id": a["id"], "name": a["name"], "type": a["type"],
                      "value": a["value"], "criticality": a["criticality"],
                      "riskScore": a["risk_score"], **exp})
    items.sort(key=lambda x: -x["score"])
    facing = [i for i in items if i["internetFacing"]]
    return {
        "items": items,
        "summary": {
            "assets": len(items),
            "internetFacing": len(facing),
            "criticalExposure": sum(1 for i in items if i["band"] == "critical"),
            "avgExposure": round(sum(i["score"] for i in items) / len(items), 1) if items else 0,
            "topFactor": (facing[0]["factors"][0]["factor"]
                          if facing and facing[0]["factors"] else None),
        },
    }


def discover_unmanaged(conn, *, limit: int = 50) -> list[dict]:
    """Passive discovery: hosts seen in telemetry/alerts that are NOT in the
    asset inventory — each with its observed activity for vetting."""
    known = {str(r["name"]).lower() for r in conn.execute("SELECT name FROM assets").fetchall()}
    known |= {str(r["value"]).lower() for r in conn.execute("SELECT value FROM assets").fetchall()}
    rows = conn.execute(
        "SELECT hostname, COUNT(*) AS events, MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
        "MAX(raw) AS sample FROM events WHERE hostname IS NOT NULL AND hostname != '' "
        "GROUP BY hostname ORDER BY events DESC LIMIT ?", (limit * 2,)).fetchall()
    out = []
    for r in rows:
        host = r["hostname"]
        if host.lower() in known:
            continue
        alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE hostname=?",
                              (host,)).fetchone()["n"]
        out.append({"hostname": host, "events": r["events"], "alerts": alerts,
                    "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
                    "sample": (r["sample"] or "")[:200]})
        if len(out) >= limit:
            break
    return out
