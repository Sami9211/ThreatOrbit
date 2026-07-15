"""Vulnerability scanner - genuine CVE findings from installed software.

Rather than fabricate CVE counts, this matches each asset's software inventory
(`[{product, version}]`) against a catalogue of real, well-known CVEs with their
affected version ranges and CVSS, producing concrete findings (CVE id, CVSS,
severity, fixed-in) per asset. The built-in catalogue is real CVE data, and the
NVD connector syncs live feed records (CPE product/version ranges) into the
`cve_catalogue` table, which is merged in at scan time - so NVD imports flow
straight into scanning.

Version comparison is a simple dotted-numeric compare - enough for the common
`affected: <fixed_version` and inclusive-range checks these CVEs use.
"""
import json
import logging
import re
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("dashboard_api.vuln_scanner")

# Real CVEs keyed by product (lowercased). `lt` = affected when version < fixed;
# `range` = affected when min <= version <= max (inclusive). `kev` = listed in
# CISA's Known Exploited Vulnerabilities catalogue; `exploit` = a public
# exploit exists. Both are documented facts for these CVEs, not estimates.
CVE_CATALOGUE: dict[str, list[dict]] = {
    "log4j": [{"cve": "CVE-2021-44228", "cvss": 10.0, "severity": "critical",
               "lt": "2.15.0", "fixed": "2.15.0", "kev": True, "exploit": True,
               "summary": "Log4Shell - JNDI RCE in Apache Log4j 2"}],
    "openssl": [
        {"cve": "CVE-2014-0160", "cvss": 7.5, "severity": "high", "range": ("1.0.1", "1.0.1f"),
         "fixed": "1.0.1g", "kev": True, "exploit": True,
         "summary": "Heartbleed - TLS heartbeat memory disclosure"},
        {"cve": "CVE-2022-3602", "cvss": 7.5, "severity": "high", "range": ("3.0.0", "3.0.6"),
         "fixed": "3.0.7", "kev": False, "exploit": False,
         "summary": "X.509 email address buffer overflow"}],
    "apache httpd": [{"cve": "CVE-2021-41773", "cvss": 7.5, "severity": "high",
                      "range": ("2.4.49", "2.4.49"), "fixed": "2.4.51", "kev": True, "exploit": True,
                      "summary": "Path traversal & RCE in Apache HTTP Server 2.4.49"}],
    "httpd": [{"cve": "CVE-2021-41773", "cvss": 7.5, "severity": "high",
               "range": ("2.4.49", "2.4.49"), "fixed": "2.4.51", "kev": True, "exploit": True,
               "summary": "Path traversal & RCE in Apache HTTP Server 2.4.49"}],
    "nginx": [{"cve": "CVE-2019-20372", "cvss": 5.3, "severity": "medium", "lt": "1.17.7",
               "fixed": "1.17.7", "kev": False, "exploit": False,
               "summary": "HTTP request smuggling via error_page"}],
    "openssh": [{"cve": "CVE-2024-6387", "cvss": 8.1, "severity": "high",
                 "range": ("8.5", "9.7"), "fixed": "9.8", "kev": False, "exploit": True,
                 "summary": "regreSSHion - unauthenticated RCE in OpenSSH server"}],
    "sudo": [{"cve": "CVE-2021-3156", "cvss": 7.8, "severity": "high", "lt": "1.9.5p2",
              "fixed": "1.9.5p2", "kev": True, "exploit": True,
              "summary": "Baron Samedit - heap overflow privilege escalation"}],
    "exim": [{"cve": "CVE-2019-10149", "cvss": 9.8, "severity": "critical", "range": ("4.87", "4.91"),
              "fixed": "4.92", "kev": True, "exploit": True,
              "summary": "RCE in Exim deliver_message()"}],
    "windows": [{"cve": "CVE-2020-0796", "cvss": 10.0, "severity": "critical",
                 "range": ("10.0", "10.0"), "fixed": "patched", "kev": True, "exploit": True,
                 "summary": "SMBGhost - SMBv3 compression RCE"}],
}


def _ver_tuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))) or (0,)


def _ver_cmp(a: str, b: str) -> int:
    """Compare two dotted-numeric versions, ZERO-PADDED to equal length so
    "2.0" == "2.0.0" (a raw tuple compare treats them as unequal - a real
    vuln-scan miss at patch boundaries). Returns -1 / 0 / 1."""
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return -1 if ta < tb else (1 if ta > tb else 0)


def _lt(a: str, b: str) -> bool:
    return _ver_cmp(a, b) < 0


def _in_range(v: str, lo: str, hi: str) -> bool:
    return _ver_cmp(v, lo) >= 0 and _ver_cmp(v, hi) <= 0


def _matches(entry: dict, version: str) -> bool:
    if "lt" in entry:
        return _lt(version, entry["lt"])
    if "range" in entry:
        return _in_range(version, *entry["range"])
    if "bounds" in entry:  # NVD CPE ranges: (start, start_incl, end, end_incl)
        lo, lo_inc, hi, hi_inc = entry["bounds"]
        if lo is None and hi is None:
            return False  # unbounded "every version" rows are too noisy to honour
        if lo is not None:
            c = _ver_cmp(version, lo)
            if c < 0 or (not lo_inc and c == 0):
                return False
        if hi is not None:
            c = _ver_cmp(version, hi)
            if c > 0 or (not hi_inc and c == 0):
                return False
        return True
    return False


def scan_software(software: list[dict], extra_catalogue: dict | None = None) -> list[dict]:
    """Match an installed-software list against the CVE catalogue → findings.
    `extra_catalogue` entries (e.g. NVD-synced rows) extend the built-ins -
    per-product lists are concatenated, not replaced."""
    cat: dict[str, list[dict]] = {k: list(v) for k, v in CVE_CATALOGUE.items()}
    for prod, entries in (extra_catalogue or {}).items():
        cat[prod] = cat.get(prod, []) + list(entries)
    findings = []
    for item in software or []:
        product = str(item.get("product", "")).strip().lower()
        version = str(item.get("version", "")).strip()
        if not product or not version:
            continue
        for entry in cat.get(product, []):
            if _matches(entry, version):
                findings.append({
                    "cve": entry["cve"], "product": product, "version": version,
                    "severity": entry["severity"], "cvss": entry["cvss"],
                    "fixed_in": entry.get("fixed"), "summary": entry.get("summary", ""),
                    "kev": bool(entry.get("kev")), "exploit": bool(entry.get("exploit")),
                })
    return findings


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# -- NVD catalogue sync (live feed → cve_catalogue table) -------------------------

_NVD_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def nvd_to_catalogue(vulnerabilities: list[dict]) -> list[dict]:
    """Parse NVD CVE 2.0 records into catalogue rows: one row per vulnerable
    CPE product with its affected version bounds. Records without a vulnerable
    application CPE produce nothing (no version logic to scan against)."""
    rows = []
    for item in vulnerabilities or []:
        # Per-record isolation: one malformed CVE (e.g. a non-numeric baseScore
        # from an NVD mirror/proxy) must not abort the whole catalogue sync and
        # discard every other CVE in the feed.
        try:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            cvss, severity = 0.0, "medium"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    data = metrics[key][0].get("cvssData", {})
                    try:
                        cvss = float(data.get("baseScore") or 0)
                    except (ValueError, TypeError):
                        cvss = 0.0
                    sev = data.get("baseSeverity") or metrics[key][0].get("baseSeverity", "")
                    severity = _NVD_SEV.get((sev or "").upper(), "medium")
                    break
            summary = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    summary = d.get("value", "")[:300]
                    break
            seen: set[str] = set()
            for conf in cve.get("configurations", []) or []:
                for node in conf.get("nodes", []) or []:
                    for m in node.get("cpeMatch", []) or []:
                        if not m.get("vulnerable"):
                            continue
                        parts = str(m.get("criteria", "")).split(":")
                        if len(parts) < 6 or parts[2] != "a":  # applications only
                            continue
                        product = parts[4].replace("_", " ").strip().lower()
                        if not product or product in seen:
                            continue
                        seen.add(product)
                        vstart = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                        vstart_incl = "versionStartExcluding" not in m
                        vend = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                        vend_incl = "versionEndIncluding" in m
                        # an exact-version CPE (no range fields) pins both bounds
                        if not vstart and not vend and parts[5] not in ("*", "-", ""):
                            vstart = vend = parts[5]
                            vstart_incl = vend_incl = True
                        if not vstart and not vend:
                            continue  # unbounded - nothing scannable
                        rows.append({
                            "cve": cid, "product": product, "cvss": cvss, "severity": severity,
                            "vstart": vstart, "vstart_incl": vstart_incl,
                            "vend": vend, "vend_incl": vend_incl,
                            "fixed": m.get("versionEndExcluding"), "summary": summary,
                        })
        except Exception:
            logger.warning("skipping un-parseable NVD CVE record", exc_info=True)
            continue
    return rows


def upsert_catalogue(conn, rows: list[dict], source: str = "nvd") -> int:
    """Idempotently merge catalogue rows (keyed cve+product). Returns count."""
    now = _now()
    for r in rows:
        conn.execute(
            "INSERT INTO cve_catalogue (cve,product,cvss,severity,vstart,vstart_incl,"
            "vend,vend_incl,fixed,summary,kev,exploit,source,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,0,0,?,?) "
            "ON CONFLICT(cve,product) DO UPDATE SET cvss=excluded.cvss, "
            "severity=excluded.severity, vstart=excluded.vstart, "
            "vstart_incl=excluded.vstart_incl, vend=excluded.vend, "
            "vend_incl=excluded.vend_incl, fixed=excluded.fixed, "
            "summary=excluded.summary, updated_at=excluded.updated_at",
            (r["cve"], r["product"], r.get("cvss", 0), r.get("severity", "medium"),
             r.get("vstart"), 1 if r.get("vstart_incl", True) else 0,
             r.get("vend"), 1 if r.get("vend_incl") else 0,
             r.get("fixed"), r.get("summary", ""), source, now))
    return len(rows)


def load_db_catalogue(conn) -> dict[str, list[dict]]:
    """The synced catalogue in the scanner's shape: {product: [entries]}."""
    out: dict[str, list[dict]] = {}
    for r in conn.execute("SELECT * FROM cve_catalogue").fetchall():
        out.setdefault(r["product"], []).append({
            "cve": r["cve"], "cvss": r["cvss"], "severity": r["severity"],
            "bounds": (r["vstart"], bool(r["vstart_incl"]), r["vend"], bool(r["vend_incl"])),
            "fixed": r["fixed"], "summary": r["summary"] or "",
            "kev": bool(r["kev"]), "exploit": bool(r["exploit"]),
        })
    return out


def scan_asset(conn, asset_id: str) -> dict | None:
    """Scan one asset: match its software, replace its open findings, and roll
    the result into the asset's CVE severity counts. Returns a summary or None
    if the asset doesn't exist."""
    row = conn.execute("SELECT id, software FROM assets WHERE id=?", (asset_id,)).fetchone()
    if not row:
        return None
    software = row["software"]
    if isinstance(software, str):
        try:
            software = json.loads(software)
        except (ValueError, TypeError):
            software = []
    # NVD-synced catalogue rows extend the built-ins, so feed imports flow
    # straight into scanning.
    findings = scan_software(software or [], extra_catalogue=load_db_catalogue(conn))

    # Replace prior open findings with the fresh scan (idempotent re-scans).
    conn.execute("DELETE FROM vuln_findings WHERE asset_id=? AND status='open'", (asset_id,))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        conn.execute(
            "INSERT INTO vuln_findings (id,asset_id,cve,product,version,severity,cvss,fixed_in,"
            "summary,status,found_at,kev,exploit) VALUES (?,?,?,?,?,?,?,?,?, 'open', ?,?,?)",
            (str(uuid.uuid4()), asset_id, f["cve"], f["product"], f["version"], f["severity"],
             f["cvss"], f["fixed_in"], f["summary"], _now(),
             1 if f.get("kev") else 0, 1 if f.get("exploit") else 0))
    # Keep the asset's aggregate cve counts in sync with real findings.
    from dashboard_api.db import dumps
    conn.execute("UPDATE assets SET cves=?, last_scan=? WHERE id=?",
                 (dumps(counts), _now(), asset_id))
    return {"assetId": asset_id, "scanned": len(software or []),
            "findings": findings, "counts": counts}


def scan_all(conn) -> dict:
    ids = [r["id"] for r in conn.execute("SELECT id FROM assets").fetchall()]
    total = 0
    for aid in ids:
        res = scan_asset(conn, aid)
        if res:
            total += len(res["findings"])
    return {"assets": len(ids), "findings": total}
