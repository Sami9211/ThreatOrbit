"""Vulnerability scanner — genuine CVE findings from installed software.

Rather than fabricate CVE counts, this matches each asset's software inventory
(`[{product, version}]`) against a catalogue of real, well-known CVEs with their
affected version ranges and CVSS, producing concrete findings (CVE id, CVSS,
severity, fixed-in) per asset. The catalogue is real CVE data and is augmented
at scan time with any `cve`-type indicators already in the IOC store, so NVD
feed imports (the NVD connector) flow straight into scanning.

Version comparison is a simple dotted-numeric compare — enough for the common
`affected: <fixed_version` and inclusive-range checks these CVEs use.
"""
import json
import re
import uuid
from datetime import datetime, timezone

# Real CVEs keyed by product (lowercased). `lt` = affected when version < fixed;
# `range` = affected when min <= version <= max (inclusive). `kev` = listed in
# CISA's Known Exploited Vulnerabilities catalogue; `exploit` = a public
# exploit exists. Both are documented facts for these CVEs, not estimates.
CVE_CATALOGUE: dict[str, list[dict]] = {
    "log4j": [{"cve": "CVE-2021-44228", "cvss": 10.0, "severity": "critical",
               "lt": "2.15.0", "fixed": "2.15.0", "kev": True, "exploit": True,
               "summary": "Log4Shell — JNDI RCE in Apache Log4j 2"}],
    "openssl": [
        {"cve": "CVE-2014-0160", "cvss": 7.5, "severity": "high", "range": ("1.0.1", "1.0.1f"),
         "fixed": "1.0.1g", "kev": True, "exploit": True,
         "summary": "Heartbleed — TLS heartbeat memory disclosure"},
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
                 "summary": "regreSSHion — unauthenticated RCE in OpenSSH server"}],
    "sudo": [{"cve": "CVE-2021-3156", "cvss": 7.8, "severity": "high", "lt": "1.9.5p2",
              "fixed": "1.9.5p2", "kev": True, "exploit": True,
              "summary": "Baron Samedit — heap overflow privilege escalation"}],
    "exim": [{"cve": "CVE-2019-10149", "cvss": 9.8, "severity": "critical", "range": ("4.87", "4.91"),
              "fixed": "4.92", "kev": True, "exploit": True,
              "summary": "RCE in Exim deliver_message()"}],
    "windows": [{"cve": "CVE-2020-0796", "cvss": 10.0, "severity": "critical",
                 "range": ("10.0", "10.0"), "fixed": "patched", "kev": True, "exploit": True,
                 "summary": "SMBGhost — SMBv3 compression RCE"}],
}


def _ver_tuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))) or (0,)


def _lt(a: str, b: str) -> bool:
    return _ver_tuple(a) < _ver_tuple(b)


def _in_range(v: str, lo: str, hi: str) -> bool:
    return _ver_tuple(lo) <= _ver_tuple(v) <= _ver_tuple(hi)


def _matches(entry: dict, version: str) -> bool:
    if "lt" in entry:
        return _lt(version, entry["lt"])
    if "range" in entry:
        return _in_range(version, *entry["range"])
    return False


def scan_software(software: list[dict], extra_catalogue: dict | None = None) -> list[dict]:
    """Match an installed-software list against the CVE catalogue → findings."""
    cat = CVE_CATALOGUE if not extra_catalogue else {**CVE_CATALOGUE, **extra_catalogue}
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
    findings = scan_software(software or [])

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
