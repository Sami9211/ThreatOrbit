"""Detection pipeline: turn the engine's real outputs into SIEM alerts.

This is what makes the SIEM live with REAL data instead of demo seed:

  log analysis  →  the Log API's four detectors (pattern, statistical, ML,
                   temporal) find anomalies in a real log file; each finding
                   becomes a SIEM alert with severity, MITRE technique, source
                   IP/user, and the raw evidence.
  threat intel  →  a critical/high indicator ingested by a connector can raise
                   a "threat intel match" alert so the SIEM reflects new,
                   high-confidence threats the moment they're ingested.

Every alert written here is indistinguishable from any other SIEM alert, so
triage, correlation, KPIs, and SOAR case creation all work on it.
"""
import uuid
from datetime import datetime, timezone

from dashboard_api.db import audit, get_conn

# Log API severity (UPPER) → SIEM severity + a representative risk score.
_SEV_MAP = {
    "CRITICAL": ("critical", 92), "HIGH": ("high", 76),
    "MEDIUM": ("medium", 52), "LOW": ("low", 28), "INFO": ("info", 12),
}

# Common MITRE technique → tactic, so alerts carry a tactic for the heatmap.
_TACTIC = {
    "T1110": ("Credential Access", "TA0006"), "T1078": ("Defense Evasion", "TA0005"),
    "T1059": ("Execution", "TA0002"), "T1071": ("Command and Control", "TA0011"),
    "T1046": ("Discovery", "TA0007"), "T1190": ("Initial Access", "TA0001"),
    "T1486": ("Impact", "TA0040"), "T1041": ("Exfiltration", "TA0010"),
    "T1021": ("Lateral Movement", "TA0008"), "T1566": ("Initial Access", "TA0001"),
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _insert_alert(conn, *, title, severity, risk, rule_name, src_ip=None, username=None,
                  hostname=None, mitre_tech_id=None, mitre_tech=None, mitre_tactic=None,
                  mitre_tactic_id=None, description=None, raw_log=None, event_count=1,
                  ti_hits=0, src_country=None, org_id="org-default") -> str:
    aid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,rule_id,"
        "rule_name,mitre_tactic,mitre_tactic_id,mitre_tech,mitre_tech_id,src_ip,src_country,"
        "src_port,src_hostname,src_asn,dest_ip,dest_port,dest_service,username,hostname,"
        "host_criticality,process_name,cmd_line,description,raw_log,event_count,ti_hits,bytes_out,"
        "detect_latency_sec,ack_latency_sec,respond_latency_sec,org_id) "
        "VALUES (?,?,?,?,'new','undetermined','',?,'R-ENGINE',?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,"
        "NULL,NULL,?,?,NULL,NULL,NULL,?,?,?,?,0,?,NULL,NULL,?)",
        (aid, _now(), title, severity, risk, rule_name,
         mitre_tactic, mitre_tactic_id, mitre_tech, mitre_tech_id, src_ip, src_country,
         username, hostname, description, raw_log, event_count, ti_hits, max(0, 60), org_id),
    )
    return aid


def alerts_from_log_findings(findings: list[dict], source_file: str, actor: str) -> int:
    """Persist each anomaly finding as a SIEM alert. Returns the count created."""
    created = 0
    with get_conn() as conn:
        for f in findings:
            sev_key = str(f.get("severity") or "LOW").upper()
            severity, risk = _SEV_MAP.get(sev_key, ("low", 28))
            # adjust risk toward the detector's own score when present
            score = f.get("severity_score")
            if isinstance(score, (int, float)):
                risk = int(max(risk - 15, min(risk + 15, score)))
            tags = f.get("mitre_tags") or []
            tech_id = tech = None
            if tags:
                t0 = tags[0]
                tech_id = t0.get("technique_id") or t0.get("id") if isinstance(t0, dict) else str(t0)
                tech = (t0.get("name") if isinstance(t0, dict) else None)
            base = (tech_id or "").split(".")[0]
            tactic, tactic_id = _TACTIC.get(base, (None, None))
            evidence = f.get("evidence") or []
            _insert_alert(
                conn,
                title=f.get("description") or f.get("finding_type") or "Log anomaly detected",
                severity=severity, risk=risk,
                rule_name=f"LogEngine · {f.get('detector', 'anomaly')}",
                src_ip=f.get("source_ip"), username=f.get("username"),
                mitre_tech_id=tech_id, mitre_tech=tech,
                mitre_tactic=tactic, mitre_tactic_id=tactic_id,
                description=f"Detected by {f.get('detector', 'log engine')} in {source_file}. "
                            f"{f.get('finding_type', '')}".strip(),
                raw_log="\n".join(str(e) for e in evidence[:5]),
                event_count=int(f.get("count") or 1),
            )
            created += 1
        if created:
            audit(conn, actor, "siem.alerts_from_logs", source_file, f"alerts={created}")
            conn.commit()
    return created


def alert_from_intel(conn, *, value: str, ioc_type: str, severity: str, confidence: int,
                     threat_type: str, actor_name: str, source: str,
                     org_id: str = "org-default") -> str:
    """Raise a 'threat intel match' SIEM alert for a high-confidence indicator."""
    risk = {"critical": 90, "high": 74, "medium": 50, "low": 26, "info": 12}.get(severity, 50)
    return _insert_alert(
        conn,
        title=f"Threat intel: malicious {ioc_type} {value}",
        severity=severity, risk=risk, rule_name="ThreatIntel · IOC match",
        src_ip=value if ioc_type == "ip" else None,
        mitre_tech_id="T1071", mitre_tech="Application Layer Protocol",
        mitre_tactic="Command and Control", mitre_tactic_id="TA0011",
        description=f"{threat_type or 'Malicious indicator'} ingested from {source}"
                    + (f", attributed to {actor_name}" if actor_name else "") + ".",
        ti_hits=1, org_id=org_id,
    )
