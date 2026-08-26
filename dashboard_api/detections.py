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
import logging
import uuid
from datetime import datetime, timezone

from dashboard_api.db import audit, get_conn

logger = logging.getLogger("dashboard_api.detections")

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
                  ti_hits=0, ti_value=None, observed=False, src_country=None,
                  org_id="org-default") -> str:
    aid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,rule_id,"
        "rule_name,mitre_tactic,mitre_tactic_id,mitre_tech,mitre_tech_id,src_ip,src_country,"
        "src_port,src_hostname,src_asn,dest_ip,dest_port,dest_service,username,hostname,"
        "host_criticality,process_name,cmd_line,description,raw_log,event_count,ti_hits,ti_value,"
        "bytes_out,detect_latency_sec,ack_latency_sec,respond_latency_sec,org_id) "
        "VALUES (?,?,?,?,'new','undetermined','',?,'R-ENGINE',?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,"
        "NULL,NULL,?,?,NULL,NULL,NULL,?,?,?,?,?,0,?,NULL,NULL,?)",
        (aid, _now(), title, severity, risk, rule_name,
         mitre_tactic, mitre_tactic_id, mitre_tech, mitre_tech_id, src_ip, src_country,
         username, hostname, description, raw_log, event_count, ti_hits, ti_value,
         max(0, 60), org_id),
    )
    _announce(conn, aid, title=title, severity=severity, org_id=org_id,
              ti_value=ti_value, observed=observed)
    return aid


def _worth_interrupting(severity: str, ti_value, observed: bool) -> bool:
    """Whether an alert belongs in the notification bell.

    The bell is a digest, not a mirror of the alert queue. One detection pass
    over a busy batch raises dozens of alerts - the run that exposed this made
    80 from 20 events - and a bell that mirrors them is a bell nobody reads.
    It also is not free: the notification is written inside the detection
    worker's own transaction, and per-alert writes slowed a batch enough to
    outlive its queue lease, so another worker re-claimed the events and
    processed them twice.

    Threat-intel alerts split into two things that look identical in the row and
    mean opposite amounts, which is why `observed` exists:

      observed=True   traffic on THIS deployment touched a value we hold. One
                      per value ever (ingest.match_threat_intel dedups on
                      `ti_value`), and the highest-signal thing this platform
                      produces. Always interrupts, whatever its severity.
      observed=False  a feed we subscribe to listed something as critical.
                      That is inventory, not an event - nothing happened here.
                      A single import may raise up to _MAX_INTEL_ALERTS_PER_RUN
                      of them, and a scheduled connector does it again every
                      cycle. It belongs in the queue and the CTI store; it is
                      not a reason to interrupt anyone.

    Getting that distinction wrong is measurable: a full run with both treated
    alike filled all thirty rows of the bell with feed-import alerts, so the
    playbook that had just completed was not on the page at all.

    Everything else - rule hits, log anomalies - interrupts at `critical`, and
    is grouped by `_announce` so a burst reads as one line.
    """
    if ti_value:
        return bool(observed)
    return severity == "critical"


def _announce(conn, aid: str, *, title: str, severity: str, org_id: str,
              ti_value=None, observed: bool = False) -> None:
    """Tell somebody an alert exists.

    Every alert this function writes is one the PLATFORM found - a detection
    rule firing, a log anomaly, a threat-intel match on the deployment's own
    traffic. Those were announced to nobody. The only thing that put an alert
    in the notification bell was `engine._emit_notifications`, which is called
    from `process_tick` - the SYNTHETIC engine loop - and that returns
    immediately in live mode, correctly, because it fabricates telemetry. So
    the notifications went out with the generator when live mode stopped
    refusing it, and the one alert path that reached the bell was the manual
    `POST /siem/alerts` endpoint: the platform announced what a human had just
    typed in and stayed silent about what it had detected itself.

    Measured on a live deployment: a real threat-intel match on a real feed
    indicator raised a high-severity alert, and produced zero notifications and
    zero live-stream events.

    Best-effort throughout - announcing an alert must never be able to fail
    creating one.
    """
    payload = {"id": aid, "title": title, "severity": severity,
               "raisedBy": "detection"}
    signal = _worth_interrupting(severity, ti_value, observed)
    try:
        if signal:
            # `dispatch` = publish to the live stream AND fan out to webhook
            # subscribers. Reserved for the signal, because it costs a DB
            # subscriber lookup and outbound HTTP per call.
            from dashboard_api.webhooks import dispatch
            dispatch("alert.created", payload, org=org_id)
        else:
            # The common case, and it must stay cheap: this runs inside the
            # detection worker's transaction, once per alert, and one pass over
            # a busy batch raises dozens. Calling `dispatch` here instead cost a
            # subscriber query each time and slowed a batch past its queue
            # lease - another worker re-claimed the events and processed them
            # twice (measured: 80 alerts from one worker, 132 from six, and the
            # Postgres suite went from 5m18s to 13m37s).
            #
            # `publish` is in-process only: no query, no socket. A live console
            # still sees every alert the moment it is raised.
            from dashboard_api.events_stream import publish
            publish("alert.created", payload, org=org_id)
    except Exception:
        logger.debug("alert.created announce failed for %s", aid, exc_info=True)
    if not signal:
        return
    from dashboard_api.routers.platform import notify
    # Deliberately NOT wrapped in try/except, unlike the dispatch above.
    #
    # `notify` writes on the CALLER'S connection, inside the caller's
    # transaction. On Postgres a failed statement aborts the whole transaction,
    # so swallowing the error here would leave the caller committing something
    # the server has already poisoned - and the alert row it just inserted would
    # go with it, silently. "Best effort" is only safe for work that touches no
    # shared transaction; for a statement in one, failing loudly is the safe
    # behaviour. `notify` already swallows its own SSE and Slack failures
    # internally, which are the parts that genuinely cannot affect the write.
    #
    # Being in the same transaction is also correct on its own terms: if the
    # alert rolls back the notification must go with it, or the bell points at
    # an alert that does not exist.
    #
    # `detail=aid` matches what engine._emit_notifications writes, so the two
    # cannot double-notify the same alert if both ever run (demo mode).
    if ti_value:
        # One per value, ever. Naming the value IS the notification - rolling
        # these up would throw away the only part a human needs to read.
        notify(conn, type="alert", severity=severity, title=title, detail=aid,
               link=f"/dashboard/siem?alert={aid}", org_id=org_id)
        return
    # Detection alerts arrive in bursts, so they share a bucket per severity.
    # One critical reads as itself and links to the record; the tenth reads
    # "10 critical alerts" and links to the queue filtered to them, because
    # ten separate rows saying the same thing is nine rows of noise and no
    # extra information.
    notify(conn, type="alert", severity=severity, title=title, detail=aid,
           link=f"/dashboard/siem?alert={aid}", org_id=org_id,
           group_key=f"alert:{severity}",
           rollup_title="{n} " + f"{severity} alerts",
           rollup_link=f"/dashboard/siem?severity={severity}")


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
                     observed: bool = False, org_id: str = "org-default") -> str:
    """Raise a 'threat intel match' SIEM alert for a high-confidence indicator.

    `observed` says whether this deployment's own telemetry touched the value
    (`ingest.match_threat_intel`) or a feed merely listed it
    (`connectors._import`). Both are worth a row in the queue; only the first is
    worth interrupting a human for. See `_worth_interrupting`.
    """
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
        # Recorded whatever the type. `src_ip` above only carries it for IP
        # indicators, so a domain or URL match had no field identifying what it
        # matched - which is why duplicate suppression could not see one.
        ti_hits=1, ti_value=value, observed=observed, org_id=org_id,
    )
