"""Curated starter detection pack - real Sigma rules, shipped so a fresh install
has working detection content out of the box instead of an empty rule list.

Every rule here is authored in standard Sigma and parses through `sigma.py`'s
importer onto an evaluable definition, and every selection targets a field/value
the platform's own event stream actually produces (see the event vocabulary in
the engine), so these fire on real telemetry rather than being shelf-ware. Each
carries a MITRE ATT&CK technique + tactic. Loading is idempotent (by rule name),
so re-running it never duplicates.
"""
from dashboard_api.db import dumps
from dashboard_api.sigma import sigma_to_rule

# Standard Sigma documents. Kept readable so an operator can see exactly what
# ships and tune from there. Conditions stay within the importer's supported
# grammar (selection / a OR b / count()-by aggregation).
STARTER_PACK: list[str] = [
    """
title: Authentication Brute Force or Password Spray
status: stable
description: A burst of failed logins from a single source in a short window - the
  signature of credential brute-forcing or password spraying.
logsource:
  category: authentication
detection:
  selection:
    event_type: failed_login
  condition: selection | count() by src_ip > 8
  timeframe: 5m
level: high
tags:
  - attack.credential_access
  - attack.t1110
""",
    """
title: Password Spray Detected
status: stable
description: A single source attempting one or few passwords across many accounts.
logsource:
  category: authentication
detection:
  selection:
    action: password_spray
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
""",
    """
title: Ransomware - Mass File Encryption
status: stable
description: A process encrypting a large number of files in quick succession -
  the core behaviour of ransomware.
logsource:
  category: file_event
detection:
  selection:
    action: mass_encrypt
  condition: selection
level: critical
tags:
  - attack.impact
  - attack.t1486
""",
    """
title: Volume Shadow Copy Deletion
status: stable
description: Deletion of shadow copies to inhibit system recovery - a common
  ransomware precursor.
logsource:
  category: process_creation
detection:
  selection:
    action: delete_shadows
  condition: selection
level: high
tags:
  - attack.impact
  - attack.t1490
""",
    """
title: DNS Tunneling or Exfiltration
status: stable
description: Data smuggled over DNS - high-entropy or high-volume DNS that does
  not match normal resolution patterns.
logsource:
  category: dns
detection:
  selection:
    event_type: dns_tunnel
  selection_action:
    action: dns_exfil
  condition: selection or selection_action
level: high
tags:
  - attack.exfiltration
  - attack.t1048
""",
    """
title: Large Outbound Data Transfer
status: stable
description: An unusually large egress volume to an external host - possible bulk
  data exfiltration.
logsource:
  category: network
detection:
  selection:
    bytes_out|gt: 50000000
  condition: selection
level: medium
tags:
  - attack.exfiltration
  - attack.t1041
""",
    """
title: Living-off-the-Land Ingress Tool Transfer
status: stable
description: A built-in binary (certutil/bitsadmin/curl) used to pull tooling from
  the internet onto a host.
logsource:
  category: process_creation
detection:
  selection:
    action: lolbin_download
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1105
""",
    """
title: Suspected Command-and-Control Beacon
status: stable
description: Regular, periodic callouts to an external host consistent with a C2
  beacon.
logsource:
  category: network
detection:
  selection:
    event_type: beacon
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1071
""",
    """
title: New Cloud Access Key Created
status: stable
description: Creation of a new long-lived cloud access key - a frequent
  persistence and privilege-retention move after account compromise.
logsource:
  product: cloud
  category: cloud_audit
detection:
  selection:
    action: create_access_key
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1098.001
""",
    """
title: Impossible Travel Sign-In
status: stable
description: Successful sign-ins from geographically impossible locations within a
  short window - likely account takeover.
logsource:
  category: authentication
detection:
  selection:
    action: impossible_travel
  condition: selection
level: medium
tags:
  - attack.initial_access
  - attack.t1078
""",
]


def load_pack(conn, created_by: str, org_id: str) -> dict:
    """Import each pack rule that isn't already present (matched by name).
    Returns {created:[names], skipped:[names]}. Idempotent: a second run skips
    everything. Caller commits + audits."""
    import uuid
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    created, skipped = [], []
    for yaml_text in STARTER_PACK:
        mapped = sigma_to_rule(yaml_text)          # authored to always parse
        name = mapped["name"]
        if conn.execute("SELECT 1 FROM detection_rules WHERE name=?", (name,)).fetchone():
            skipped.append(name)
            continue
        rid = f"R-{uuid.uuid4().hex[:6].upper()}"
        tags = ["starter-pack"] + mapped["tags"]
        conn.execute(
            "INSERT INTO detection_rules (id,name,category,severity,mitre_tactic,mitre_tactic_id,"
            "mitre_tech_id,mitre_tech,hits_24h,fired_last_7d,fp_rate,status,source,last_fired,"
            "created,updated_by,description,kql,suppression_window,severity_override,tags,definition,"
            "org_id) "
            "VALUES (?,?,?,?,?,?,?,NULL,0,0,0,'enabled','pack',NULL,?,?,?,?,0,NULL,?,?,?)",
            (rid, name, mapped["category"], mapped["severity"], mapped["mitre_tactic"],
             mapped["mitre_tactic_id"], mapped["mitre_tech_id"], now, created_by,
             mapped["description"], yaml_text.strip(), dumps(tags), dumps(mapped["definition"]),
             org_id),
        )
        created.append(name)
    return {"created": created, "skipped": skipped}
