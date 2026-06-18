# Supported log sources & parser matrix

This is the honest, code-backed list of what the SIEM ingest pipeline
recognises and normalises today. Every row maps to real parser code in
[`dashboard_api/ingest.py`](../dashboard_api/ingest.py) (JSON source shapes,
key=value, Apache/Nginx, generic) and the long-running collectors in
[`dashboard_api/log_listeners.py`](../dashboard_api/log_listeners.py).

Ingest happens through:

| Path | How | Notes |
| --- | --- | --- |
| `POST /siem/ingest` | JSON `{lines:[…], format:"auto"}` | validated, backpressure-aware (429 + Retry-After) |
| `POST /siem/ingest/raw` | plain text / NDJSON / JSON array | for vendor agents that emit natively |
| Syslog UDP | `DASHBOARD_SYSLOG_PORT` | RFC 3164/5424 lines |
| **Syslog TLS (RFC 5425)** | `DASHBOARD_SYSLOG_TLS_PORT` + cert/key | octet-counted framing, optional mTLS |
| File / directory watch | `DASHBOARD_LOG_WATCH_DIR` | tails new appends, checkpointed |
| First-party agent | [`collector/`](../collector) | tail + checkpoint + at-least-once |
| Certified shippers | Fluent Bit / Vector / Filebeat→Logstash | configs in [`collector/configs`](../collector/configs) |

Every parser returns the one normalised event shape the detection rules read
(`event_type`, `category`, `src_ip`, `dest_ip`, `dest_port`, `username`,
`hostname`, `process_name`, `action`, `bytes_out`, `severity_hint`,
`mitre_tech_id`, `raw`), so a rule authored once fires regardless of source.
ECS-shaped JSON (nested Beats style or dotted keys) is additionally normalised
through the same alias map.

## Source matrix

| Source | Format detected by | Example native mappings | ATT&CK |
| --- | --- | --- | --- |
| **Windows Security** | `EventID` + a Windows companion field (`Channel`/`Computer`/winlog) | 4625→`failed_login`, 4624→`login_success`, 4688→`process_start`, 4728/4732→`group_change`, 1102→`log_cleared`, 7045→`service_install` | T1110, T1078, T1098, T1070.001, T1543.003 |
| **Sysmon** | `Channel`/provider contains `Sysmon` + `EventID` | 1→`process_start`, 3→`network_connect`, 11→`file_create`, 12/13→`registry_change`, 22→`dns_query` | T1059, T1112, T1071.004 |
| **AWS CloudTrail** | `eventName` + `eventSource` ends `amazonaws.com` / `eventVersion` | CreateAccessKey→`create_access_key`, ConsoleLogin failure→`failed_login`, StopLogging→`log_cleared`, GetSecretValue→`secret_access` | T1098.001, T1110, T1562.008, T1552.005 |
| **Microsoft Entra / Azure AD** | `category` in sign-in set / `auditlogs`, or `properties.userPrincipalName` | sign-in errorCode≠0→`failed_login`, add-member-to-role→`group_change` | T1110, T1098 |
| **GCP Cloud Audit** | `protoPayload.methodName` / `logName` contains `cloudaudit.googleapis.com` | CreateServiceAccountKey→`create_access_key`, SetIamPolicy→`policy_change`, AccessSecretVersion→`secret_access` | T1098.001, T1552.005 |
| **CrowdStrike Falcon** | Streaming `metadata.eventType` / `event.event_simpleName` | UserLogonFailed2→`failed_login`, ProcessRollup2→`process_start`, DnsRequest→`dns_query`, DetectionSummaryEvent→`malware_detected` (maps `TechniqueId`/`SeverityName`) | T1110, T1059, T1071.004, T1204 |
| **SentinelOne** | nested `threatInfo` / `agentRealtimeInfo` / `agentDetectionInfo` | ransomware→`malware_detected` (T1486), malware/trojan→`malware_detected` (T1204), else→`edr_alert` | T1486, T1204 |
| **Microsoft 365 Defender** (Advanced Hunting) | `ActionType` + a Device* companion field | LogonFailed→`failed_login`, ProcessCreated→`process_start`, ConnectionSuccess→`network_connect`, AntivirusDetection→`malware_detected`, RegistryValueSet→`registry_change` | T1110, T1059, T1204, T1112 |
| **Microsoft 365 / Office 365 audit** | `Operation` + `Workload`/`RecordType`/`OrganizationId` | UserLoginFailed→`failed_login`, New-InboxRule→`mailbox_rule`, Add-member-to-role→`group_change`, Consent-to-application→`app_consent`, Disable-Strong-Auth→`mfa_disabled` | T1110, T1114.003, T1098, T1528, T1556.006 |
| **Palo Alto PAN-OS** | `type` TRAFFIC/THREAT + a PA field (`sessionid`/`threatid`/`app`/`rule`/`subtype`) | THREAT/vulnerability→`ips_alert`, THREAT/virus→`malware_detected`, TRAFFIC deny→`firewall_deny` | T1190, T1204 |
| **Fortinet FortiGate** | `devname`/`devid`/`logid`, or forti `type` + `srcip` (JSON **or** key=value syslog) | utm/ips→`ips_alert`, utm/virus→`malware_detected`, traffic deny→`firewall_deny` | T1190, T1204 |
| **Apache / Nginx** | combined/common access-log line | access line→`web_request` (+ SQLi/traversal signatures) | T1190, T1083 |
| **Generic syslog / key=value / free text** | fallback | content signatures (brute force, C2 beacon, PowerShell, malware) + IP/user/host extraction | T1110, T1071.001, T1059.001 |

Auth failures from **every** source above land as `event_type=failed_login`, so
the built-in brute-force / password-spray detection fires uniformly across
Windows, cloud, EDR, M365 and firewall logins.

## TLS syslog (RFC 5425)

Set all of:

```
DASHBOARD_SYSLOG_TLS_PORT=6514
DASHBOARD_SYSLOG_TLS_CERT=/etc/threatorbit/syslog.crt
DASHBOARD_SYSLOG_TLS_KEY=/etc/threatorbit/syslog.key
# optional — require a client certificate (mutual TLS):
DASHBOARD_SYSLOG_TLS_CA=/etc/threatorbit/clients-ca.crt
```

The listener accepts the octet-counting framing RFC 5425 mandates
(`MSGLEN SP MSG`) **and** non-transparent newline framing, so both strict
senders (rsyslog `omfwd` with `octet-counted`, syslog-ng `tls()`) and simple
newline emitters work. Framing is handled by the unit-tested
`log_listeners.deframe_syslog`, which correctly carries a frame that spans TCP
segments. Like the UDP listener, the TLS listener is single-writer by
deployment — bind it on one node (or a VIP) per cluster.

## What is *not* yet first-class (honest gaps)

- **Agentless pull** (tail an S3 / Azure Blob / GCS bucket on a schedule) — use
  the file watcher or a shipper today; a native bucket-pull connector is on the
  roadmap.
- **CEF / LEEF** envelope parsing — many appliances can emit JSON or key=value
  instead; native CEF decoding is not yet implemented.
- **Vendors beyond the matrix** (other EDR/firewall brands, NDR, WAF). The
  generic key=value and JSON paths still extract IP/user/host and content
  signatures; add a mapper in `ingest.py` (see the `_apply_*` functions) to
  promote a new vendor to first-class.
