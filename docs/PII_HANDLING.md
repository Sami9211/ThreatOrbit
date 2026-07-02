# PII handling & redaction policy (stored logs)

A SIEM stores what your systems emit — and what systems emit routinely
includes personal data (account emails, usernames, IPs) and, when
applications misbehave, credential material. This document states plainly
**what ThreatOrbit stores, where, for how long, and which knobs reduce it**,
so an operator can run the platform under GDPR/CCPA-style obligations without
reverse-engineering the schema.

> Principle: the platform gives you the mechanisms (redaction, retention,
> erasure, residency pinning) but cannot decide your policy. Data
> minimisation starts **at the log forwarder** — the cheapest PII to protect
> is the PII you never send.

## 1. What is stored, and where

| Store | Table / location | Personal data it can carry |
| --- | --- | --- |
| Event stream | `events` (dashboard DB) | `raw` log text (anything your systems log: emails, names, tokens); structured pivots `src_ip`, `username`, `hostname` |
| Alerts | `alerts` | `raw_log` / `description` excerpts of the triggering event; the same pivots; `owner` (analyst email) |
| Cases | `cases` | war-room notes and evidence entered by analysts; `owner` |
| CTI | `iocs` | indicator values — `email`-type IOCs are personal data by construction |
| Dark web | `dark_web_findings` | leaked credential findings reference affected emails |
| Users & audit | `users`, `audit_log`, `sessions` | operator accounts and their action trail |
| Log API | `analysis_jobs` (log_api DB) | the full analysis result + rendered report per job, which embed sample lines from the uploaded log |
| Threat API | `threat_api.db` | OSINT indicators (may include emails published in feeds) |

Backups (`docs/OPERATIONS.md`) contain all of the above; treat backup media
with the same classification as the live database.

## 2. Reducing what is stored

### Redaction at the ingest seam (opt-in)

Set `DASHBOARD_LOG_REDACT` to a comma-separated list of categories and the
dashboard masks them in raw log text **before persistence** — the stored copy
never contains them. Every real ingest path goes through this one seam
(`ingest_lines`): the HTTP ingest endpoints, the collector, the syslog/TLS
listeners, the file watcher, and the S3 puller.

```
DASHBOARD_LOG_REDACT=email,secret,cc,ssn
```

| Category | Behaviour |
| --- | --- |
| `email` | local part masked, domain kept (`[redacted]@corp.example`) — the domain is the phishing/typosquat pivot |
| `secret` | values after credential-ish keys (`password=`, `api_key=`, `Authorization: Bearer …`) and AWS access-key ids replaced — secrets in logs are a liability regardless of privacy law |
| `cc` | 13–19-digit sequences that pass the Luhn check |
| `ssn` | US SSNs in dashed form |

Deliberate scope limits, stated honestly:

* **Lossy and irreversible** — that's the point; hence off by default.
* **Raw text only.** Structured pivots (`src_ip`, `username`, `hostname`)
  are what detection/correlation runs on and are retained. If usernames
  themselves must not be stored, pseudonymise at the forwarder.
* **Pattern-based**, not NLP: free-text names, addresses and novel formats
  will pass through. Redaction reduces exposure; it is not a guarantee.
* The **Log API upload path** is a separate service and does not apply this
  seam: its per-job results (which embed sample lines) live in `log_api.db`
  until deleted. Prefer the dashboard ingest paths when redaction matters.
* The synthetic demo engine generates fictional data — no real PII.

### Retention

* Dashboard retention tiering purges (optionally archiving first —
  `DASHBOARD_ARCHIVE_DIR` / object-lock S3) on the deployment schedule, with
  **per-tenant overrides** (`org_retention_days`).
* The audit trail and its tamper-evident external mirror
  (`AUDIT_SINK_URL`, see `audit_sink.py`) are for accountability; size their
  retention to your legal obligations, not convenience.

## 3. Data-subject rights (DSAR)

`dashboard_api/privacy.py` ships the tooling for **platform users**:

* **Export** — everything held about a subject (profile + audit trail +
  reference counts), suitable as an access/portability response.
* **Erase** — anonymises rather than hard-deletes: PII replaced, account
  disabled, the subject's email rewritten to a placeholder everywhere it
  appears as an identity. Anonymisation keeps audit/security records
  referentially intact while removing the personal data.

For third-party PII inside *log content*, the units of erasure are retention
(it ages out) and redaction (it was never stored). Point-deleting a single
person out of raw log history is not supported — say so in your privacy
notice rather than promising it.

## 4. Residency & processors

Every external egress point (enrichment APIs, OSINT feeds, webhook targets,
the audit sink, the assistant's model API) and how to pin or disable each for
in-region installs is catalogued in [`DATA_RESIDENCY.md`](DATA_RESIDENCY.md).
The DPA template and the SOC 2 / ISO 27001 control self-assessment live in
[`DPA_TEMPLATE.md`](DPA_TEMPLATE.md) / [`COMPLIANCE.md`](COMPLIANCE.md) —
self-assessed, not externally audited; see `SECURITY.md` for the honest
status.

## 5. Operator checklist

1. Minimise at the forwarder (drop debug logs, mask fields you never need).
2. Decide the redaction categories → set `DASHBOARD_LOG_REDACT`.
3. Set retention to the shortest window your obligations allow; enable
   archival only if you genuinely need the raw history.
4. Encrypt and access-control backups like the live DB; store the
   `DASHBOARD_ENCRYPTION_KEY` separately.
5. Document the above in your privacy notice, including what erasure can and
   cannot reach (§3).
