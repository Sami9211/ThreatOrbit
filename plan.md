# ThreatOrbit — Roadmap to enterprise SIEM + SOAR + CTI (and beyond)

This is the working roadmap toward feature parity with Splunk/Elastic (SIEM),
Cortex XSOAR/Splunk Phantom (SOAR), and OpenCTI/Anomali (CTI) — and past them.

**How to use this file:** pick the next unchecked item, implement it fully
(backend + frontend + tests + docs), check it off / delete it, and append any
new ideas discovered along the way. Always keep this file on `main`.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done (move to CHANGELOG section)

---

## Phase 0 — Cross-cutting platform (foundations everything needs)

- [ ] **Scheduled & emailed reports** — cron the reporting engine to deliver
      daily/weekly executive + section reports to recipients (webhook/email).
      *(report engine itself is done — see CHANGELOG)*
- [ ] **Deep-linking** — clicking a detail drawer action opens the target
      section pre-filtered/scrolled to that exact record (e.g. `?alert=ID`).
      *(generic drill-down drawer is done — see CHANGELOG)*
- [ ] **Global search + command palette** across alerts, IOCs, assets, cases,
      actors, dark-web findings (one box, typeahead, deep links).
- [ ] **Saved views / filters** per section, persisted per user.
- [ ] **Real-time push** — replace 15s polling with WebSocket/SSE so alerts,
      cases, and findings stream in without refresh.
- [ ] **Notifications centre** — in-app bell + per-user routing rules (email,
      Slack, webhook) driven by the existing webhook engine.
- [ ] **RBAC depth** — per-section, per-action permissions beyond the 4 roles;
      audit who-saw-what.
- [ ] **Multi-tenancy / workspaces** — org isolation for an MSSP selling this.
- [ ] **Audit & compliance pack** — immutable audit export, SOC2/ISO evidence
      bundles, data-retention policy enforcement.

## Phase 1 — SIEM depth (detection & monitoring)

- [ ] **Detection rule editor** — author/edit correlation rules in the UI
      (conditions, thresholds, time windows, suppression), test against live
      events, enable/disable. Sigma-rule import/export.
- [ ] **Real log-source ingestion** — a syslog/HTTP-collector listener and a
      file/directory watcher so production logs stream in (not just uploads).
- [ ] **Field normalization to ECS** (Elastic Common Schema) so rules and
      searches are vendor-neutral.
- [ ] **UEBA** — per-entity (user/host) behavioural baselines and anomaly
      scoring over time; risk timelines.
- [ ] **Alert tuning workflow** — false-positive feedback loop that adjusts rule
      confidence; allow/deny lists per rule+entity.
- [ ] **Full ATT&CK navigator** — coverage matrix, technique drill-down to the
      alerts/rules that cover it, gaps highlighted.
- [ ] **Search/hunt language** — expand the hunt engine to real field operators,
      aggregations, joins, and saved/scheduled hunts that raise alerts.
- [ ] **Threat-intel matching** — automatically match incoming events against
      the CTI IOC store and raise enriched alerts (partly done; make it a first-
      class, configurable detection).

## Phase 2 — SOAR depth (orchestration & response)

- [ ] **Visual playbook builder** — drag-and-drop nodes (trigger, condition,
      action, human-approval, loop, sub-playbook), versioning, dry-run.
- [ ] **Real action integrations** — actually call EDR/firewall/ticketing APIs
      (CrowdStrike isolate host, Palo block IP, Jira create issue, etc.) with
      credentialled connectors and an action audit trail.
- [ ] **Automation triggers** — run a playbook automatically on alert/case
      criteria; SLA-driven escalation.
- [ ] **Case management depth** — linked cases, merge/split, MITRE-mapped
      timelines, evidence chain-of-custody, collaboration/assignment, SLA
      breach tracking.
- [ ] **Response approvals** — human-in-the-loop gates with notifications.
- [ ] **Post-incident** — auto-generated incident report + lessons-learned
      template (ties into the reporting engine).

## Phase 3 — CTI depth (intelligence & library)

- [ ] **Full STIX 2.1 / TAXII 2.1 server** — publish + subscribe collections so
      ThreatOrbit is a real CTI hub others can pull from.
- [ ] **Relationship graph at scale** — actors ↔ campaigns ↔ malware ↔ IOCs ↔
      TTPs, interactive, with pivoting and path-finding.
- [ ] **Enrichment pipeline** — pluggable enrichers (VirusTotal, GreyNoise,
      Shodan, WHOIS, geo/ASN) with caching and per-IOC enrichment history.
- [ ] **IOC lifecycle** — confidence decay over time, sighting tracking,
      whitelist/known-good handling, expiry.
- [ ] **Campaign & report management** — analyst-authored intel reports, MISP
      events import/export.
- [ ] **Attribution scoring** — evidence-weighted actor attribution.

## Phase 4 — Asset, Vuln & Dark Web depth

- [ ] **Real vulnerability scanning** — integrate an actual scanner (or NVD +
      installed-software matching) for genuine CVE findings per asset.
- [ ] **Attack-surface discovery** — passive/active asset discovery, exposure
      scoring, internet-facing inventory.
- [ ] **Asset ↔ alert ↔ case linkage** everywhere (one click from a host to all
      its activity).
- [ ] **Dark-web depth** — real source connectors (paste sites, leak DBs,
      Telegram), credential-leak matching against your user list, takedown
      workflow.

## Phase 5 — Product polish & scale

- [ ] **Onboarding wizard** — first-run setup (org, users, connectors, log
      sources) so a buyer is productive in minutes.
- [ ] **Billing/licensing** for the plan tiers already designed.
- [ ] **Postgres option** for scale beyond single-file SQLite; migrations.
- [ ] **Performance** — pagination/virtualisation on big tables, server-side
      filtering everywhere, caching.
- [ ] **Mobile-responsive** review of every dashboard page.
- [ ] **E2E test suite** (Playwright) across the critical workflows.

---

## CHANGELOG (done)

_Move completed items here with the date so the roadmap stays honest._

- **2026-06-10 · Reporting engine** — structured, sectioned reports
  (`dashboard_api/reports.py` + `/reports/*`): executive + SIEM + SOAR + CTI +
  assets + dark-web, each with an executive summary, headline KPIs, severity/
  category breakdowns, detailed findings, and recommendations. Daily / weekly /
  monthly / custom ranges. Frontend `ReportButton` on every section header
  opens a paginated, print-to-PDF + HTML-download viewer (Nessus/Acunetix
  style, not a CSV dump). Tested across all kinds.
- **2026-06-10 · Universal drill-down** — `DetailDrawer` (window-event based,
  mounted in the dashboard layout) makes previously dead "clickable" overview
  items open a real detail view with rows + deep-link actions; wired recent
  alerts, incidents, and the live threat feed. Also wired the dead SIEM
  "Refresh" button and added live polling to the SIEM queue.
