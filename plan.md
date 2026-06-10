# ThreatOrbit — Roadmap to enterprise SIEM + SOAR + CTI (and beyond)

This is the working roadmap toward feature parity with Splunk/Elastic (SIEM),
Cortex XSOAR/Splunk Phantom (SOAR), and OpenCTI/Anomali (CTI) — and past them.

**How to use this file:** pick the next unchecked item, implement it fully
(backend + frontend + tests + docs), check it off / delete it, and append any
new ideas discovered along the way. Always keep this file on `main`.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done (move to CHANGELOG section)

---

## Phase 0 — Cross-cutting platform (foundations everything needs)

- [x] **Scheduled & emailed reports** — DONE: report schedules (daily/weekly)
      with webhook delivery + a background scheduler; "Schedule" in the report
      viewer. Remaining: SMTP email channel (webhook works today).
- [x] **Deep-linking** — DONE: the SIEM queue honours `?q=` from search / the
      detail drawer / the ATT&CK navigator. (Extend to other sections as needed.)
- [x] **Global search + command palette** — DONE: `/search` across alerts,
      IOCs, assets, cases, actors, dark-web; wired into ⌘K with deep links.
- [x] **Saved views / filters** — DONE (backend `/saved-views` per user +
      section). Remaining: per-section "save this view" buttons in each page UI.
- [ ] **Real-time push** — replace 15s polling with WebSocket/SSE so alerts,
      cases, and findings stream in without refresh. *(DEFERRED — own unit:
      SSE endpoint + client; polling works today.)*
- [x] **Notifications centre** — DONE: live notification bell (real
      `/notifications` feed from critical alerts, escalated cases, credential
      leaks, scheduled reports), mark-read, deep-link on click. Remaining:
      per-user routing rules (email/Slack) on top of the webhook engine.
- [ ] **RBAC depth** — per-section, per-action permissions beyond the 4 roles;
      audit who-saw-what. *(DEFERRED — own unit; touches every endpoint.)*
- [ ] **Multi-tenancy / workspaces** — org isolation for an MSSP selling this.
      *(DEFERRED — large architectural unit: org_id scoping on every table/query.)*
- [x] **Audit & compliance pack** — DONE: CSV audit export + retention
      enforcement (purge past `data_retention_days`) with UI in Config →
      Security. Remaining: signed/immutable evidence bundles.

## Phase 1 — SIEM depth (detection & monitoring)

- [~] **Detection rule editor** — DONE: author rules with field conditions,
      AND/OR logic, threshold-over-window aggregation, and a live backtest;
      built-in rules now evaluate the raw event stream; per-rule/entity
      suppression UI + FP tuning shipped (see CHANGELOG). Remaining: Sigma
      import/export.
- [~] **Real log-source ingestion** — DONE: native HTTP collector
      (`POST /siem/ingest`) parses syslog/Apache/JSON/key=value lines into
      events and runs detection on them; a Log Collector panel on SIEM →
      Sources. Remaining: a long-running syslog UDP listener + file/dir watcher.
- [x] **Field normalization to ECS** — DONE (see CHANGELOG): an ECS alias layer
      resolves Elastic Common Schema names (`source.ip`, `user.name`,
      `destination.port`, `event.action`, …) to native event fields at match
      time, so detection rules and event searches authored in vendor-neutral ECS
      work unchanged; `/siem/rule-schema` advertises the alias map. Remaining:
      full ECS ingest-time normalization of stored events (alias layer covers
      read/query today).
- [x] **UEBA** — DONE (see CHANGELOG): per-entity (user/host/ip) risk scoring
      from alert history (severity-weighted volume + technique diversity), an
      Entity Risk page with ranking + drill-down timeline. Remaining: true
      learned baselines / deviation-from-norm anomaly scoring.
- [x] **Alert tuning workflow** — DONE (see CHANGELOG): false-positive feedback
      bumps rule FP rate; suppressions/allow-lists per entity (and rule) that
      retro-close open alerts and drop future matches, with a hit counter.
      Remaining: time-boxed/recurring suppression windows.
- [x] **Full ATT&CK navigator** — DONE (see CHANGELOG): coverage matrix by
      tactic, per-technique drill-down to rules/alerts, gaps highlighted.
- [~] **Search/hunt language** — DONE: a real field-operator query language over
      the raw event stream (`POST /siem/search`) — `field=value`, `!= > < >= <=`,
      `~regex`, `:contains`, `field in a,b,c`, bare full-text, and
      `| stats count by <field>` aggregation; compiles to the same condition
      shape the detection engine evaluates. Event-stream search panel on the Hunt
      page. Remaining: joins across sources, and saved/scheduled event-searches
      that raise alerts on threshold.
- [x] **Threat-intel matching** — DONE: ingested/generated events whose IP
      matches a known malicious IOC raise an enriched intel alert (R-TIMATCH).

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

- **2026-06-10 · ECS field normalization (Phase 1)** — detection rules and event
  searches are now vendor-neutral. `rule_engine.ECS_ALIASES` + `canonical_field`
  resolve Elastic Common Schema names (source.ip → src_ip, user.name → username,
  destination.port → dest_port, event.action → action, threat.technique.id →
  mitre_tech_id, message → raw, …) to native fields at evaluation time, so rules
  ported from Elastic/Splunk content match unchanged. The search parser
  recognises ECS names (including the `| stats count by` field, grouped on the
  native column) and `/siem/rule-schema` advertises the alias map. Tested:
  alias resolution, ECS-authored conditions/searches, and the schema endpoint.

- **2026-06-10 · Event-stream search language (Phase 1)** — a real, compact
  field-operator query language over the raw `events` stream (what hunting
  actually searches, not just alerts). `POST /siem/search` parses
  `field=value`, `!= > < >= <=`, `~regex`, `:contains`, `field in a,b,c`, bare
  full-text tokens, and a `| stats count by <field>` aggregation; every term
  compiles to the same condition shape `rule_engine.matches_event` evaluates, so
  search and detection stay consistent. New Event-stream search panel on the
  Hunt page (interpreted-as chips, raw-event rows, or grouped-count bars).
  Tested: parser units + the live search/agg/validation path.

- **2026-06-10 · Alert tuning workflow (Phase 1)** — the false-positive feedback
  loop. Marking an alert false-positive now bumps its detection rule's FP rate
  (a real tuning signal surfaced on the Rules page). New `suppressions` store +
  `/siem/suppressions` CRUD: a suppression matches an entity (src_ip / username /
  hostname, optionally scoped to a rule, mode `suppress` or `allow`); creating
  one retro-closes every open alert it covers and the shared `run_detection`
  drops future matching detections before they become alerts, incrementing a
  per-suppression hit counter (so analysts see how much noise it removed). The
  SIEM alert "Suppress" action now creates a real suppression for the alert's
  entity instead of just closing the alert, and a Suppressions & allow-lists
  panel on SIEM → Rules manages them. Enforcement is centralised, so it applies
  to engine telemetry and native log ingestion alike. Tested: lifecycle
  (create → retro-close → future-drop + hit bump → delete → re-fire) and the
  FP-rate feedback.

- **2026-06-10 · UEBA entity risk (Phase 1)** — `/siem/entities` ranks
  users/hosts/IPs by behavioural risk (severity-weighted alert volume +
  ATT&CK technique diversity, banded normal→critical); `/siem/entities/detail`
  gives a per-entity risk timeline, top techniques, and contributing alerts.
  New Entity Risk page under SIEM with ranking bars + a drill-down panel and
  deep-link into the alert queue. Auto-refreshes.

- **2026-06-10 · Phase 0 platform bundle** — `routers/platform.py` +
  `db.py` tables. (1) Notifications centre: live bell fed by real events
  (critical alerts, auto-escalated cases, credential leaks, scheduled reports),
  mark-read, click-to-navigate. (2) Global search: `/search` across alerts/
  IOCs/assets/cases/actors/dark-web, wired into the ⌘K palette with deep links.
  (3) Scheduled reports: `/report-schedules` (daily/weekly + webhook delivery)
  run by the background scheduler; "Schedule" in the report viewer. (4) Saved
  views: `/saved-views` per user+section. (5) Audit & compliance: CSV audit
  export + retention enforcement (Config → Security). (6) Deep-linking: SIEM
  queue honours `?q=`. DEFERRED as own units: real-time SSE push, per-action
  RBAC, multi-tenancy.

- **2026-06-10 · Log ingestion + ATT&CK navigator + TI matching (Phase 1)** —
  native log collector (`ingest.py`, `POST /siem/ingest`): parses syslog,
  Apache/Nginx, JSON, and key=value lines into events (content-signature
  inference for event_type/MITRE), then runs the detection rules on them — so
  production logs stream in (a Log Collector panel on SIEM → Sources lets you
  paste/forward lines). Threat-intel matching: any event IP matching a
  critical/high IOC raises an enriched R-TIMATCH alert. ATT&CK Navigator
  (`/siem/attack-coverage` + new page): coverage matrix by tactic, per-technique
  rule/alert counts, gaps highlighted, drill-down to alerts/rules/MITRE.

- **2026-06-10 · Detection rule engine + editor (Phase 1)** — the SIEM now
  works like a real SIEM: the live engine emits raw telemetry into an `events`
  table, and enabled detection rules evaluate that stream to fire alerts.
  `rule_engine.py` supports field conditions (equals/contains/in/gt/lt/regex/
  cidr…), AND/OR logic, and threshold-over-window aggregation (brute-force /
  beaconing style). 7 built-in rules ship; analysts author custom rules in a
  new visual `RuleEditor` (condition builder + aggregation + **live backtest**
  via `POST /siem/rules/test`) and `/siem/rule-schema` exposes the fields/
  operators. Rules carry MITRE mapping; alerts are produced by the matching
  rule, so triage/KPIs/correlation all flow from real detections.

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
