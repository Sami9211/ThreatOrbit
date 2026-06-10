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
- [x] **Real-time push** — DONE (see CHANGELOG): an in-process pub/sub broker +
      `GET /stream` SSE endpoint; the engine tick, `notify()`, and webhook
      dispatch publish events; a `useLiveStream` hook updates the notification
      bell and SIEM queue the instant data lands (polling kept as a safety net).
- [x] **Notifications centre** — DONE: live notification bell (real
      `/notifications` feed from critical alerts, escalated cases, credential
      leaks, scheduled reports), mark-read, deep-link on click. Remaining:
      per-user routing rules (email/Slack) on top of the webhook engine.
- [~] **RBAC depth** — DONE (see CHANGELOG): a capability matrix (roles →
      named per-section/per-action permissions), a `require_perm` dependency
      that audits denials, applied so viewers are read-only and analysts hold
      SOC write but not platform admin; `/auth/permissions` + `/config/roles`
      drive UI gating. Remaining: extend `require_perm` to the last
      config/connectors endpoints (still on the equivalent `require_role`).
- [~] **Multi-tenancy / workspaces** — FOUNDATION DONE (see CHANGELOG): `orgs`
      table + user→workspace membership (default workspace, non-breaking),
      `/orgs` CRUD + `/orgs/current`, and a tested isolation seam
      (`tenancy.scope_sql`) gated behind `DASHBOARD_MULTI_TENANT` (off).
      Remaining (staged, not yet wired so `main` stays green): add `org_id` to
      the data tables in `tenancy.TENANT_TABLES` and drop `scope_sql` into each
      query, then flip the flag on.
- [x] **Audit & compliance pack** — DONE: CSV audit export + retention
      enforcement (purge past `data_retention_days`) with UI in Config →
      Security. Remaining: signed/immutable evidence bundles.

## Phase 1 — SIEM depth (detection & monitoring)

- [x] **Detection rule editor** — DONE: author rules with field conditions,
      AND/OR logic, threshold-over-window aggregation, and a live backtest;
      built-in rules evaluate the raw event stream; per-rule/entity
      suppression UI + FP tuning; Sigma import/export (see CHANGELOG).
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

- [~] **Visual playbook builder** — the execution side is DONE (see CHANGELOG):
      playbooks are authorable step definitions (11 executable kinds incl.
      condition + human-approval gates), validated CRUD, and dry-run preview.
      Remaining: the drag-and-drop canvas UI (node editor) + versioning.
- [~] **Real action integrations** — playbook actions are recorded on connected
      integrations (block_ip → firewall, isolate_host → EDR, disable_user →
      IdP) with a full per-step audit trail. Remaining: real outbound API
      calls with credentialled connectors (CrowdStrike/Palo/Jira adapters).
- [x] **Automation triggers** — DONE (see CHANGELOG): enabled auto playbooks
      with `trigger_match` criteria (severities/techniques/rule) run
      automatically on matching fresh alerts, once per alert, throttled per
      engine tick.
- [~] **Case management depth** — DONE (see CHANGELOG): SLA tracking computed
      on every case (within / at-risk / breached / met, deadline + % elapsed,
      `slaBreached` metric) and linked evidence (`/soar/cases/{id}/related`):
      alerts/IOCs/playbook-runs matched through case entities + a MITRE-mapped
      merged timeline, surfaced in the case drawer. Remaining: case
      merge/split + linked-case relations, evidence chain-of-custody.
- [x] **Response approvals** — DONE (see CHANGELOG): `approval` steps pause the
      run, raise a notification, and resume/cancel via approve/reject — in the
      Run history panel.
- [x] **Post-incident** — DONE (see CHANGELOG): `GET /reports/incident?case_id`
      builds a per-case post-incident report (MITRE timeline, response
      actions, SLA verdict, lessons-learned scaffold) in the standard report
      viewer, from the case drawer.

## Phase 3 — CTI depth (intelligence & library)

- [~] **Full STIX 2.1 / TAXII 2.1 server** — DONE (see CHANGELOG): read-side
      TAXII 2.1 server (discovery → collections → STIX 2.1 objects) + STIX
      bundle export, auth by JWT or API key. Remaining: TAXII write/push
      (POST objects to a collection) for true publish-subscribe.
- [x] **Relationship graph at scale** — DONE (see CHANGELOG): a multi-entity
      graph (actors ↔ malware ↔ techniques ↔ IOCs ↔ sectors) built from the
      live stores, with pivot (`/cti/graph/expand`) and shortest-path
      (`/cti/graph/path`) over shared nodes; `?focus=&depth=` narrows to a
      neighbourhood.
- [x] **Enrichment pipeline** — DONE (see CHANGELOG): pluggable enrichers with
      per-IOC caching (TTL) + history. Real offline built-ins (internal
      cross-reference + indicator analysis incl. geo/ASN hint); VirusTotal/
      GreyNoise/Shodan/WHOIS adapter seam that reports honestly-unavailable
      without an API key. Remaining: live external calls when keys are set.
- [x] **IOC lifecycle** — DONE (see CHANGELOG): per-type confidence decay,
      sighting tracking (events/connectors/manual), known-good whitelisting,
      and expiry — wired into TI matching, with an IOC database + lifecycle
      drawer on the CTI hub.
- [~] **Campaign & report management** — DONE (see CHANGELOG): analyst-authored
      intel reports (CRUD, TLP, draft/publish, actor/IOC refs) + MISP Event
      import/export (store, per-report, and ingest). Remaining: a dedicated
      report-authoring UI panel (API + clients shipped).
- [x] **Attribution scoring** — DONE (see CHANGELOG): evidence-weighted actor
      attribution (`/cti/attribution` + per-case) ranking tracked actors by
      shared IOCs/malware/TTPs/sectors/origin with transparent weighted evidence
      and confidence bands.

## Phase 4 — Asset, Vuln & Dark Web depth

- [~] **Real vulnerability scanning** — DONE (see CHANGELOG): per-asset software
      inventory matched against a real CVE catalogue (Log4Shell, Heartbleed,
      regreSSHion, …) with version-range logic → genuine CVE findings (CVSS,
      fixed-in) that drive asset risk. `/assets/{id}/scan`, `/assets/scan-all`,
      `/assets/{id}/vulns`. Remaining: live NVD feed sync into the catalogue +
      a findings UI panel (API + clients shipped).
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

- **2026-06-10 · Real vulnerability scanning (Phase 4)** — assets carry CVE
  *findings*, not fabricated counts. `vuln_scanner.py` matches each asset's
  software inventory (`[{product,version}]`) against a catalogue of real CVEs
  (Log4Shell CVE-2021-44228, Heartbleed, regreSSHion, Baron Samedit, Apache
  2.4.49 traversal, …) with version-range / less-than logic, producing concrete
  findings (CVE id, CVSS, severity, fixed-in) stored in `vuln_findings`; re-scan
  is idempotent and the asset's aggregate CVE counts (which drive the risk
  model) are kept in sync. `POST /assets/{id}/scan` + `/assets/scan-all`
  (assets.write) and `GET /assets/{id}/vulns`. Seed gives several assets
  deliberately vulnerable versions so scans surface real CVEs. Frontend clients
  shipped. Tested: version-match units + scan→findings→risk, idempotent
  re-scan, scan-all, 404s, viewer-blocked.

- **2026-06-10 · Actor attribution scoring (Phase 3, closes Phase 3)** —
  `attribution.py` scores which tracked actor observed activity maps to, with
  transparent weighted evidence: IOC overlap (strongest — an indicator already
  attributed to the actor), then malware, ATT&CK technique (base-id matched so
  T1059==T1059.001), targeted sector, and origin. Scores normalise 0–100
  against the top candidate; confidence bands reflect corroboration across
  independent signal types. `POST /cti/attribution` (techniques/iocs/malware/
  sectors/origin) and `GET /cti/attribution/case/{id}` (pulls a case's linked
  alert techniques + entity indicators and attributes it). Frontend clients
  shipped. Tested: pure scoring/weighting/normalisation/confidence units +
  the API (decisive IOC match → 100/high, technique evidence, case
  attribution, 400/404 guards). **Phase 3 (CTI depth) is now complete.**

- **2026-06-10 · Campaign & report management + MISP interop (Phase 3)** —
  analyst-authored CTI reports and community sharing. New `intel_reports` store
  + `/cti/reports` CRUD (title, TLP, draft→published, actor/IOC references,
  tags; cti.write-gated). `misp.py` does real MISP **Event** interop: export
  the IOC store, a single report's indicators, or import an Event —
  `to_misp_event` maps each indicator to the correct MISP attribute type +
  category (ip-dst, domain, md5/sha1/sha256, vulnerability…) with a TLP tag and
  `to_ids` from severity; `parse_misp_event` maps attributes back to indicators
  (composite types handled, unknown types skipped not guessed) and imports them
  with a per-attribute tally. Endpoints: `/cti/reports/{id}/misp`,
  `/cti/misp/export`, `/cti/misp/import`. Frontend clients shipped (report CRUD
  + MISP import/export). Tested: MISP round-trip units + report CRUD + export +
  import tally + viewer-blocked.

- **2026-06-10 · IOC enrichment pipeline (Phase 3)** — pluggable enrichers with
  caching + per-IOC history. `enrichment.py` runs real **offline** built-ins:
  `internal` cross-references the live platform (prior sightings, related
  alerts, attributed actor, dark-web mentions, lifecycle → verdict) and
  `indicator` analyses the value itself (hash algorithm, domain entropy /
  suspicious-TLD DGA flag, URL structure, IP class + coarse RIR/geo hint). A
  real adapter seam for VirusTotal / GreyNoise / Shodan / WHOIS reports
  `available:false` honestly when no API key is configured rather than
  fabricating a verdict. Results cache per (indicator, provider) in
  `ioc_enrichments` with a TTL and keep full history; a combined verdict rolls
  the providers up (worst-of). Endpoints: `/cti/enrichers`,
  `POST /cti/iocs/{id}/enrich` (cti.write), `GET /cti/iocs/{id}/enrichment`.
  Frontend: an Enrich action + per-provider verdict/summary panel in the IOC
  lifecycle drawer. Tested: offline-analysis units, the pipeline (internal
  malicious verdict, cache hit on re-run, history, honest external
  unavailability, viewer-blocked).

- **2026-06-10 · CTI relationship graph at scale (Phase 3)** — the intelligence
  graph went from an actor→IOC star to a navigable multi-entity graph.
  `cti_graph.py` builds actors ↔ malware ↔ techniques ↔ IOCs ↔ sectors from the
  live stores, with shared malware/technique/sector nodes as connective tissue
  (two actors using the same tool/TTP are linked through it). Two analyst
  operations on it: **pivot** (`/cti/graph/expand?node=` → a node's neighbours,
  grouped by relationship) and **path-finding** (`/cti/graph/path?from=&to=` →
  BFS shortest chain, the "why are these related?" answer); `/cti/graph` gains
  `?focus=&depth=` to narrow to a neighbourhood, plus per-group counts. Frontend
  clients (fetchCtiGraph focus, expandGraphNode, findGraphPath) exposed. Tested:
  multi-group graph integrity, pivot, focus-narrowing, path-find + no-path, and
  the pure adjacency/BFS units.

- **2026-06-10 · Multi-tenancy foundation (Phase 0)** — the org/workspace model,
  shipped non-breaking. New `orgs` table + `users.org_id` (migrated); a
  bootstrapped default workspace that every existing/seeded user joins, so
  single-tenant installs are unchanged. The authenticated principal carries
  `org_id` (defaulted when unset); `/orgs/current` shows the caller's workspace
  (+ member count + isolation status), `/orgs` CRUD lets an admin stand up
  tenants (config.manage). The *breaking* half — isolating every data table by
  org_id — is **staged, not enforced**: `dashboard_api/tenancy.py` holds the
  pure, unit-tested seam (`scope_sql`, `org_of`, `TENANT_TABLES` checklist)
  gated behind `DASHBOARD_MULTI_TENANT` (default off), so it can be wired into
  queries table-by-table later without touching this foundation — `main` stays
  green. Frontend: a Workspace card on Config → General. Tested: workspace
  lifecycle, membership inheritance, viewer can't manage the directory, and the
  scope helper no-ops off / scopes on.

- **2026-06-10 · RBAC depth (Phase 0)** — authorization is now a capability
  matrix, not scattered role lists. `permissions.py` maps the four roles to
  named per-section/per-action capabilities (siem.write, soar.write, cti.write,
  config.manage, users.manage/delete, …); `require_perm(*caps)` enforces them
  and **audits denials** (who-tried-what, `rbac.denied`). Applied to the SOC
  mutations that were previously open to any logged-in user, so a **viewer is
  now genuinely read-only** (can read alerts/cases/IOCs, 403 on every write)
  while an **analyst** holds SOC write but not platform admin (can author a
  rule, 403 on user/api-key management). `GET /auth/permissions` returns the
  caller's effective set and `GET /config/roles` the full matrix; sensitive
  reads (API-key list) are access-audited. Frontend `usePermissions` hook
  (`can('siem.write')`) gates write controls — e.g. the Rules page hides New
  Rule / Import Sigma for viewers. Tested: matrix introspection + viewer-blocked
  / analyst-allowed across SIEM/SOAR/CTI with audited denials.

- **2026-06-10 · Real-time push / SSE (Phase 0)** — the dashboard updates
  live instead of polling. `events_stream.py` is a dependency-free, thread-safe
  pub/sub broker (bounded per-client queues; a backed-up browser is dropped,
  never back-pressures the engine). `routers/stream.py` serves `GET /stream`
  as `text/event-stream` with JWT-via-query auth (EventSource can't set
  headers) and heartbeats. Producers publish to the broker: the live engine
  tick (`tick` with the delta), `notify()` (`notification`), and webhook
  `dispatch()` (alert.created/case.created/…). Frontend `useLiveStream` hook
  (auto-reconnecting EventSource) re-broadcasts each event on `window` as
  `live:<type>`; the notification bell refreshes on `notification` and the SIEM
  queue on `tick`/`alert.created`, with polling dropped to a 30s safety net.
  Tested: broker fan-out/bounded-drop units + the SSE auth guard + live publish
  on the engine path.

- **2026-06-10 · STIX 2.1 / TAXII 2.1 server (Phase 3)** — ThreatOrbit is now a
  real CTI hub other tools can pull from. `stix.py` serializes the live stores
  to STIX 2.1: IOCs → `indicator` SDOs with correct patterns per type
  (`[ipv4-addr:value=…]`, `[domain-name:value=…]`, `[file:hashes.'SHA-256'=…]`,
  url/email), CVEs → `vulnerability`, actors → `threat-actor`, attribution →
  `relationship` (indicator *indicates* actor); ids are deterministic (uuid5)
  so clients de-dupe across pulls, known-good IOCs are excluded/relabelled.
  `routers/taxii.py` is a TAXII 2.1 read server (discovery → api-root →
  collections `indicators`/`threat-actors` → STIX objects) with proper
  `application/taxii+json;version=2.1` media types, `type`/`added_after`/`limit`
  filtering, and auth by **either a dashboard JWT or a platform API key**
  (`Authorization: Bearer to_rk_live_…`), so an external SIEM/CTI client can
  subscribe. `GET /cti/stix/bundle` downloads the same content; an export
  button + TAXII endpoint hint on the CTI IOC panel. Tested: STIX pattern/SDO
  units + the full TAXII flow (discovery, collections, objects, filtering,
  API-key auth, bundle).

- **2026-06-10 · IOC lifecycle (Phase 3)** — threat indicators now age like real
  intel. `ioc_lifecycle.py`: per-type confidence **decay** (half-life: IPs 14d,
  domains 45d, hashes 180d, CVEs 365d) so `effective_confidence` falls off from
  the asserted value with age since last seen; **expiry** below a confidence
  floor / age ceiling stops stale intel matching; **sightings** (a SIEM event
  matching the IOC, a connector re-import, or a manual confirmation) are
  recorded in `ioc_sightings`, bump the count, refresh last_seen, nudge
  confidence up and reactivate expired indicators; **known-good** whitelisting
  makes an indicator read benign and never match. Wired into TI matching
  (skips known-good/expired, records a sighting on every match), the engine
  (`_write_ioc` re-observation → sighting; periodic `decay_iocs` maintenance),
  and the lookup verdict (benign/expired). New endpoints: `/cti/iocs/{id}`
  (detail + lifecycle + sightings history), `/iocs/{id}/sighting`,
  `/iocs/{id}/known-good` (POST/DELETE), `/iocs/decay`; list gains a `status`
  filter + `effectiveConfidence`; summary gains active/expired/known-good
  counts. Frontend: IOC database & lifecycle panel on the CTI hub (status
  tabs, effective-vs-asserted confidence bars, a drawer with the decay model,
  sightings timeline, and record-sighting / known-good actions). Tested: decay
  model units + the full API lifecycle (sighting → reactivate, whitelist stops
  TI matching, decay maintenance).

- **2026-06-10 · Sigma rule import/export (Phase 1 close-out)** — community
  detection content ports in: `POST /siem/rules/import-sigma` parses Sigma
  YAML (selections + field modifiers |contains/|re/|cidr/|gt…/|startswith,
  lists → `in`, and/or conditions, `count() by` aggregation → threshold rule,
  level → severity, attack.* tags → MITRE) into a live, evaluable rule —
  field names resolve through a Sigma map + the ECS alias layer, unmappable
  fields degrade to raw-contains with explicit import notes; unsupported
  grammar (`not`/`1 of`/grouping) is rejected with a clear error, never
  silently weakened. `GET /siem/rules/{id}/sigma` exports: original YAML for
  Sigma-imported rules, generated Sigma for native ones (round-trips, incl.
  aggregation). UI: “Import Sigma” modal on SIEM → Rules + “Export Sigma”
  download in the rule panel. Tested incl. detection firing on live ingest.

- **2026-06-10 · Case depth: SLA tracking, linked evidence, post-incident
  reports (Phase 2)** — every case read now carries computed SLA state
  (deadline, % elapsed, within / at-risk / breached for open, met / breached
  for closed; `slaBreached` in SOAR metrics). `/soar/cases/{id}/related` links
  the case to its real evidence through its entities: matching alerts, IOC
  records, and the playbook runs that responded, plus a MITRE-mapped merged
  timeline (war room + alert + response activity) and a technique frequency
  list — shown as a “Linked evidence” section in the case drawer with deep
  links into the SIEM. Post-incident reporting: `GET /reports/incident?case_id`
  assembles the full report (severity/alerts/actions/SLA-verdict headline,
  narrative, severity + technique breakdowns, chronological findings,
  conditional lessons-learned recommendations) rendered in the standard
  print/PDF report viewer via a “Report” button on the case (period selector
  hidden for case-scoped reports).

- **2026-06-10 · SOAR playbook execution engine (Phase 2)** — playbooks now
  actually run. `playbook_engine.py`: 11 executable step kinds that act on the
  real stores — enrich (IOC + alert history), condition gate, block_ip (IOC
  blocklist + firewall-integration action), isolate_host (asset tag + EDR
  action), disable_user (IdP action), create_case (real SOAR case, feeds the
  automation rate), add_note, close_alerts (resolve triggering/same-entity
  alerts), notify, webhook, and approval (human-in-the-loop pause →
  approve/reject resumes/cancels, with notification). Every execution persists
  to `playbook_runs` with a per-step status/detail audit trail; dry-run
  previews all steps with zero writes. Playbook CRUD validates step kinds;
  **automation triggers**: auto playbooks with `trigger_match`
  (severities/techniques/rule) run on matching fresh alerts — once per alert,
  throttled per tick — wired into the live engine. The 8 canonical playbooks
  (shared demo/live) carry real step definitions. Frontend: Run history panel
  on SOAR → Playbooks (live, expandable per-step results, approve/reject
  inline), enable-toggle persisted, run button reports real outcomes. New
  webhook events `playbook.completed`/`playbook.action`. Verified: live boot →
  20 ticks → 40 auto-runs, 41 alerts auto-contained, 33 playbook-opened cases.

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
