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
      with webhook **and SMTP email** delivery + a background scheduler;
      "Schedule" in the report viewer. Real SMTP send when configured (honest
      not-configured otherwise); `/config/email` status + test-send.
- [x] **Deep-linking** — DONE: the SIEM queue honours `?q=` from search / the
      detail drawer / the ATT&CK navigator. (Extend to other sections as needed.)
- [x] **Global search + command palette** — DONE: `/search` across alerts,
      IOCs, assets, cases, actors, dark-web; wired into ⌘K with deep links.
- [x] **Saved views / filters** — DONE: backend `/saved-views` per user +
      section, and a shared `SavedViewsButton` (save current filters / apply /
      delete) wired into the SIEM queue, assets, dark web and feeds headers.
- [x] **Real-time push** — DONE (see CHANGELOG): an in-process pub/sub broker +
      `GET /stream` SSE endpoint; the engine tick, `notify()`, and webhook
      dispatch publish events; a `useLiveStream` hook updates the notification
      bell and SIEM queue the instant data lands (polling kept as a safety net).
- [x] **Notifications centre** — DONE: live notification bell (real
      `/notifications` feed from critical alerts, escalated cases, credential
      leaks, scheduled reports), mark-read, deep-link on click. An SMTP email
      channel backs report delivery (see Scheduled reports), and **per-user
      Slack routing is live**: each user registers a personal incoming-webhook
      URL + severity floor (`/auth/me/slack`, UI in Config → Notifications);
      `notify()` mirrors qualifying notifications there, with an honest
      test-send.
- [x] **RBAC depth** — DONE (see CHANGELOG): a capability matrix (roles →
      named per-section/per-action permissions), a `require_perm` dependency
      that audits denials, applied so viewers are read-only and analysts hold
      SOC write but not platform admin; `/auth/permissions` + `/config/roles`
      drive UI gating. Every endpoint now enforces a named capability —
      config/connectors/services/users/schedules included — with licensing on
      its own admin-only `license.manage`; `require_role` survives only as a
      documented escape hatch.
- [x] **Multi-tenancy / workspaces** — DONE (see CHANGELOG): org model/CRUD/
      membership, then real data isolation behind `DASHBOARD_MULTI_TENANT`
      (default off, single-tenant behaviour byte-for-byte unchanged):
      defaulted `org_id` on every table in `tenancy.TENANT_TABLES`, workspace
      scoping on every list endpoint AND every aggregate/rollup (overview
      KPIs/charts/geo, SIEM KPIs, SOAR metrics, CTI/assets/darkweb/feeds
      summaries), and `org_of(user)` stamping on every user-driven create so
      rows land in the creator's workspace. Proven by tests that flip the
      flag: foreign-workspace rows vanish from lists and KPI totals, and a
      foreign-org analyst's IOC/case are invisible to the default admin.
      Documented limits: engine/seed writers stay in the deployment
      workspace (per-org engine context is a deployment concern), and
      get-by-id detail endpoints remain id-addressed.
- [x] **Audit & compliance pack** — DONE: CSV audit export + retention
      enforcement (purge past `data_retention_days`) with UI in Config →
      Security, plus **signed evidence bundles**: a case's full record
      (evidence with per-item SHA-256 custody, war room, tasks, audit slice)
      exports as canonical JSON signed with HMAC-SHA256
      (`/soar/cases/{id}/evidence-bundle` + `/soar/evidence/verify`,
      "Export signed bundle" in the case drawer) — tamper-evident end to end.

## Phase 1 — SIEM depth (detection & monitoring)

- [x] **Detection rule editor** — DONE: author rules with field conditions,
      AND/OR logic, threshold-over-window aggregation, and a live backtest;
      built-in rules evaluate the raw event stream; per-rule/entity
      suppression UI + FP tuning; Sigma import/export (see CHANGELOG).
- [x] **Real log-source ingestion** — DONE: native HTTP collector
      (`POST /siem/ingest`), **plus** long-running collectors — a syslog UDP
      listener (`DASHBOARD_SYSLOG_PORT`) and a file/directory watcher
      (`DASHBOARD_LOG_WATCH_DIR`, tails new appends) that feed the same
      parse→events→detect→alert pipeline; status at `/siem/log-listeners`.
- [x] **Field normalization to ECS** — DONE (see CHANGELOG): an ECS alias layer
      resolves Elastic Common Schema names (`source.ip`, `user.name`,
      `destination.port`, `event.action`, …) to native event fields at match
      time, so detection rules and event searches authored in vendor-neutral ECS
      work unchanged; `/siem/rule-schema` advertises the alias map. Remaining:
      full ECS ingest-time normalization of stored events (alias layer covers
      read/query today).
- [x] **UEBA** — DONE (see CHANGELOG): per-entity (user/host/ip) risk scoring
      (severity-weighted volume + technique diversity), an Entity Risk page with
      ranking + drill-down, **and** a learned behavioural baseline — each
      entity's daily-volume norm (mean ± stddev) with the latest day's z-score
      flagging deviation-from-self, surfaced in the drawer.
- [x] **Alert tuning workflow** — DONE (see CHANGELOG): false-positive feedback
      bumps rule FP rate; suppressions/allow-lists per entity (and rule) that
      retro-close open alerts and drop future matches, with a hit counter.
      Remaining: time-boxed/recurring suppression windows.
- [x] **Full ATT&CK navigator** — DONE (see CHANGELOG): coverage matrix by
      tactic, per-technique drill-down to rules/alerts, gaps highlighted.
- [x] **Search/hunt language** — DONE: a real field-operator query language over
      the raw event stream (`POST /siem/search`) + `| stats count by`, **plus**
      scheduled hunts — a saved hunt put on an interval runs the event search on
      the engine tick and raises a SIEM alert on hits (detection over time).
      Remaining (minor): joins across sources.
- [x] **Threat-intel matching** — DONE: ingested/generated events whose IP
      matches a known malicious IOC raise an enriched intel alert (R-TIMATCH).

## Phase 2 — SOAR depth (orchestration & response)

- [x] **Visual playbook builder** — DONE (see CHANGELOG): a visual step-flow
      authoring canvas (palette of the 11 executable kinds, reorderable cards,
      per-step params, live dry-run) over the real execution engine, plus
      append-only version history with one-click revert.
- [~] **Real action integrations** — DONE (see CHANGELOG): credentialled
      connectors make **real** outbound vendor calls (CrowdStrike contain /
      firewall block / IdP suspend / Jira issue), uncredentialled ones record a
      not-configured action, and every attempt hits an action audit trail; the
      API key is never returned. Remaining: a credential-entry UI form +
      per-vendor request-shape config (clients shipped).
- [x] **Automation triggers** — DONE (see CHANGELOG): enabled auto playbooks
      with `trigger_match` criteria (severities/techniques/rule) run
      automatically on matching fresh alerts, once per alert, throttled per
      engine tick.
- [x] **Case management depth** — DONE (see CHANGELOG): SLA tracking, linked
      evidence (`/related`), **plus** evidence chain-of-custody (SHA-256 +
      custody log), linked cases (related/duplicate, both-sided), and
      merge/split (combine entities/war-room/evidence + sum alerts + close
      source / spin a child case). MITRE-mapped merged timeline in the drawer.
- [x] **Response approvals** — DONE (see CHANGELOG): `approval` steps pause the
      run, raise a notification, and resume/cancel via approve/reject — in the
      Run history panel.
- [x] **Post-incident** — DONE (see CHANGELOG): `GET /reports/incident?case_id`
      builds a per-case post-incident report (MITRE timeline, response
      actions, SLA verdict, lessons-learned scaffold) in the standard report
      viewer, from the case drawer.

## Phase 3 — CTI depth (intelligence & library)

- [x] **Full STIX 2.1 / TAXII 2.1 server** — DONE (see CHANGELOG): read-side
      (discovery → collections → STIX objects) + STIX bundle export, **and**
      write/push (POST a STIX envelope to the indicators collection → ingested
      into the IOC store) for true publish-subscribe. Auth by JWT or API key.
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
- [~] **Attack-surface discovery** — DONE (see CHANGELOG): passive discovery of
      unmanaged hosts from real telemetry (+ one-call promotion into the
      inventory) and transparent factor-based exposure scoring with an
      internet-facing inventory (`/assets/exposure`, `/assets/discovered`).
      Remaining: an attack-surface UI panel (API + clients shipped) + active
      probing.
- [x] **Asset ↔ alert ↔ case linkage** — DONE (see CHANGELOG):
      `/assets/{id}/activity` ties an asset to its alerts, cases, events, CVE
      findings and responding playbook runs; “Linked activity” section in the
      asset drawer with SIEM/SOAR deep links. The page’s fake re-scan simulator
      was replaced with the real vulnerability scanner.
- [x] **Dark-web depth** — DONE (see CHANGELOG): `darkweb-json` connector kind
      (any leak-DB/paste-monitor API → findings, deduped), credential-leak
      matching against the real user directory (stamp + escalate + notify),
      and a takedown workflow (status + `darkweb.takedown` webhook + UI button).

## Phase 5 — Product polish & scale

- [x] **Onboarding wizard** — DONE (see CHANGELOG): a first-run checklist
      computed from real platform state (org, admin password rotated, team,
      connector, log source + events, rules, webhook, first report) with deep
      links, progress, and a persisted dismiss — on the overview.
- [~] **Billing/licensing** — DONE (see CHANGELOG): HMAC-signed license keys,
      plan tiers (starter/pro/enterprise) with seat + connector limits enforced
      server-side (402), activate/issue/clear endpoints + a License card with
      usage bars. Remaining: payment-processor integration (Stripe) for
      self-serve purchase.
- [~] **Postgres option** — ADAPTER IMPLEMENTED (see CHANGELOG): the opt-in
      path is now functional end-to-end in code — `PgConnection` translates
      every statement through the tested dialect layer, `PgRow` supports dict
      AND positional access, `executescript` splits literals-safely, and
      migrations introspect `information_schema` instead of PRAGMA. SQLite
      default untouched (full suite proves it). Remaining: validate against a
      live Postgres (not reachable from this environment) before cutover.
- [~] **Performance** — DONE for the data layer (see CHANGELOG): hot-path
      indexes on every dashboard-refresh query (verified with EXPLAIN QUERY
      PLAN) with a safe upgrade path for migrated columns; server-side
      pagination/filtering already exists on alerts/IOCs/assets/findings.
      Remaining: frontend virtualisation for very large tables.
- [~] **E2E test suite** (Playwright) — DONE (see CHANGELOG): a 36-test suite
      (auth, every section's critical workflow, responsive) across desktop +
      mobile projects, parse-validated, with a CI workflow that boots the real
      stack and runs it. Executes in CI (browsers + stack provisioned there).
- [~] **Mobile-responsive** — the contract is now executable: `responsive.spec.ts`
      asserts no horizontal overflow + reachable content on a phone viewport
      across the six core pages, run by the mobile-safari project in CI.
      Remaining: fix any overflow the CI run flags.

---

## CHANGELOG (done)

_Move completed items here with the date so the roadmap stays honest._

- **2026-06-12 · Signed evidence bundles (Phase 0 closed)** — the audit
  pack's last piece: `GET /soar/cases/{id}/evidence-bundle` exports the
  case's full investigation record (case + evidence with per-item SHA-256
  chain-of-custody + war room + tasks + the case's audit-log slice) as
  canonical JSON signed with HMAC-SHA256 (key pinnable via
  `DASHBOARD_EVIDENCE_SECRET`); `POST /soar/evidence/verify` honestly
  re-verifies — one edited byte fails. Case drawer gains "Export signed
  bundle" (downloads the JSON) and the previously dead "Add evidence" button
  now works; live evidence rows show real ts/addedBy/sha256 instead of
  undefined seed-only fields. Exports are audited.
- **2026-06-12 · Per-user Slack routing (Phase 0 closed)** — each user can
  register a personal Slack incoming-webhook URL with a minimum-severity
  floor (GET/PUT `/auth/me/slack` + an honest `/test` send; panel in Config →
  Notifications). Every platform notification at/above the floor is mirrored
  to the user's Slack on the webhook engine's fire-and-forget thread. The URL
  is treated as a quasi-secret — scrubbed from `/auth/me` and all user
  payloads, visible only to its owner via the dedicated endpoint. Tests cover
  the round-trip, threshold filtering, clearing, and the no-leak guarantee.
- **2026-06-12 · Saved views in the page UIs (Phase 0 closed)** — a shared
  `SavedViewsButton` component (list / save-current-filters / apply / delete,
  backed by the per-user `/saved-views` API) now sits in the SIEM queue
  header (q + severity + status + tactic), assets (q + type + criticality),
  dark web (q + category) and feeds (severity). Defaults are stripped before
  saving; applying a view restores the page's filter state.
- **2026-06-12 · RBAC: capability checks everywhere (Phase 0 closed)** — the
  last `require_role` call sites are gone: config → `config.manage`,
  connectors → `connectors.manage`, services → `services.run`, report
  schedules → `reports.manage`, audit export + retention → `config.manage`,
  users → `users.manage`/`users.delete`, IOC decay → `cti.write` (its
  catalogue entry always named decay). Licensing gets its own admin-only
  `license.manage` capability (managers keep config but not license keys).
  Authorisation is now a single matrix in permissions.py; tests assert the
  new admin/manager split and that analysts are denied connectors + license.
- **2026-06-12 · Real SOAR trends (data honesty)** — `/soar/metrics` no longer
  returns fabricated "↓ 12% / ↑ 8%" trend strings: `mttrTrendPct` is the real
  week-over-week movement of average response latency and
  `automationTrendPp` the percentage-point change in playbook-driven closure
  rate, both null when there is no prior-week baseline. The SOAR KPI strip
  renders the real numbers (or "no prior-week baseline"), and the invented
  "≈ $127K analyst time" sub was replaced with the actual run count behind
  the time-saved figure.
- **2026-06-12 · Tenant scoping on aggregates — multi-tenancy complete
  (Phase 0)** — the last seam: every overview rollup (KPIs, threat vectors,
  hourly volume, MITRE heatmap, recent alerts/incidents, top actors, geo,
  live feed) and every section summary (SIEM KPIs, SOAR metrics, CTI summary,
  assets summary + risk distribution, dark web summary, feeds summary) now
  applies the workspace scope via the tested `tenancy.scope_sql` helper. The
  isolation test proves flag-on KPI totals exclude exactly the foreign-org
  rows. With reads, writes and aggregates wired, the multi-tenancy roadmap
  item is closed (131-test suite green, flag off by default).
- **2026-06-12 · Tenant write stamping (Phase 0)** — every user-driven create
  endpoint now stamps `org_of(user)` so new rows land in the creator's
  workspace: IOC import + MISP import, scans, cases (create + split),
  playbooks, assets (create + promote), detection rules (create + Sigma
  import), suppressions, log sources, feeds, connectors, report schedules,
  saved views, saved hunts. Single-tenant value is the default org, so
  behaviour is unchanged; engine/seed/background writers stay in the
  deployment workspace by design. New end-to-end test: an analyst moved to a
  foreign workspace imports an IOC + opens a case, the rows land in their org,
  and with the flag on the default-workspace admin can't see them while the
  author can (131-test suite green).
- **2026-06-12 · Tenant read isolation: all TENANT_TABLES (Phase 0)** — the
  rollout completes the read side: defaulted `org_id` migrations on the 13
  remaining tables (events, threat_actors, log_sources, feeds, connectors,
  playbooks, playbook_runs, saved_hunts, scans, suppressions, notifications,
  saved_views, report_schedules) and the workspace clause on every list
  endpoint that serves them (12 endpoints across siem/cti/soar/feeds/
  connectors/platform). The isolation test adds playbooks as the secondary-
  store representative; tenancy.py docs updated from "staged" to "wired, off
  by default". Defaults unchanged (130-test suite green with the flag off).
- **2026-06-12 · Tenant isolation: assets + dark web + rules (Phase 0)** — the
  rollout reaches all six primary stores: defaulted `org_id` migrations on
  `assets`, `dark_web_findings` and `detection_rules`, and the 3-line
  `tenancy.enforced()` workspace clause on `GET /assets`,
  `GET /darkweb/findings` and `GET /siem/rules`. The isolation test now also
  inserts two-workspace assets and proves they vanish/reappear with the flag;
  defaults remain byte-for-byte unchanged (130-test suite green).
- **2026-06-12 · Tenant isolation: cases + iocs (Phase 0)** — the alerts
  reference pattern applied to the next two primary stores: defaulted
  `org_id` migrations on `cases` and `iocs`, and the 3-line
  `tenancy.enforced()` workspace clause on `GET /soar/cases` and
  `GET /cti/iocs`. The isolation test now proves all three: with
  `DASHBOARD_MULTI_TENANT` on, a foreign workspace's alerts, cases and IOCs
  all disappear from the caller's views; with it off (default), behaviour is
  byte-for-byte unchanged (full 130-test suite green).

- **2026-06-12 · Tenant isolation reference pattern (Phase 0)** — the breaking
  half of multi-tenancy now exists, demonstrated end-to-end on the alerts
  table without touching default behaviour: `alerts.org_id` (migrated,
  `DEFAULT 'org-default'` so every existing/seeded/engine row stays visible in
  single-tenant installs) and the alert queue read appends an
  `org_id = <caller's workspace>` clause **only when `DASHBOARD_MULTI_TENANT`
  is on**. A test inserts alerts in two workspaces and proves: flag off → both
  visible (130-test suite green, unchanged), flag on → the foreign workspace's
  alert disappears from the queue, flag off again → restored. The remaining
  tables are a mechanical repeat of this 3-part pattern (defaulted column
  migration + 3-line read clause + write-path stamp), listed in
  `tenancy.TENANT_TABLES`.

- **2026-06-12 · Postgres adapter (Phase 5)** — the staged flip is now
  implemented, still opt-in and zero-impact by default. `PgConnection` adapts
  psycopg to the sqlite3-ish interface every call site already uses: `execute`/
  `executemany` translate each statement through the tested `to_postgres`
  dialect layer (PRAGMAs become no-ops), `executescript` splits statements
  string-literal-safely, and `PgRow` supports BOTH `row["col"]` and `row[0]`
  access so `row_to_dict`/positional reads work unchanged. `_apply_migrations`
  is backend-aware (`information_schema.columns` instead of PRAGMA on
  Postgres). The SQLite default path is byte-for-byte untouched — the full
  129-test suite proves it. Honest remaining step: validation against a live
  Postgres server (unreachable from this environment) before any cutover.

- **2026-06-10 · UEBA learned baselines (Phase 1)** — entity risk gains
  deviation-from-self anomaly scoring: `_entity_baseline` computes each entity's
  own daily-alert-volume norm (mean + population stddev over its prior days) and
  the latest day's z-score, flagging `deviating` at z≥2 with a confidence band
  from the history length — real behavioural-baseline anomaly detection, not
  just raw volume. Surfaced in the Entity Risk drawer (today vs norm, z-score,
  deviating/normal badge). Tested: insufficient-history guard, a spike over a
  steady baseline flags deviating, a normal day does not.

- **2026-06-10 · Syslog UDP listener + file/dir watcher (Phase 1, closes log
  ingestion)** — `log_listeners.py`: a long-running syslog UDP listener
  (`DASHBOARD_SYSLOG_PORT`) that ingests datagrams, and a file/directory
  watcher (`DASHBOARD_LOG_WATCH_DIR`) that tails only new appends from a
  per-file byte offset (handles rotation/truncation), both feeding the same
  `ingest_lines` pipeline (parse → events → detection + threat-intel → alerts).
  Off by default; started in live mode when configured. Socket/thread-free core
  (`ingest_datagram`, `scan_log_dir`) so it's unit-tested without binding ports.
  `GET /siem/log-listeners` reports status. Tested: a multi-line syslog
  datagram → events + alerts; the watcher ingests a new file, re-scans without
  duplication (offset respected), and ingests only appended lines; missing dir
  is a safe no-op.

- **2026-06-10 · SMTP email delivery channel (Phase 0)** — scheduled reports can
  now be emailed, not just webhooked. `mailer.py` sends a real MIME multipart
  email via SMTP when the deployment provides settings (SMTP_HOST/PORT/USER/
  PASSWORD/FROM/TLS), and honestly reports `not-configured` otherwise — never
  raises (a mail failure can't break a request or the engine tick). Report
  schedules gained an `email` target (`run` delivers the report's summary +
  findings as HTML); `GET /config/email` shows readiness and
  `POST /config/email/test` sends a test (admin/manager). Frontend clients +
  the schedule email field shipped. Tested: not-configured default, configured
  send (mocked smtplib asserts host/recipient/body), report-schedule email
  delivery, RBAC.

- **2026-06-10 · Scheduled hunts → alerts (Phase 1)** — a saved hunt becomes a
  detection over time. `POST /siem/hunts/{id}/schedule` sets an interval
  (+ auto_alert); `run_due_scheduled_hunts` (engine tick + `POST
  /siem/hunts/run-scheduled`) runs each due hunt's query through the
  event-stream search and, on hits, raises a SIEM alert ("Scheduled hunt
  matched …", rule R-HUNT) carrying the matched entity/technique, then stamps
  `last_scheduled` so it's throttled to its interval. saved_hunts gains
  schedule_minutes / last_scheduled / auto_alert. Tested: schedule → run →
  alert raised, throttle (second immediate run does nothing), off, range
  validation, 404, viewer-blocked.

- **2026-06-10 · TAXII 2.1 write/push (Phase 3, closes STIX/TAXII)** — the TAXII
  server now accepts pushed intel, not just serves it: `POST
  /taxii2/api/collections/indicators/objects/` takes a STIX envelope and
  ingests its `indicator` SDOs into the IOC store (deduped, source "TAXII
  push"), returning a TAXII status resource (per-object success/failure). New
  `stix.parse_indicator_pattern` / `objects_to_iocs` map STIX patterns
  (ipv4/ipv6/domain/url/email/file-hash) back to indicators. The indicators
  collection advertises `can_write:true`; threat-actors stays read-only.
  Auth (JWT or API key) enforced on writes. Tested: pattern-parser units, a
  push of mixed objects (2 indicators ingested → real IOCs, 1 non-indicator
  failed), read-only-collection 403, empty 422, unknown 404, unauth 401.

- **2026-06-10 · Case management depth: evidence custody, link, merge/split
  (Phase 2, closes case depth)** — `POST /soar/cases/{id}/evidence` attaches an
  evidence item with **tamper-evident chain-of-custody** (SHA-256 of the
  content + a custody log of who collected it, when). `…/link` relates two
  cases (related|duplicate, recorded on both sides). `…/merge` folds a source
  case into the target (dedup-combines entities, concatenates war-room +
  evidence, sums alert counts, closes the source as a duplicate with a
  system note). `…/split` spins selected entities off into a linked child
  case. `cases.linked_cases` column (migrated). Frontend clients shipped.
  Tested: evidence sha256 + custody, two-sided link, split parent/child links,
  merge (entities combined, alerts summed, source closed, note), 400/404/RBAC.

- **2026-06-10 · Real SOAR action integrations + action trail (Phase 2)** —
  response actions actually call vendor APIs. `integration_actions.py` builds
  the real request per category (EDR→CrowdStrike `devices-actions` contain,
  firewall→`/api/blocklist` deny, identity→IdP suspend, ticketing→Jira issue,
  else generic webhook POST) and, when the integration has a `base_url` +
  `api_key` configured, performs the live outbound httpx call (short timeout,
  failures recorded never crash) — otherwise records a `not-configured` action
  honestly. Every attempt (live or not) is written to the `integration_actions`
  audit trail: action, target, status, mode (live/simulated), detail, actor.
  Integrations gained `base_url`/`api_key` columns; the **credential is never
  returned** (a `credentialed` boolean is, instead). Endpoints:
  `POST /soar/integrations/{id}/actions/run` (now returns the action result) +
  `GET /soar/integrations/{id}/actions` (the trail). Frontend clients shipped.
  Tested: request-spec units per category, a credentialled firewall block that
  asserts the real vendor request shape (URL/headers/body) was sent, the
  not-configured path, the trail (no key leakage), a network-failure record,
  and viewer-blocked.

- **2026-06-10 · Visual playbook builder + versioning (Phase 2)** — a real
  authoring canvas over the (already-real) execution engine. `PlaybookBuilder`:
  a step-kind palette (`GET /soar/step-kinds` — the 11 executable kinds with
  display type + which run-context params each reads), an ordered, drag-to-
  reorder list of step cards with inline name + per-step parameter editing, a
  live **dry-run** preview (no side effects), and save through the real
  `/soar/playbooks` API. Wired to the previously-dead "New Playbook" button and
  an Edit action on each playbook. **Versioning**: `playbook_versions` snapshots
  the step definition on every create/edit/revert (append-only history);
  `GET /soar/playbooks/{id}/versions` + `POST …/revert/{version}` (restoring is
  itself a new version). The builder seeds an edited playbook from the latest
  version snapshot (which carries the real `kind`-bearing steps). Tested:
  step-kind catalogue, version history (create→v1, edit→v2, revert→v3 with the
  restored definition), 404/RBAC.

- **2026-06-10 · E2E suite + responsive contract (Phase 5)** — a real Playwright
  suite (`frontend/e2e/`): auth (bad creds rejected, valid login reaches the
  dashboard, protected-route redirect), the critical workflow per section
  (overview KPIs, SIEM queue → alert detail, rules, SOAR playbooks + run
  history, CTI actors + IOC lifecycle, dark web, assets, ⌘K palette), and a
  **responsive** spec that asserts no horizontal overflow + reachable content
  on an iPhone-13 viewport across the six core pages. Two projects
  (desktop-chromium + mobile-safari) → 36 tests; `playwright.config.ts` with a
  `webServer` that serves the production export, a login fixture, and a CI
  workflow (`.github/workflows/e2e.yml`) that boots the seeded API + frontend,
  installs browsers, and runs it on every push/PR. Verified well-formed via
  `playwright test --list` (parses all specs without browser binaries);
  execution happens in CI where the stack + browsers are provisioned. The Next
  build excludes `e2e/` so the app bundle is unaffected.

- **2026-06-10 · Postgres backend foundation (Phase 5)** — the seam to scale
  past single-file SQLite, shipped non-breaking. `db_backend.py`: backend
  selection (`DASHBOARD_DB_BACKEND`, default `sqlite`; `DATABASE_URL`), a guarded
  Postgres connection path (lazy psycopg import with a clear error; only taken
  when explicitly selected — SQLite installs are byte-for-byte unchanged), and
  a **pure, unit-tested SQLite→Postgres dialect translator** (`to_postgres`):
  `?`→`%s` placeholders (string-literal-aware), `INSERT OR REPLACE`→
  `INSERT … ON CONFLICT … DO UPDATE` (rewritten after the VALUES list),
  `AUTOINCREMENT`→`BIGSERIAL`, `datetime('now')`→`now()`, `PRAGMA` stripped.
  `GET /config/database` reports the active backend + psycopg readiness. The
  breaking flip (wiring the translator into every execute + a row-dict factory)
  is staged behind the flag so it lands reviewably on its own — `main` stays
  green. Frontend: a Storage card on Config → General. Tested: translation
  units (placeholders/idioms/upsert) + the backend endpoint + RBAC.

- **2026-06-10 · Data-layer performance (Phase 5)** — hot-path indexes for the
  queries every dashboard refresh runs: alerts (ts, severity+status, hostname,
  src_ip, username), iocs (value — the per-event TI match, status, actor),
  playbook_runs (alert_id, playbook+ts), vuln_findings (asset_id), dark-web
  (url dedupe, category), sightings/enrichments, audit action, events
  hostname. Verified with EXPLAIN QUERY PLAN that SQLite actually uses them
  (tests assert the plan). `init_db` gained a safe upgrade path: schema →
  migrations → schema again, so indexes on migrated columns apply cleanly to
  old databases (covered by an upgrade-path smoke test on a pre-migration DB).

- **2026-06-10 · Licensing & plan limits (Phase 5)** — the pricing tiers become
  real. `licensing.py`: license keys are base64url JSON payloads (plan, seats,
  connectors, expires, org) **HMAC-SHA256-signed** with
  `DASHBOARD_LICENSE_SECRET`, so they can't be forged or tampered with;
  expired/forged keys are rejected at activation AND at resolution (a stored
  key that goes invalid falls back safely). Default is a built-in enterprise
  license (unlimited) so existing installs lose nothing. Enforcement is
  server-side: adding a user or connector beyond the active plan's limit fails
  with **402** naming the limit. Endpoints: `GET /config/license` (plan,
  limits, live usage), `POST /config/license/activate`,
  `POST /config/license/issue` (vendor side — a self-hosted operator mints
  keys for their tenants; admin-only), `DELETE /config/license`. Frontend:
  License card on Config → General (plan, seat/connector usage bars, key
  activation). Tested: sign/verify/tamper/expiry units + the full
  activate→402-block→clear→restore flow + RBAC.

- **2026-06-10 · Onboarding wizard (Phase 5)** — `GET /config/onboarding`
  computes the first-run checklist from REAL platform state (a step is done
  only when the thing actually exists — org named, bootstrap admin password
  rotated (verified against the hash), 2+ users, an enabled connector, a log
  source with events flowing, enabled detection rules, a delivery webhook, a
  generated report), so the wizard can never drift from reality;
  `POST /config/onboarding/dismiss` persists dismissal. The overview shows an
  OnboardingCard (progress bar, next undone steps deep-linked) that hides once
  complete or dismissed. Tested: state-derived steps, the report step flipping
  after a real generation, dismiss persistence.

- **2026-06-10 · Dark-web depth (Phase 4, closes Phase 4)** —
  `darkweb_logic.py` + connector/router wiring. (1) **Credential matching**:
  credential-leak findings are checked against the *real* user directory —
  exact email or org-domain match stamps `matched_user`, escalates to critical
  and raises a force-reset notification; runs on engine ticks, on feed import,
  and on demand (`POST /darkweb/match-credentials`). (2) **Takedown workflow**:
  `POST /darkweb/findings/{id}/takedown` stamps the request (status
  `takedown-requested`, audit note) and emits a `darkweb.takedown` webhook for
  external takedown/ticketing services; new status in the lifecycle + a
  Request-takedown button in the finding drawer; summary gains
  workforceMatches/takedownsRequested. (3) **Real source connectors**: new
  `darkweb-json` connector kind — any leak-DB / paste-site / breach-monitor
  API returning JSON maps (field-mapped) into findings, deduped by URL, with
  credential matching on the way in; darkweb mutations now require
  darkweb.write. Tested: directory match + escalation + notification, takedown
  flow + 404/403, feed connector import/dedupe/workforce-match.
  **Phase 4 (Asset, Vuln & Dark Web depth) is now complete.**

- **2026-06-10 · Asset ↔ alert ↔ case linkage (Phase 4)** — one click from a
  host to all its activity. `GET /assets/{id}/activity` joins everything tied
  to the asset's name/value: its alerts (with MITRE + status), the cases whose
  entities reference it, recent raw events, open CVE findings, and the playbook
  runs that responded — with a summary rollup. The asset drawer gained a
  “Linked activity” section (CVE findings with CVSS, alerts deep-linking into
  the SIEM queue, cases linking to SOAR). Also replaced the assets page's fake
  random “Re-scan” simulator with the real vulnerability scanner
  (scan → reload real risk/findings; restores status honestly on API failure).
  Tested: ingest + scan + case → all linked through one call, 404 guard.

- **2026-06-10 · Attack-surface discovery (Phase 4)** — `attack_surface.py`.
  **Passive discovery**: hosts emitting telemetry that are NOT in the asset
  inventory (shadow IT) surface as vetted candidates with their observed
  activity (event/alert counts, first/last seen, sample line);
  `POST /assets/discovered/promote` registers one into the inventory (tagged
  `discovered`, 409 on duplicates, assets.write). **Exposure scoring**: a
  transparent, factor-weighted score per asset — public IP/domain,
  internet-facing tag, risky listening ports (RDP/Telnet/SMB/databases/
  plaintext HTTP), and open critical/high CVEs on the exposed surface — with
  the factors returned alongside the score so it's explainable;
  `GET /assets/exposure` ranks the fleet and summarises (internet-facing
  count, critical exposure, top factor). Frontend clients shipped. Tested:
  scoring units (weights, ordering, cap, public-IP detection) + the
  discover→promote lifecycle (telemetry host found, promoted, vanishes from
  candidates, 409/400/403 guards).

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
