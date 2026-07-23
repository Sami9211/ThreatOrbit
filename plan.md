# ThreatOrbit - Roadmap to enterprise SIEM + SOAR + CTI (and beyond)

This is the working roadmap toward feature parity with Splunk/Elastic (SIEM),
Cortex XSOAR/Splunk Phantom (SOAR), and OpenCTI/Anomali (CTI) - and past them.

**How to use this file:** pick the next unchecked item, implement it fully
(backend + frontend + tests + docs), check it off / delete it, and append any
new ideas discovered along the way. Always keep this file on `main`.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done (move to CHANGELOG section)

---

## Audit (2026-06-22) - verified state + open findings

A fresh end-to-end audit pass: every backend suite was run on a clean install,
the prior review (`audit_fixes.md`) was re-verified against the current tree,
and the finished roadmap entries below were pruned into the CHANGELOG.

**Verified green.** **413 backend tests pass** on a clean checkout - `log_api`
20, `threat_api` 8, `dashboard_api` 385. Static sweeps are clean: no bare
`except:`, mutable-default args, `eval`/`exec`/`subprocess(shell=True)`,
`pickle`, `yaml.load`, or `datetime.utcnow()` in service code. The
security-critical paths re-read and hold up: SSRF send-time IP-pinning
(`net_guard.safe_request` pins to a validated address, preserves Host/SNI,
blocks redirects), RBAC capability enforcement, and SAML/OIDC verification.
Most `audit_fixes.md` findings (A1-A4, B1-B12, C1-C6, D1-D2, E1-E4, F1-F4,
I1-I2) are genuinely resolved; the live residue is tracked below.

### New findings (open)

- [x] **MSSP: id-addressed sub-resource GETs lack a cross-org guard** - DONE
      (2026-07-03, CHANGELOG): threaded the caller through and 404 on
      `cross_org` for `soar/cases/{id}/related`, `assets/{id}/vulns`,
      `assets/{id}/activity`, `cti/attribution/case/{id}`,
      `cti/iocs/{id}/enrichment`, and the full `intel_reports` set
      (read/misp/patch/delete + scoped list/create). `intel_reports` was also
      missing from the tenancy migration entirely - added `org_id` (schema v4)
      and to `TENANT_TABLES`. Guarded by `test_tenant_e2e.py`.
- [x] **ReDoS in detection-rule `regex` conditions** - DONE (2026-07-03,
      CHANGELOG): a catastrophic-backtracking pattern could hang the detection
      thread (whole-deployment DoS). `rule_engine.is_safe_regex` now rejects
      unsafe patterns at authoring (create/update/backtest → 400) and skips them
      at eval, with input length capped. Guarded by test_pipeline_e2e.py.
- [x] **RBAC: write endpoints gated only by `current_user`** - DONE (2026-07-03,
      CHANGELOG): 13 mutating endpoints (ingest, detection-rule edit, sources,
      hunts, asset create/recompute, feed manage, integration test) now enforce
      their documented capability; a read-scoped key/viewer gets 403. Guarded by
      test_ingest_authz.py.
- [x] **Several dashboard widgets render hardcoded demo data as if live** -
      DONE (2026-06-22): see CHANGELOG. Overview Trending CVEs → /assets/vuln-findings;
      CTI Sector Targeting + Threat Briefs → derived from live actors; SOC-metrics
      analyst throughput/leaderboard → new /soar/analysts, playbook effectiveness →
      /soar/playbooks, automation donut → live; SIEM in-page hunt tab now links to
      the real /siem/hunt workspace. The two genuinely-unbacked SOC-metrics charts
      (alert-volume shape, disposition split) are explicitly badged "sample".
      contradicts the repeated "every number is real data" principle.
      Confirmed static, with no API binding:
      - Overview (`frontend/app/dashboard/page.tsx`) - the **Trending CVEs**
        list (`TRENDING_CVES`).
      - Threat-Intel (`frontend/app/dashboard/cti/page.tsx`) - **Sector
        targeting** (`SECTOR_DATA`) and the **Intelligence briefs** list
        (`BRIEFS`).
      - SOC Metrics (`frontend/app/dashboard/soar/metrics/page.tsx`) - analyst
        throughput, the **analyst leaderboard** (`ANALYSTS`), and **playbook
        effectiveness** (`PLAYBOOK_EFFECTIVENESS`) are constants; only the KPI
        strip + MITRE coverage are live (the CHANGELOG's 2026-06-18 note already
        flagged the first two - promote them to a real fix).
      - SIEM (`frontend/app/dashboard/siem/page.tsx`) - the in-page **Threat
        Hunt** tab shows a fixed `HUNT_RESULTS` / `SAVED_HUNTS` set with
        `ran=true`, while a real `/dashboard/siem/hunt` page already drives
        `POST /siem/search`.
      *Fix:* wire each widget to its existing endpoint, or remove/label it as a
      sample. (The `*_FALLBACK` arrays that overlay live data - `HEATMAP_ROWS`,
      `BRIEF_ITEMS_FALLBACK`, `HOURLY_FALLBACK` - are acceptable offline
      fallbacks and are out of scope here.)
- [x] **SOC Metrics time-range selector is a no-op.** DONE (2026-06-22): the
      no-op 7d/30d/90d control was removed (the backing endpoints aren't windowed),
      along with the "last {range}" relabels. The 7d/30d/90d control
      only relabels the cards ("last {range}"); it triggers no refetch or
      filter (the data effect has `[]` deps and the underlying constants never
      change). Wire it to a windowed query or remove it.
- [x] **Scanner shows fabricated history on an empty install.** DONE (2026-06-22):
      the bundled SCAN_HISTORY rows were removed; Recent Scans is populated live
      from /scans and shows an empty state on a fresh install.
      `frontend/app/dashboard/scanner/page.tsx` keeps the bundled `SCAN_HISTORY`
      rows (acme-corp…) unless a live scan exists (`if (data.items.length > 0)`),
      so a fresh tenant sees invented scans. Render an empty state instead.
- [x] **CI dependency gate is enforced only for `dashboard_api`.** DONE (2026-06-22):
      all three services now run `pip-audit --strict` (gating); only the triaged
      starlette advisory PYSEC-2026-161 is ignored, and only for the two FastAPI
      services (threat_api is Flask, no ignore). Verified clean locally.
      `.github/workflows/security.yml` runs `pip-audit … dashboard_api --strict`
      (fails the build) but `log_api` / `threat_api` use `|| true` (audit, never
      fail), and `log_api` blanket-ignores `PYSEC-2026-161`. A CVE in the two
      flagship services would not break CI. Make all three `--strict`, with a
      reasoned, expiring `--ignore-vuln` only where no fix is yet available.

### Residual from the prior review (still open)

- [x] **D3 - no hash-pinned Python lockfile.** DONE (2026-06-22): added
      `requirements.lock` per service (`pip-compile --generate-hashes`,
      fully hash-pinned incl. transitive deps). The three Dockerfiles now install
      from the lock with `pip install --require-hashes` (reproducible,
      tamper-evident images; the docker-build CI validates them), and a security-CI
      step independently verifies each lock resolves under `--require-hashes`.
      `requirements.txt` stays the human-edited input; regenerate the lock with
      `pip-compile --generate-hashes -o <svc>/requirements.lock
      <svc>/requirements.txt` when it changes.
- [x] **A3 / A4 - Postgres path is a regex dialect translator + a new
      connection per call.** DONE (2026-06-22): `to_postgres` now parses each
      statement with **sqlglot** (a real SQL transpiler) and applies AST transforms
      for the app idioms it doesn't map (INTEGER→BIGINT, INSERT OR REPLACE→ON
      CONFLICT, datetime('now')→now()), replacing the regex rewriter (kept as a
      best-effort fallback for un-parseable statements). Connections now come from
      a **psycopg_pool** pool instead of per-call open/close. Validated against a
      live Postgres 16 locally (full dashboard suite: 386 passed / 2 SQLite-only
      skipped) and in CI's backend-postgres job; SQLite default unchanged (388
      passed). Postgres extras live in `dashboard_api/requirements-postgres.txt`.
- [x] **B9 residual - SP-signed SAML AuthnRequest.** DONE (2026-07-02): with
      `SAML_SP_PRIVATE_KEY` set (PEM, RSA or EC) the SP signs its AuthnRequest per
      the HTTP-Redirect binding (Bindings §3.4.4.1 detached SigAlg/Signature over
      the transmitted `SAMLRequest=…&RelayState=…&SigAlg=…` octets) for IdPs that
      require WantAuthnRequestsSigned. Unset = unsigned, exactly as before. Tests
      verify the signature IdP-side (RSA + ECDSA), parameter ordering, tamper
      detection, and unsupported-key rejection.
- [x] **Test-only: Starlette `TestClient` httpx deprecation.** DONE (2026-06-22):
      migrated the TestClient to its sanctioned successor `httpx2` (Tom Christie /
      Pydantic; Starlette's own deprecation points there). Added as a *test-only*
      dep (`dashboard_api/`+`log_api/requirements-dev.txt`) so production keeps the
      stable `httpx` - the SSRF guard etc. stay on the audited client, unchanged.
      Each service's new `pytest.ini` errors on `StarletteDeprecationWarning`, so a
      missing httpx2 fails CI loudly instead of silently regressing to the shim
      (verified both ways: green with httpx2, red without). CI test jobs install the
      `-dev` files. Suites green: dashboard 388, log_api 18/2-skip, no warnings.

### UX / product findings (2026-06-22, round 2)

User-reported pass over the live dashboard. Several are recurrences of the
"flexible for any device/viewport" principle; one is a hard crash; the reports
item is a large, multi-part feature.

- [x] **Normal-mode Overview (and other pages) leave empty left/right gutters on
      wide screens.** DONE (2026-06-22): the recurring fixed-width problem. The
      `NormalDashboard` (`frontend/app/dashboard/page.tsx`) was pinned to
      `max-w-3xl mx-auto`, wasting most of a wide viewport. Rebuilt as a fluid,
      responsive multi-column layout (health + status side-by-side, priority/quick
      access on a 12-col grid at `xl`) that fills the space at every width. Also
      replaced the hardcoded Detection/Response/Prevention mock scores with a real
      derivation from the health score.
- [x] **Actor Profiles page crashes (white screen) once live actors load.**
      DONE (2026-06-22): the backend emits the motivation `"Disruption"`
      (`threat_actor_library.py`), absent from the frontend `MOTIVATION_CFG`, so
      `cfg.icon` threw. Added `Disruption`, made the motivation/threat/type lookups
      defensive (neutral fallback for any unknown value), and normalised the mapped
      values so no backend string can white-screen the page again.
- [x] **Network map still shakes on continuous (held) zoom in/out.** DONE
      (2026-06-22): the cursor anchor was read from the stale `vbRef` outside the
      `setVb` updater, so during a fast pinch the zoom centre drifted each event →
      wobble. Anchor is now computed from `prev` inside the functional update and
      the viewBox is rounded, so held/pinch zoom is stable.
- [x] **"Ask ThreatOrbit" launcher is an oversized pill.** DONE (2026-06-22):
      collapsed to a circular icon button that expands to reveal the label on
      hover/focus (`AssistantWidget.tsx`), keeping the full affordance on touch.
- [x] **Save buttons require scrolling back to the top.** DONE (2026-06-22):
      added a shared floating Save affordance (`SaveBar`) that appears at the
      top-right while there are unsaved changes, so config can be saved from any
      scroll position; wired into the Settings page.
- [x] **Theme/colour palette doesn't reach everything.** DONE (2026-07-02):
      the migration onto token-based `lib/colors.ts` (`tk()` / `withAlpha()`) is
      complete across the whole dashboard - all per-page severity/status maps
      (Overview, SIEM + attack/entities/hunt/rules/sources, CTI + actors/hunt,
      SOAR + metrics/playbooks/integrations, assets + network/vulns, dark web,
      feeds, scanner, config + users/sources), the SVG chart gradients, the
      network-topology hues, and the world-map choropleth (now an accent-opacity
      ramp, so it themes too) plus the shared panels (CommandPalette, CreateModal,
      EntityGraph, PlaybookBuilder/Runs, IocLifecycle, LogAnalysis, WorldMap).
      Zero hardcoded theme hex remains under `app/dashboard`/`components/dashboard`.
      Deliberate exceptions, unchanged: the report print/download HTML (renders in
      a detached window without the theme's CSS variables), non-token accent hues
      (lavender/orange in CHART_PALETTE), and the marketing site / 3D scenes
      (brand-fixed, outside ThemeScope). Verified: tsc + production build green.
- [x] **"SOC Metrics" reads thin and has an empty section.** DONE (2026-06-22):
      both formerly "sample" charts are now live - new GET /overview/alert-analytics
      returns real 7-day alert volume by severity and the disposition breakdown
      (null = untriaged). The "sample" badges are gone and the empty sections carry
      honest empty states.
- [x] **Reports are consistently lacking vs. mature vuln-assessment tools.**
      DONE (2026-06-22): multi-format + multi-audience reporting.
      • Formats - new `report_render.py` (stdlib only) renders any report to
        JSON / CSV / Markdown / self-contained printable HTML (all HTML-escaped);
        `GET /reports/{kind}?format=…` returns it as a file download. PDF stays
        browser print-to-PDF of the HTML.
      • Audiences - `audience=technical|executive|compliance` reshapes the report:
        Executive (compact: top findings + severity breakdowns + exec framing),
        Technical (full depth, default), Compliance (adds an ISO 27001 / SOC 2
        control-mapping section + evidence framing).
      • Frontend - ReportButton gains an audience selector (re-renders the preview)
        and CSV/MD/JSON download buttons alongside HTML/PDF; the preview + printable
        HTML render the control-mapping section.
      • Tests - the dashboard suite covers every format + audience and HTML escaping.
      Remaining (optional): a heavyweight server-side PDF engine - currently
      unnecessary (browser print-to-PDF covers it dependency-free).

---

## Audit 3 (2026-07-18) - post-Linux-deployment findings (owner's brief audit)

The owner deployed on Linux and ran a brief first inspection. Standing
directive reaffirmed: **stop adding features - fix existing functionality,
remove placeholder behaviour, make every button/workflow work, validate
integrations, improve performance, and QA properly.** The owner should be
finding edge cases, not fundamental breaks.

Status legend: `[ ]` open / `[~]` in progress / `[fix-on-main]` a fix for
this exact symptom shipped on main after the audited build - must be
re-verified on a fresh Linux deployment before it may be called closed.

**Triage round 1 (2026-07-18, same day): systemic root cause found and
fixed.** The built frontend hard-defaulted its API base to
`localhost:8002` while the start scripts build without
`NEXT_PUBLIC_API_URL` - so viewing the deployment from any machine other
than the server silently killed every API call and left the UI running on
leftover placeholder constants (static data, dead actions, fake
"connected" vendors, empty consoles). Fixed (hostname-derived base) and
proven in the cross-machine topology; placeholder fallbacks purged
(Overview live-feed recycler, feeds/sources 16 fake vendor rows,
SOAR-integrations fake fallback). Items below updated accordingly.

1. **[verified] Default mode** - fresh live-posture session starts in
   Normal mode (browser-verified on the owner-faithful build; the backend
   only overrides when an org has explicitly chosen a mode).
2. **[fix-on-main, not reproduced] Landing: second-planet edge boundary** -
   zoomed captures of the current production export show no rectangle on
   any of the five canvases (masks from `9511178` verified). Awaiting
   owner confirmation on the updated build; if it persists there, capture
   the exact GPU/browser and hunt driver-specific compositing.
3. **[~] Landing scroll performance** - measured (4x CPU throttle,
   production export): 8.6fps baseline; attribution showed the WebGL
   loops as the largest cost plus a forced reflow per scroll event in the
   hero. FIXED: all four scenes pause their render loop during active
   scroll (`useScrollIdle`), hero rect cache re-measures on scroll end.
   Loops-paused scroll ceiling doubled (16.8 → 35.3fps on a GPU-less
   rig; real GPUs skip the software-raster floor). Remaining: owner
   confirmation on real hardware.
4. **[fixed] Hero 3D object jumps when scrolling back to top** - drei
   Float wobbled on the absolute clock (kept running while the loop was
   paused off-screen → snap on return) and unclamped deltas integrated
   the whole pause in one step. Pause-safe float + `clampDelta`
   everywhere; return-to-top verified: objects resume from the frozen
   pose.
5. **[~] Dashboard alerts look static ("always exactly 6 critical/high")** -
   root cause split: (a) cross-machine API-base failure froze the page on
   constants - FIXED; (b) the Overview "Live Threat Feed" recycled the
   same rows with fresh ids every 3.5s, manufacturing activity - FIXED
   (honest 15s re-poll of the real endpoint). Remaining: verify the KPI
   numbers move with real detections over time on a long-running deploy.
6. **[~] IOC provenance skew: nearly everything is NVD CVE** - partial
   root cause: feeds/sources rendered 16 fabricated vendor rows
   regardless of reality - REMOVED (backend-only rows + honest states;
   live check shows the real state: NVD + OSINT-engine connectors with
   genuine error reporting). Remaining: run the full stack (threat_api
   bridged) and verify the engine's own intel lands and is labeled.
7. **[fixed] Dashboard elements don't navigate (Critical Alerts, cards)** -
   every Overview KPI/status card now opens the surface it summarises
   (SOC queue / CTI / feed sources / assets) in BOTH modes, and row
   drawers link the exact record (`?alert=` / `?case=`) instead of the
   module. Overview re-polls every 30s so numbers move with detections.
8. **[~] CVE → "Lookup in CTI Scanner" hand-off** - must pre-populate the
   scanner (value + type) and require at most one click (or auto-run).
   In progress together with item 9.
9. **[~] IntelScope depth** (VirusTotal-grade result page) - detailed
   analysis, evidence for the verdict, reputation, sources, related
   indicators, investigation context. In flight on main: tabbed results
   (Details / Relations / Community / Sources), real RDAP registry data,
   relations from own stores (alerts/cases/dark-web/assets/events/graph),
   analyst-history community panel - all honest (no fabricated vendors).
10. **[verified] SOC Console empty** - re-verified on the owner-faithful
    live build: the console renders the full operational shell (queue,
    SLA timers, pipeline health) with real zeros and an explicit "queue
    is empty" note; the blank-page failure was the cross-machine API-base
    defect, now fixed. Populates as soon as alerts exist (e2e-fenced in
    demo posture).
11. **[fixed] "Send to SIEM" (and similar) give no feedback** - action
    toasts now confirm completion AND link straight to the created
    record: feed "Send to SIEM" → "Open alert →" (`?alert=`), SIEM
    "Create Case" → "Open case →" (`?case=`), "Suppress" → "Manage /
    undo →" (suppressions panel anchor). Linked toasts persist 10-12s.
12. **[~] Threat-feed verification + connector management** - the fake
    paid-API placeholder rows are gone (feeds/sources + SOAR
    integrations now backend-only with honest unreachable/empty states),
    and the connector panel already reports genuine per-connector errors
    (verified live: NVD 403, engine connection refused). Remaining:
    connector edit/reconfigure/API-key management UI (task #89).
13. **[ ] CTI CVE actions fail** - dead buttons, pages fail to load; every
    CVE entry needs official references (NVD/vendor/mitigation) that
    actually resolve.
14. **(deferred by owner)** Dark-web section stays as-is until core
    functionality is fixed.
15. **[ ] Attack visualisation** - per attack/investigation: timeline,
    affected systems, attack path, relationship map ("how did this attack
    happen?", not isolated alerts). Verify network-map data provenance
    while there.
16. **[ ] Undo / action history** - critical analyst actions (e.g. threat
    suppression) need discoverable reversal: undo affordances, recent
    actions, action history.
17. **[fixed] SIEM Rules Engine** - root cause: the page cast the API
    response onto the seed display type, so opening any real rule crashed
    (`hits24h.toString()` / `tags.join()` on mismatched fields). Added a
    `normalizeRule()` (parses tags/definition, aliases snake-case
    counters, labels the integer suppression window). Panel now opens
    clean; Save persists the severity override (`PATCH`, empty→NULL),
    Delete is wired, new Test Rule backtests structured rules (disabled
    with tooltip for KQL-only display rules), new Related Alerts filters
    the queue to the rule's alerts. Write actions gated on siem.write.
    Backend test extended; live-verified.
18. **[ ] ATT&CK Navigator** - "View Matching Alerts" (and other entity
    actions) fail; wire every entity action to real alerts/investigations/
    techniques.
19. **[ ] Entity Risk** - many non-functional links/actions; every
    displayed action must work.
20. **[ ] SOAR feels incomplete** - empty pages, missing workflows, little
    automation evidence; needs playbooks, automated responses, workflows,
    analyst approvals, action history demonstrably working.

**Process obligation (standing):** each item gets reproduce-first triage on
a fresh Linux live deployment; fixes ship with regression fences (unit/e2e);
"fix-on-main" items are only closed after re-verification on the deployed
artifact.

---

## Audit 4 (2026-07-22) - owner's enterprise-readiness audit

Owner's fourth deep audit. Standing directive reaffirmed: **complete existing
workflows, eliminate dead links, improve usability, validate integrations -
not surface-level features.** The bar is "survive a professional enterprise
audit with no obvious functional issues." Items carry code-level triage notes
found while reading the tree on 2026-07-22.

Status legend: `[ ]` open · `[~]` in progress · `[x]` done (moved to CHANGELOG)
· `[answered]` investigation question resolved in-thread.

### Administration & identity

1. **[x] Admin Panel + RBAC + sign-up validation.**
   **Sign-up validation - RESOLVED (2026-07-22).** On reading the code, the
   register endpoint *already* enforces the input validation the audit asked
   for: rate-limit throttle, a disable switch, required name + length cap,
   email-format regex, password complexity (`password_policy.validate_password`),
   and duplicate prevention (409) - plus client-side strength/format gating.
   The genuine gap was **email-ownership verification**, now SHIPPED (gated,
   opt-in): `DASHBOARD_REQUIRE_EMAIL_VERIFICATION=true` (+ SMTP configured)
   makes a non-first signup land in `status='pending'`; a single-use,
   24h-expiry token (hash stored in `settings`, no migration) is emailed via
   the existing `mailer.py`; login is blocked until verified; `POST
   /auth/verify` activates; `POST /auth/resend-verification` re-sends without
   account enumeration. Frontend: signup shows a "check your email" state, a
   new `/verify` page consumes the link, `lib/api` helpers added. The
   bootstrap admin is always active (deployment can't lock itself out); OFF by
   default so existing deployments/tests are unchanged. Backend test covers
   pending→blocked-login→verify→login + single-use/invalid-token.
   **Admin password reset - SHIPPED (2026-07-22).** The one missing admin
   user-management capability (the page already had create / edit / role /
   suspend-unlock / delete / revoke-sessions / MFA-reset): new
   `POST /users/{id}/reset-password` (`users.manage`) sets an admin-supplied
   password OR generates a strong temporary one (returned exactly once, never
   stored in the clear), and bumps the token epoch so every existing session
   is invalidated. Config → Users panel gains a "Reset password" action that
   shows + copies the temp password. Tested (generated + explicit + weak-400 +
   404 + old-password-dead + new-works).
   **Admin console landing page - SHIPPED (2026-07-23).** New
   `/dashboard/admin` consolidates every admin surface into one governed
   launch-point: an estate-at-a-glance strip (total / active / disabled users,
   admin count, MFA-enrolment %, all from `fetchUsers` - real, never
   placeholders), capability-gated navigation cards grouped into Identity &
   access, Security & compliance, and Platform & data (each deep-links to the
   real existing surface, not a copy), and a live "recent activity" feed from
   `fetchAuditLog`. The whole page is gated on `config.manage` (admin + SOC
   manager); analysts/viewers get an honest "administrator access required"
   state rather than an empty page, and each card is additionally hidden unless
   the caller holds its specific capability. Config page gained `?tab=` deep-link
   support so cards land on the exact settings section (e.g. `?tab=security` →
   Audit Trail). Sidebar gains an "Admin Console" entry under System. Build +
   lint (0 errors) + route-integrity (no dead links) all clean.
   **RBAC policy editor SHIPPED (2026-07-23) - #1 now COMPLETE.** The Config →
   Users & Roles "Roles" tab was a *static, hardcoded* permission matrix; it is
   now a live editor driven by the real `/roles` API (built-ins + custom roles +
   the capability catalogue). New `RolesEditor` component: built-in roles render
   read-only (lock badge) with their true capabilities; custom roles can be
   **created, cloned from any role, edited by toggling capabilities, and
   deleted**, each card showing the real capability matrix from the API. It
   honours the backend guarantees - surfaces the actual reason on failure
   (no-privilege-escalation 403, duplicate 409, "N users still hold this role"
   delete-409) instead of a generic error, gates every mutation on
   `users.manage` (view-only otherwise), and two-step-confirms deletes. Added
   `fetchRoles/createRole/updateRole/deleteRole` helpers; the `/roles` CRUD was
   already complete + tested (test_roles.py, 7 passing). Build + lint (0 errors)
   + route-integrity clean. Every sub-part of #1 (RBAC, sign-up validation,
   email verification, admin password reset, admin console, role editor) is now
   shipped - **nothing remaining.**
2. **[~] Account Settings page.** Profile menu "Profile & settings"
   (`TopBar.tsx:288`) routes to `/dashboard/config` (admin config, not a
   personal profile). Build a dedicated Account Settings page: profile, change
   password, 2FA enrol, active sessions, notification prefs, personal UI prefs,
   personal API tokens. (In progress this session.)

### Data honesty & scoring

3. **[x] Security Posture stuck at 100%.** DONE (2026-07-22): shared
   `computePosture()` now derives the gauge (both Normal + Power modes) from
   real operational signals - the prevention baseline (inverse average asset
   risk) is pulled down by live threat pressure: open critical/high alerts
   (`kpis.threats` + `siem.critical`), active/critical incidents, and SLA
   breaches. Critical alerts now visibly move the number instead of leaving it
   pinned at 100. The three pillars (Detection = inverse FP-rate, Response =
   SLA compliance, Prevention = asset-risk posture) decompose it honestly.
4. **[answered] The "same six NVD CVEs".** They are **real CVE records**, not
   fabricated: `vuln_scanner.py::CVE_CATALOGUE` is a hand-curated set of genuine
   well-known CVEs (Log4Shell CVE-2021-44228, Heartbleed CVE-2014-0160,
   regreSSHion CVE-2024-6387, sudo CVE-2021-3156, SMBGhost CVE-2020-0796, …)
   with accurate CVSS + affected-version ranges. In **demo mode** (`seed()`)
   the scanner matches them against **seeded demo assets** - deterministic
   (`SEED_RANDOM` fixed), hence always the same six. In **live mode**
   (`bootstrap_live()`) there are no seeded assets; CVEs appear only from the
   live NVD connector (`connectors.py::_fetch_nvd`, real `services.nvd.nist.gov`
   API) matched against real scanned assets. So: CVEs genuine, the *assets*
   they're found on are demo. **Follow-up (open):** the UI doesn't badge
   demo-seeded findings vs live findings - add a clear "sample data" marker in
   demo mode so it can't be mistaken for live intel.
17. **[answered] Dark-web data genuine?** Partly plumbing, not a live source.
    `darkweb_logic.py` has **real** logic - credential-leak matching against
    the actual user directory (with public-domain guarding), a takedown
    workflow, and a `darkweb-json` connector sink that imports findings from any
    real leak-DB / paste-monitor API. But the platform does **not** itself crawl
    the dark web: absent a configured `darkweb-json` connector, the findings
    shown are **demonstration data** (demo seed). To make them genuine, wire a
    real leak-database/paste-monitor feed via the connector. (Owner previously
    deferred dark-web implementation until core is fixed - unchanged.)

### Navigation & workflow completeness

5. **[x] Live Processing Engine → Imports page (OpenCTI-style).** DONE
    (2026-07-22): new `/dashboard/feeds/imports` page (nav: Threat Feeds →
    Imports), all from real endpoints, auto-refreshing every 15s:
    • pipeline summary - processing-queue depth + in-flight, engine burst
      cadence (`tickSeconds`), queue lag/shedding, total indicators
      (`fetchEngineStatus`);
    • import sources - every connector's live status / last-import / indicator
      count / last error, with an **admin-settable per-source cadence** (the
      "delay between processing bursts" - `interval_minutes` via
      `patchConnector`) and an Import-now button, both admin-gated;
    • recent import jobs (`fetchJobs`) with status + progress = the
      success/failure log;
    • recently-imported indicators (`fetchIocs`, newest first-seen) as the
      real-time import stream, each linking to IntelScope.
    Genuine live intel by construction (reads the same stores the pipeline
    writes - nothing generated). The global engine tick stays env-config
    (`DASHBOARD_ENGINE_TICK_SECONDS`) since it's a background-thread constant;
    the per-source cadence is the settable knob.
6. **[~] Dead links.** Named: SOAR→Alert→Affected Systems, SOC→SLA Breach
    Queue, CTI→IOC actions, Related Alerts, ATT&CK Navigator actions.
    Systemic root cause found + fixed (2026-07-22): most of these DID link, but
    with `?q=<value>` to a SIEM queue whose filter only matched
    title/ruleId/ruleName/srcIp - so pivots on a **hostname, username,
    dest-IP or MITRE technique** landed on an empty-looking queue (reads as
    dead). Broadened the SIEM `?q=` match to src/dest IP + hostname + username
    + mitreTech/mitreTechId/mitreTactic, and made Normal mode drop its
    actionable-only restriction while a search/deep-link is active so the
    target is findable. Also wired the two non-clickable "Related Alerts" rows
    (SIEM entity detail) to pivot. This fixes SOAR affected-systems host/user
    pivots, ATT&CK "View matching alerts", and entity Related-Alerts in one go.
    SOC SLA breach rows verified already navigating. Remaining: CTI per-IOC
    action set (folded into #14).
7. **[~] SOC Console redesign.** Big step done (2026-07-22): the console had
    KPIs + SLA-breach queue + pipeline health but no analyst work surface. Added
    a full-width **Investigation Queue** driven by the live alert store
    (`fetchSiemAlerts`): **search** (title/rule/IP/host/user/owner), **severity**
    + **assignment** (all/mine/unassigned) filters, an **analyst-workload** chip
    row (open alerts grouped by assignee), per-alert **Assign to me**
    (`patchAlert` owner+status, admin-perms enforced server-side), and every row
    opens the exact alert (`?alert=`). So: active alerts ✓, investigation queue
    ✓, analyst assignments ✓, search/filter ✓, SLA monitoring ✓ (existing).
    Escalations/incident-timeline/collaboration reach the SOAR case war-room via
    the alert→SIEM→case path. **Inline escalate-to-case SHIPPED (2026-07-23):**
    every Investigation-Queue row now has a one-click **"case"** button that
    opens a real SOAR investigation case seeded with the alert's entities
    (`createCase`, ip/host/user), marks the alert in-progress + owned so the
    queue stays honest, and pops a confirmation toast with a **direct link to
    the new case** - no leaving the console to escalate. Build + lint (0 errors)
    + route-integrity clean. Remaining (minor polish): a collaboration/notes
    side-panel inline on the console (notes already live in the SOAR case).
8. **[x] Undo for destructive analyst actions.** DONE (2026-07-23). Prior undo
    work (task #92) covered the SIEM triage actions (status / disposition /
    assign / escalate all offer an "Undo" toast via `flashUndo`). The two the
    audit named were the Threat-Feeds card actions:
    • **Dismiss** was a one-way client-side removal - now **reversible**: the
      dismissed card is stashed with which column it came from
      (confirmed/unconfirmed) and a bottom-centre **Undo toast** (7s window)
      restores it into the exact list, de-duped against any live refresh that
      re-added it. So an accidental dismiss is one click to recover.
    • **Block IOCs** writes real indicators into the CTI store and there is no
      one-click "unblock" endpoint, so undo would be dishonest - instead it's
      **confirm-gated**: the first click arms the button ("Confirm block?",
      amber), a second within 4s commits (then "Blocking…", disabled), and it
      auto-disarms if not confirmed. This matches the audit's "confirm prompts"
      for the genuinely-irreversible action while keeping the reversible one
      (dismiss) a true undo. Build + lint (0 errors) + route-integrity clean.
9. **[x] SIEM deep-link on "Send to SIEM".** DONE (2026-07-23). `?alert=<id>`
    already opened the exact record's detail drawer (not just the module) and
    the source action ("Send to SIEM" in the IOC panel) already toasts with a
    direct link before navigating (task #88). The missing piece - now added -
    is the landing behaviour: the deep-linked alert's **queue row auto-scrolls
    to viewport centre** (`scrollIntoView({ block:'center', behavior:'smooth' })`)
    and **flashes** a magenta pulse (keyframed backgroundColor over ~2.4s, then
    self-clears), so the analyst sees exactly *where* in their queue the record
    lives, not just the opened drawer. Best-effort for the rendered row; the
    drawer opens regardless, and the existing `?q=` fallback still finds alerts
    outside the loaded window. Build + lint (0 errors) + route-integrity clean.
    **Normal-mode gap CLOSED (2026-07-23, found via e2e runtime pass):** the app
    defaults to Normal mode, whose triage board is a *separate* component with
    no alert drawer - so `?alert=<id>` set `selectedId` but nothing rendered the
    record (a hard dead-link in the default mode; the `deep-links` e2e caught
    it). Fixed by lifting the `AlertDetail` drawer into the Normal-mode return
    so a deep-linked alert opens its exact record in both modes; also pinned the
    open/deep-linked alert into the Power queue's Normal filter so its row stays
    visible in context. `deep-links` e2e + all 17 SIEM-touching specs green.
13. **[ ] CTI CVE actions** (carried from Audit 3 #13) - still dead per this
    audit's item 14/21; fold into the dead-link sweep.
14. **[~] Every IOC action works.** The IOC lifecycle panel now wires the full
    action set: Open in IntelScope (scanner), Matching alerts (SIEM `?q=`),
    Record sighting, Mark/Un- known-good, Enrich, FP likelihood, STIX export,
    and NEW (2026-07-22) **Send to SIEM** (raises a manual alert via
    `/siem/alerts`, then links to it) and **Create case** (opens an
    investigation case via `/soar/cases` seeded with the indicator as an
    entity, then links to it) - both with confirm+link feedback. Remaining:
    related-cases lookup surfaced inline (the case link + entity seeding cover
    the create path).
15. **[~] Per-investigation graph.** DONE for the CTI investigation graph
    (2026-07-22): `buildGraph()` was already per-actor but always emitted the
    same fixed 4-ring template (Campaigns/TTPs/IOCs/Sectors) with generic IOC
    buckets, so every actor's graph looked structurally identical. Now it (a)
    adds an **Aliases** ring from the actor's real aliases (previously unused),
    (b) drops **empty** groups and zero-count IOC buckets, so a rich actor
    renders more rings/nodes and a sparse one renders fewer - each
    investigation's graph is visibly its own. (SOAR cases already carry their
    own per-incident relationship view: Affected-systems + Attack-timeline.)
    Remaining: a malware-family ring (needs the field threaded onto the CTI
    display type) and edge-level relationship weighting.
21. **[ ] ATT&CK Navigator dead links** - "Related Alerts" and per-entry
    actions must resolve (overlaps Audit 3 #18).

### Connectors & intelligence quality

10. **[~] Threat-feed filtering + connector controls.** **Filtering SHIPPED
    (2026-07-22):** the Threat Feeds page had only a severity chip row; now
    also filters by **confidence band** (high ≥85 / medium 65-84 / low <65),
    **source** (dropdown built from the feeds actually present), and a **free-
    text search** over title / attack-type / country / IOCs / feed-sources /
    MITRE techniques, with a Clear button - and all four are saved/restored
    through the existing SavedViews ("saved filter configurations"). Remaining:
    a couple more facets (explicit IOC-type / actor / malware-family / tags /
    time-range). **Connector controls DONE (2026-07-22):** ConnectorsPanel
    already had sync-now / pause-resume / edit-reconfigure / delete + honest
    per-connector status & error; added **admin-gating** - every mutating
    control is now disabled with a "Requires administrator privileges" tooltip
    (and a "View-only" note) for users without `connectors.manage`, exactly the
    audit's "greyed / requires administrator" ask. (Sync-now already doubles as
    a connectivity/health check - it reports the real per-connector error.)
11. **[~] Per-connector config fields.** Setup asks generic type+URL; each
    connector must present only its real fields - OTX→API key, VirusTotal→API
    key, MISP→URL+key, TheHive→URL+key - and be correctly wired. `connectors.py`
    already knows each kind's shape (`KIND_PRESETS`); the config UI must read it.
    Partial (2026-07-22): **VirusTotal wired the honest way.** VT is an
    *enrichment* provider (per-IOC lookup), not a feed - it lives alongside
    GreyNoise/Shodan/WHOIS in `enrichment.py` and was previously env-var-only.
    Added UI configuration: `enrichment.provider_key()` now reads a settings-
    stored, encrypted key (env-var fallback preserved); new `GET/PUT
    /config/enrichment` endpoints (admin-gated, key never returned); a
    Config → Integrations → **Enrichment providers** panel to paste/save/clear
    each key with a live status badge. Backend test covers the round-trip +
    that the key activates the provider. Remaining: MISP/TheHive feed
    connectors and the per-*feed*-connector field schema in the Add-connector
    form.
12. **[x] Connector marketplace.** DONE (2026-07-22): a "Browse catalogue"
    toggle on the connector panel shows every supported integration
    (`fetchConnectorKinds`) as a card - label, description, an "API key
    required / no key needed" badge, a "configured" tick if one already exists,
    and a one-click **Configure →** that opens the add form pre-set to that
    kind (new `initialKind` prop → the right fields, e.g. OTX opens straight to
    its API-key field). Admin-gated. (There was no separate "Search Feeds"
    route; the catalogue lives with the connectors it configures. VirusTotal
    isn't here because it's an *enrichment* provider, configured in its own
    panel - see #11.) Minor remaining: hide the (fixed) URL field for
    managed keyed kinds like OTX so only the key shows.
13b. **[~] IntelScope redesign** (item 13). **Input-type validation SHIPPED
    (2026-07-22):** the scanner already had URL/IP/Hash/File type tabs + a File
    upload section (the two-section layout the audit asked for); now each tab
    validates the entered value against its type - an IP typed in the URL field
    (or a URL/hash in the IP field, a non-hash in the Hash field) is caught with
    a specific "switch to the X type" message, the Scan button disables, and a
    manual scan/Enter is blocked. Real-data pivots are never gated. Deeper
    results already exist (Audit 3 #9: Details / Relations / Community / Sources
    tabs, real RDAP registry data, relations from own stores). **Result depth +
    Domain tab SHIPPED (2026-07-23):**
    • The Details tab now surfaces the **structured external-provider data**
      that was previously only a one-line summary - a **VirusTotal detection
      ratio** card (multi-engine malicious/suspicious/harmless/undetected split
      with a ratio bar, from `last_analysis_stats`), a **GreyNoise** card
      (internet-scanner classification / RIOT / actor tag / last-seen), and a
      **Shodan exposure** card (open ports + known-CVE list, each CVE a
      one-click re-scan pivot). Every card is gated on the provider's honest
      `available` flag, so nothing renders (or invents data) when a key isn't
      configured - real VirusTotal-grade depth exactly when the deployment has
      wired those providers (see #11).
    • Added a first-class **Domain** input tab (bare-host lookup, `example.com`)
      with its own validator that steers full-URL/IP/hash input to the right
      tab; a domain scan drives the same RDAP registry lookup, so the Details
      tab renders registrar / registration date / age / nameservers - the
      WHOIS/DNS depth the audit asked for. (`domain` was already a recognised
      backend scan type; this gives it a dedicated tab.)
    Build + lint (0 errors) + route-integrity (283 links, no dead) clean.
    Remaining (minor): a full historical detection *timeline* (needs
    per-provider result history retained over time; today only the latest
    enrichment is cached) and inline ATT&CK technique mapping on non-demo
    results.
16. **[~] Threat Actor profiles.** Collapse bug FIXED (2026-07-22): the actor
    card's rotating chevron implied expand/collapse but `onSelect` only ever
    selected, so it never closed - now it toggles (click the open actor again
    to collapse). The detail panel already carries bio, aliases, origin, type,
    sophistication, first/last seen, motivation, ATT&CK TTPs (linked), and
    target sectors. **Filter bar EXTENDED (2026-07-22):** the actors page
    already filtered by origin (region/country), motivation and type + search;
    added **Industry** (built from the actors' sectors) and **Sophistication**
    (1-5) selects - so the audit's filter set (industry/region/motivation/
    sophistication/country) is covered. **Profile body ENRICHED (2026-07-23):**
    the detail panel already carried campaigns + malware/tooling; added (a) an
    **Active** header stat showing the actor's operating span (first-seen year →
    last-seen year, or "present" with a live dot when the record's `active` flag
    is set - both now threaded from the API `firstSeen`/`lastSeen`/`active`
    fields), and (b) an **Attribution Assessment** block: a High/Moderate/Low
    confidence band *derived transparently* from the corroborating evidence
    actually on the record (named origin, cross-vendor aliases, mapped ATT&CK
    techniques, attributed tooling, documented campaigns) with the reasons
    listed beside it, so the band is auditable rather than asserted - and no
    fabricated percentage. (Target-regions intentionally NOT added: there is no
    target-geography field in the data and inventing one would be fabrication;
    `origin` is the actor's own region, already shown.) Build + lint (0 errors)
    + route-integrity clean.
18. **[~] Reporting depth.** Visuals added (2026-07-22): `report_render.to_html`
    now embeds **self-contained inline-SVG charts** (no external libs, print-
    clean) built from the report's real data - a **findings-by-severity donut**
    beside the KPI tiles and a **horizontal bar chart** above every breakdown
    table (severity-coloured), while the exact-number tables stay for
    precision. Verified rendering + all 13 report tests pass. Combined with the
    existing multi-format (HTML/PDF/CSV/MD/JSON) + multi-audience (exec/
    technical/compliance) + control-mapping work, reports now carry charts,
    statistics, executive summaries, analyst findings and visual dashboards.
    **Time-series + geographic SHIPPED (2026-07-23):**
    • **Trend line** - the SIEM and executive reports now carry a real, zero-
      filled **per-day alert-volume series** (`_daily_buckets`, computed in
      Python from the already-fetched rows so it's DB-agnostic and always
      consistent with the findings shown; skips windows too wide to plot). A new
      stdlib inline-SVG `_svg_line` (line + area + dots + date axis, print-clean)
      renders it in the report body, right under the KPI/donut block. The
      `series` field survives all three audience reshapes.
    • **Geographic aggregation** - a **"Alert sources by country"** breakdown
      (`_geo_breakdown` over the real `src_country` column, top-8) that renders
      via the existing severity-coloured bar renderer. Only appears when alerts
      actually carry a country - never fabricated.
    Backend test added (series present + zero-filled + geo breakdown + both
    drawn in the HTML render); all report tests pass.
    Remaining (deferred, disproportionate for a stdlib module): a full
    **choropleth world-map SVG** - it needs an embedded country-path/centroid
    dataset (tens of KB) that would bloat the report renderer; the top-country
    bar communicates the same geographic distribution faithfully.
19. **[~] Per-IOC context.** DONE for the IOC detail panel (2026-07-22): the
    IocLifecyclePanel (the canonical IOC drill-down across CTI) now renders a
    "Context" block - What it is / Why it's flagged / Potential impact /
    Recommended action. Type-keyed honest SOC guidance (ip/domain/url/hash/
    email/cve), with the "why" line built from the record's REAL fields
    (source, actor, threatType, confidence, severity, sightings, tags) - not
    fabricated specifics. Remaining: surface the same context on the IntelScope
    result page (folds into #13).

### UI polish

20. **[~] Toggle switches inverted / overflow.** Root cause: three divergent
    ad-hoc toggle geometries (config `w-9 h-5`/knob `w-4`; siem-rules
    `w-8 h-4.5`/knob `w-3` vertically off-centre `top-0.5`; feeds-sources
    variant). Fix: one shared `Toggle` component - correct on/off semantics,
    perfect centring (flex `items-center`), no overflow (padded travel), eased
    knob - swapped in everywhere. (In progress this session.)
22. **[x] Text scaling consistency + smooth slider.** DONE (2026-07-22): the
    UI-scale slider was `step={0.1}` (fixed 10% jumps) - now `step={0.01}`
    (continuous 1% steps, 90-150%), so any size is reachable (102%, 116%, …).
    The "not all text responds" perception was the coarse stepping, not the
    mechanism: scaling is CSS `zoom` on the ThemeScope wrapper, and a repo-wide
    check confirmed **zero** `createPortal` usages - every modal/drawer/toast
    renders in-tree, so the whole dashboard (including overlays) scales
    uniformly. Consistent + smooth.
23. **[~] Sidebar collapse polish.** Expand (hover) is smooth; collapse is
    "abrupt/uneven" - width uses a direction-asymmetric spring
    (`Sidebar.tsx:262`) while label content unmounts instantly. Fix: symmetric
    eased tween for width + coordinated content fade. (In progress this session.)

**This session's batch (2026-07-22):** #2, #20, #23, #3 first (self-contained,
verifiable); the large items (#1 Admin Panel, #5 Imports, #7 SOC redesign, #13
IntelScope, #18 reporting) are staged as tracked follow-ups.

---

## Open roadmap (remaining work only - finished items live in the CHANGELOG)

**Shipped & complete** (full detail in the CHANGELOG below): Phase 0
cross-cutting platform, Phase 1 SIEM depth, Phase 2 SOAR depth, Phase 3 CTI
depth, Phase 4 asset/vuln/dark-web depth, Phase 5 polish & scale, and the
Tier-1 go-live hardening (secrets-at-rest, TOTP MFA, OIDC/SAML/SCIM SSO,
backup/restore, observability baseline, deployment hardening, signed
releases + SBOM + Trivy, custom-role/break-glass RBAC, versioned `/v1` API).

**Positioning today.** Small single-node deployments (≤~50 assets, low EPS):
a strong beta - the Tier-1 punch list is essentially closed. Mid-size: needs
the Tier-2 items. Large enterprise / MSSP: needs the Tier-3 re-architecture
plus external compliance attestations.

### Tier 1 - before any paying deployment

- [ ] **Pilot validation with real logs** - deploy against a live environment,
      forward real syslog/files, and tune parsers + built-in rules on actual
      data (the generated event stream proves the pipeline, not parser
      coverage).
- [~] **Security pass** - dependency audits, disclosure policy, and patched
      backend pins shipped. Remaining (env-gated / external): a third-party
      pentest before first sale, and re-check `PYSEC-2026-161` when FastAPI's
      Starlette ceiling moves.

### Tier 2 - mid-size deployments

- [x] **Published load limits.** DONE (2026-07-08): backpressure, a measured
      SQLite EPS baseline, a now-measured **Postgres** EPS baseline (`bench.py`
      + `docs/LOAD_LIMITS.md`), and per-endpoint UI dataset ceilings all
      shipped. The Postgres measurement corrected a previously-unverified
      assumption in `LOAD_LIMITS.md` that switching to Postgres alone would go
      "materially higher" - measured, it's markedly *slower* than SQLite for
      the current pipeline (one round-trip statement per event row, no
      batching), which is now the concretely-scoped remaining item below.
- [x] **Batch the per-row ingest writes on Postgres.** DONE (2026-07-09):
      `ingest_lines` now collects a batch's rows and issues one
      `conn.executemany(...)` instead of one `conn.execute(...)` per event -
      measured ~5.7x faster on Postgres (~670 → ~3,800 EPS, `bench.py` +
      `docs/LOAD_LIMITS.md`). The "detection-claim path" named in the original
      version of this item turned out to already be batched once actually
      read (`event_queue.claim` is one `UPDATE … WHERE id IN (…)`, `.complete`
      was already `executemany`) - not a real gap, corrected here rather than
      left inaccurate. Remaining, lower priority: `_insert_alert` (one write
      per firing match) isn't batched - matches are a small fraction of raw
      events in a realistic mix, so this matters far less than the ingest path
      did. 4 workers still ≈ 1 worker on the `drain` benchmark (unaffected by
      this fix, since drain was never bottlenecked on claim/complete) - that's
      about the detection-processing side, not ingest.

### Tier 3 - large enterprise / MSSP

- [~] **Event pipeline at scale** - the queue seam, bounded ingest (HTTP 429 +
      Retry-After), and a concurrency-safe multi-worker detection pool shipped.
      Remaining: flip the engine to **ingest-only** by default, and partition or
      externalise the event store (ClickHouse / OpenSearch behind the same hunt
      API, with predicate push-down).
- [x] **Finish multi-tenancy for GA.** DONE (2026-07-02): the end-to-end
      validation pass is in (`tests/test_tenant_e2e.py` - a second workspace with
      its own admin drives create→stamp→list→detail→mutate across SIEM/SOAR/
      assets/CTI, aggregate scoping, per-workspace import dedup) and it caught +
      fixed five real isolation gaps (manual-alert org stamping, alert get/patch
      and asset get cross-org guards, case patch scoping, cross-tenant IOC-import
      dedup oracle). Flipping `DASHBOARD_MULTI_TENANT` on is now purely a
      per-deployment decision for MSSP builds (set it in that environment).
- [~] **HA / DR / zero-downtime** - Helm chart, DB-backed leader lease,
      schema-version boot gate, full-stack backup/restore drill, multi-AZ
      Postgres guidance, and (2026-07-02) the **packaged scheduled-backup job**
      shipped: an opt-in compose service (`--profile backup`,
      `scripts/backup_loop.sh`, interval + retention pruning) and a Helm CronJob
      (`backup.enabled`, dedicated PVC, co-scheduled with the service pods) -
      both wrapping the same consistent tar.gz snapshot. Remaining: an actual
      **tested** failover drill (needs live multi-AZ infra).
- [~] **Vendor compliance posture** - DPA template, GDPR data-subject tooling,
      data-residency doc, and a SOC 2 / ISO 27001 control self-assessment
      shipped. Remaining (external, can't self-certify): an independent **SOC 2
      Type II** then **ISO 27001** program.

### Cross-cutting maturity (from the honest gap analysis)

- [~] **Supply chain** - DONE (2026-07-15): the trailing frontend majors are
      cleared - tailwindcss 3→4 (CSS-first `@theme`, official upgrade tool,
      screenshot-verified), tailwind-merge 2→3, `@types/node` 20→22 (pinned to
      the runtime actually targeted: CI and the frontend Dockerfile are both
      Node 22 now that Node 20 is EOL), and ESLint works again post-Next-16
      (`next lint` removal) with an errors-only gate in CI. Remaining: an
      in-product "platform updates" upgrade notice, and signing published
      **container images** once a registry push pipeline exists.
- [x] **Detection content.** DONE (2026-07-09): `POST
      /siem/rules/import-sigma-pack` bulk-imports a pasted Sigma rule
      collection (`---`-separated multi-document YAML, the format downloaded
      rule sets ship as) in one request - each document parsed and inserted
      independently so one bad rule doesn't block the rest, capped at 500
      rules, a structured created/failed report. `SigmaImportButton` routes
      to it automatically on a multi-document paste. See `CHANGELOG.md`.
      Imports land as individual `source='sigma'` rules (not the code-shipped
      `content-pack` versioning system, which is for vetted, code-reviewed
      content - user-imported rules stay in their own trust tier).
- [~] **Compliance & data lifecycle** - DONE (2026-07-02): the **PII handling /
      redaction policy** (`docs/PII_HANDLING.md` + opt-in `DASHBOARD_LOG_REDACT`
      redaction at the single ingest seam - email/secret/cc/ssn masked in raw
      text before persistence, pivots retained) and the **audit-sink persisted
      cursor + replay** (outbox drain over the committed `audit_log` with a
      persisted cursor: at-least-once across restarts/outages, ordered, one
      drainer via the DB lease). Remaining: native syslog / object-lock writers
      for the audit sink.
- [~] **Platform SRE / self-observability** - Started (2026-07-13):
      `dashboard_api/self_health.py` aggregates the platform's *own* vitals
      (DB reachability + latency, schema version, detection-queue backpressure,
      leader lease, process counters) into one verdict, surfaced at authed
      `GET /self-health` and a Settings → System Health card; a leader-gated
      monitor thread raises a `platform.health` notification on verdict
      transitions (alerting on the platform's own health); and `/ready` now
      returns a true 503 when the DB is unreachable (readiness-contract fix).
      Remaining: distributed tracing, SLOs + error budgets, and external
      synthetic checks (`/metrics` + self-health cover the in-process side).
- [~] **Product, UX & quality.** Started (2026-07-08): automated a11y
      regression testing (`@axe-core/playwright`, `e2e/a11y.spec.ts`) now runs
      in CI against login/overview/SIEM/SOAR/Config, and its first run caught
      + fixed 4 real bugs (a sitewide skip-link with no target, 6 unlabeled
      Config form fields, 2 indistinguishable nav landmarks, a missing `<main>`
      on login) - see `CHANGELOG.md`. Also present already: connector SSRF
      regressions (`test_net_guard.py`, `test_connector_resilience.py`) and
      retry/backoff webhook delivery (`webhooks.py`) count toward "standing
      SSRF/authz/XSS regressions" and "notification reliability" respectively.
      DONE (2026-07-08): `--ink-500` and the alert-count badge now clear
      4.5:1 AA across all 11 themes, checked against every surface level
      (see `CHANGELOG.md`). Remaining: `--ink-600` (480+ usages sitewide)
      still falls short of AA in real-text contexts (e.g. activity-feed
      timestamps) - naively lightening it collapses it visually onto
      `--ink-500`, so this needs per-usage triage, not a token edit: split
      out which of the 480+ usages are genuine informational text (needs a
      lighter, AA-compliant color) vs. WCAG SC 1.4.3-exempt "inactive UI
      component" text (disabled buttons, placeholder-style hints - legally
      doesn't need AA contrast at all) and fix only the former, possibly by
      introducing a distinct token for "muted-but-still-informational" text
      rather than reusing `--ink-600` for both purposes. The rest of a full
      keyboard-nav/screen-reader pass beyond what axe-core catches mechanically
      (axe covers roughly a third of WCAG's criteria); i18n; notification
      templating/digests/escalation policies; chaos/failure-injection and
      connector contract tests; GTM plumbing (trial/free-tier flow, usage
      metering, in-product upgrade prompts, status page, support surface).

### Evidence-based false-positive identification (SIEM alerts + CTI IOCs)

- [x] **Phase 1+2 (scoring engine, API, and UI panel) shipped.** Requested
      by the project owner (2026-07-09): identify false positives from
      *strong evidence and findings*, for both SIEM alerts and CTI IOCs -
      not the manual-only mechanisms that exist today.

**The gap, precisely.** FP handling today is manual and retroactive, and
never looks at the specific alert/indicator's own evidence:

- Marking an alert `disposition=false-positive`
  (`dashboard_api/routers/siem.py::update_alert`) bumps its **rule's**
  `fp_rate` by a flat `+2` (capped at 100) - a blunt per-rule counter, not a
  per-alert judgement, and it carries no reasoning.
- `dashboard_api/ioc_lifecycle.py::set_known_good` is the IOC-side
  equivalent - a manual whitelist override (`dashboard_api/routers/cti.py`,
  `ioc.known_good` audit action), also with no evidence attached.

Neither uses the corroborating context the platform already collects (asset
criticality, correlation history, VirusTotal enrichment, source trust,
sighting counts) to help an analyst decide *faster* which alerts/IOCs are
worth a first look versus probably noise. At real alert volume this is
exactly where analyst time is wasted - triaging obvious noise with the same
rigor as a real hit.

**What to build.** A transparent, evidence-based false-positive *likelihood*
score for both alerts and IOCs, built from signals already present in the
platform (no new external integrations needed for v1) - surfaced to speed up
triage, and **never** silently auto-closing anything without a human
decision and an audit-trail entry. Same "honest, inspectable" posture as the
existing transparent asset-risk model and the README's explicit framing of
the ML layer as "unsupervised outlier ranking for triage, not trained
ground-truth detection" - this is a scoring/explanation aid, not a
black-box classifier making claims the platform can't back up.

**Evidence signals - alerts** (draws on `dashboard_api/detections.py`,
`engine.py`, the `assets` table, `suppressions`):
- the firing rule's existing `fp_rate` - today the *only* signal used
  anywhere; becomes one input among several instead of the whole picture;
- the source asset's criticality/expected role - e.g. a known dev/test box
  vs. a crown-jewel server firing the same rule;
- a *close-but-not-exact* match against `suppressions`/allow-lists (an
  analyst already told the platform "ignore this pattern" for something
  adjacent, e.g. same rule + same subnet but a different exact IP);
- correlation context from the engine's own escalation logic
  (`engine.py::_maybe_escalate_case`) - an isolated, non-correlated single
  event scores differently than one that's part of a multi-alert pivot;
- IOC cross-reference: does the alert's src/dest IP or hash match a CTI
  indicator already marked `known_good`, or is it an RFC1918/internal range
  a rule mis-fired on as "external";
- per-entity FP history (**new** - today only the *rule* remembers, not the
  entity): this exact user/host/rule combination has been marked FP
  repeatedly before.

**Evidence signals - IOCs** (draws on `threat_api/trust_scoring.py`,
`dashboard_api/ioc_lifecycle.py`, `enrichment.py`):
- enrichment provider verdicts already cached in `ioc_enrichments`
  (`enrichment.py`) - zero providers flagging "malicious" against a claimed
  high-severity label is a strong FP signal, multiple independent
  "malicious" verdicts the opposite;
- source trust score (`trust_scoring.py`) - a single low-trust feed
  reporting something no other independent source corroborates;
- multi-source consensus - the same indicator independently reported by 2+
  feeds is materially stronger evidence than one;
- a small static reference list of major cloud/CDN ASN/CIDR ranges
  (AWS/Azure/GCP/Cloudflare) - the classic false-positive pattern for
  IP-reputation feeds flagging shared, high-churn infrastructure;
- sighting history (`ioc_lifecycle.record_sighting`) with **no** correlated
  alert/case ever created from those sightings in this org's own
  environment, despite a high claimed severity - a mismatch between claimed
  and observed impact;
- existing `known_good` overrides used as a reference set: a new IOC
  sharing an ASN/domain/first-seen pattern with a previously-confirmed
  known-good inherits some of that signal.

**Implementation plan (phased, each phase independently shippable):**

1. **Scoring engine - shipped.** `dashboard_api/fp_scoring.py`: pure
   functions `score_alert(conn, alert, org_id) -> {score, band, evidence}` /
   `score_ioc(conn, ioc, org_id) -> {score, band, evidence}`. The evidence
   list is the whole point - every score is explainable, so an analyst can
   see exactly why. Compute-on-read for both (alert evidence is mostly
   static once the alert exists; the IOC store is small enough that a
   background job isn't needed for v1). Six alert signals (rule fp-rate,
   live-joined asset criticality, suppression proximity, time-windowed
   correlation against other unresolved high/critical alerts, direct IOC
   cross-reference, per-entity FP history) and three IOC signals (enrichment
   provider consensus, cloud/CDN CIDR match, sighting/impact mismatch).
   Regression-tested in `dashboard_api/tests/test_fp_scoring.py`, including
   the testing-discipline case: a correlated multi-alert attack + a
   known-bad IOC match stays in the `likely-real` band even with a weak
   FP-leaning signal (low-criticality asset) also present.
2. **API + UI surfacing - shipped.** Rather than embedding the assessment
   in every alert/IOC list or detail read (N+1 query cost on list views),
   it's a dedicated compute-on-demand sub-endpoint - the same pattern as the
   existing `GET /cti/iocs/{id}/enrichment`: `GET /siem/alerts/{id}/fp-assessment`
   and `GET /cti/iocs/{id}/fp-assessment`. Advisory only, never mutates the
   alert/IOC. A "FP Likelihood" button in the Power-mode Alert detail drawer
   and the IOC lifecycle panel fetches on demand and renders the band, score,
   and evidence bullets (signed weight + plain-English detail per signal).
   Verified live in a browser against the real pipeline: a critical-asset
   match plus an isolated (uncorrelated) alert nets `uncertain · 43` exactly
   as the signed weights predict (50 − 15 + 8).
3. **Bulk triage view - shipped.** A new Power-mode-only "FP Triage" SIEM
   tab: `GET /siem/alerts/fp-triage` scores a bounded working set (the most
   recent 300 open alerts - an honest cap, since each row costs several
   `fp_scoring` queries, not one) and returns them filtered by band and
   sorted by score. `POST /siem/alerts/bulk-dismiss` marks a selection
   false-positive/closed in one call (audit-logged per alert, rule fp_rate
   bumped once per rule, not once per alert). The tab renders a
   checkbox-selectable list with a band filter, "select all", and "dismiss
   selected" - the actual time-saving payoff this phase targeted, not just
   a per-alert badge. Verified live in a browser: filtering to `likely-fp`
   isolated the one seeded low-risk alert out of 74 scored, and dismissing
   it removed it from the view.
4. **Opt-in guarded automation** (off by default, an explicit config flag) -
   only above a high threshold (e.g. ≥90) *and* multiple independent
   corroborating signals (never one weak signal alone), auto-**suggest** -
   not auto-execute - bulk dismissal for review, or at most auto-lower
   priority. Every such action is audit-logged and reversible, the same
   human-in-the-loop posture as the SOAR playbook `approval`-step gating
   already in `playbook_engine.py`. This system must never silently close a
   real incident.
5. **Feedback loop** - when an analyst confirms or overrides a suggestion,
   record it as labelled feedback and let it nudge the per-signal weights
   over time (simple, transparent rule-based weight adjustment - not a
   black-box model, keeping the same "explainable, not mysterious" position
   as the rest of the scoring/ML surface in this codebase).

**Testing discipline (non-negotiable before any UI ships).** A wrong
"likely-fp" call that leads an analyst to skip a real incident is the worst
possible failure mode here - worse than the feature not existing at all.
Before shipping: known real-attack fixtures (e.g. a genuine multi-stage
brute-force → lateral-movement chain) must score `likely-real` even when
some superficially-benign-looking signals are also present (e.g. a partial
suppression match) - one weak signal must never outvote several strong
ones. Match the rigor already established for `fp_rate`/suppression logic in
`test_api.py` and the correlation-engine tests.

### Standing sub-end goals (owner, 2026-07-10)

Two additions to the overall vision, to be upheld on **every** future UI change,
not one-off tasks:

- [~] **No dead links.** Every link / nav target / button must resolve to a
      real destination - no `href="#"`, no route that 404s, no anchor to a
      missing id, no handler-less button, no "coming soon" stub. Enforced in
      CI: `frontend/scripts/check-routes.mjs` (runs in `tests.yml`) now gates
      **both** route links (227 checked) **and** in-page anchors (bare
      `href="#"` and anchors to a non-existent `id` both fail the build) - so
      a dead link can't land silently. First pass (2026-07-10): audited the
      whole app clean; the only real fix was the stale
      `github.com/Sami9211/ThreatOrbit-V2` URL (worked only via GitHub's
      rename redirect) → canonical `.../ThreatOrbit` in the footer, CTA,
      quick-start clone command. Ongoing: re-run the guard on every UI change.
- [~] **Smooth animations everywhere.** Foundation shipped (2026-07-10):
      `lib/motion.ts` - one shared easing curve + a 3-step duration scale +
      reusable variants (`fadeInUp`, `fadeIn`, `scaleIn`, `drawerRight`,
      `listContainer`/`listItem`, `pageEnter`), replacing the ad-hoc per-file
      timings that had drifted across 84 framer-motion files; a single
      app-root `<MotionConfig reducedMotion="user">` so **every** framer
      animation now honours the OS reduce-motion setting (the CSS `@media`
      rule only covered CSS animations, not framer's JS-driven ones); and a
      smooth per-route **dashboard page transition** (a keyed fade-up in
      `PageScale`, verified live in both normal and emulated reduce-motion).
      Increment 2 (2026-07-10): SIEM **tab-switch transitions** (the tab
      content is a keyed `fadeInUp` wrapper, so every tab change replays a
      smooth enter), **staggered list enter** on the FP-triage list
      (`listContainer`/`listItem`, keyed on band + item count - children
      mounting into an already-settled parent don't animate, so the remount
      on data arrival is what makes the stagger actually play; caught live,
      not assumed), and `IocLifecyclePanel` migrated onto the shared
      `fadeInUp` variant. All verified in a browser by sampling inline
      opacity during the transitions (wrapper and rows both observed at
      0.000 → 1), zero console errors.
      Increment 3 (2026-07-10): **number count-ups** - a reusable
      `AnimatedNumber` (counts from the previously shown value; honours
      reduced motion explicitly via `useReducedMotion`, since imperative
      `animate()` bypasses MotionConfig) wired into the Overview KPI cards
      (both Power and Normal mode). A one-frame flash of the final value
      before the count started was observed live and fixed (render from the
      previously-committed value, not the target). **Hover/press
      micro-interactions** - a shared `hoverLift` token (gesture transitions
      embedded in the targets so it composes with elements that set their own
      enter transition), applied to the KPI/status cards. Verified live:
      monotonic count-up 0→31 over ~0.8s, reduced-motion jumps instantly,
      zero console errors.
      Increment 4 (2026-07-10): the keyed tab-switch transition extended to
      every remaining tabbed surface - SOAR main tabs (cases/playbooks/
      metrics), the SOAR case-detail tabs (overview/warroom/tasks/evidence),
      Config settings tabs, and Config-Users (users/roles, whose plain fades
      also migrated onto the shared `fadeInUp`). Verified live on all three
      pages by watching inline opacity during a switch (each keyed wrapper
      observed animating), zero console errors.
      Increment 5 (2026-07-10, user-reported): **landing 3D scene fixes** -
      (a) square WebGL point sprites read as "box shapes" riding the orbit
      rings (OrbitalScene dots + hero starfield) → drei `PointMaterial`
      (circular mask); (b) on the no-bloom path the hero's flat unlit
      hex prisms rendered edge-on as solid rectangles → shaded material in
      both modes + directional key light + face-on initial tilt (Float's
      wobble is bounded so they stay face-on); (c) the orbital planet
      saturated into a flat pink disc without bloom → emissive 0.55 + the
      key light restores limb shading; (d) ScrollStory planet rotation
      mapped RAW scroll progress → now derived from the spring-smoothed
      progress (wheel steps no longer snap the rotation); (e) threat-globe
      arcs teleported to their next random curve at opacity 0.12 →
      `0.44·sin(π·t)` envelope fades them fully out before the swap.
      Verified with before/after zoomed screenshots of the rebuilt export.
      Increment 6 (2026-07-11): **loading skeletons + chart draw-ins** -
      shared `Skeleton`/`SkeletonRows` (CSS pulse, frozen by the global
      reduce-motion rule); SIEM alert queue no longer flashes "No alerts
      match" during its first fetch (skeleton rows instead), FP-triage list
      ditto while scoring, analytics trend cards skeleton until first
      answer; sparklines draw in via framer `pathLength`. Shipped together
      with the analytics-tab fabrication fix (live `/siem/analytics/trends`
      endpoint - see CHANGELOG 2026-07-11). Browser-verified with delayed-
      request interception: skeletons appear, resolve to live data, demo
      numbers never leak.
      Increment 7 (2026-07-11): first-load skeletons extended to every
      major list surface - SOAR case board (both modes; Power mode also
      gained a real empty state where it used to render blank), assets
      (table + cards), fleet vulns, both feed columns, dark-web findings.
      Browser-verified on all five pages with request-delay interception.
      Increment 8 (2026-07-11): count-ups (AnimatedNumber) on the SIEM
      header KPI strip, feeds KPI strip, and SOAR header stats - shipped
      together with the header/alert-detail honesty fixes (see CHANGELOG:
      computed KPI sub-annotations, real UEBA identity/host tabs).
      Increment 9 (2026-07-11): playbooks KPI strip live + count-ups +
      skeleton (with the 100× success-rate fix, see CHANGELOG).
      Timing audit (2026-07-11): surveyed every remaining ad-hoc
      `duration:` across dashboard pages/components - all cluster on the
      token scale (0.12-0.25 fast/base, 0.5-0.9 for chart draw-ins); the
      only >1s cases are the two health-gauge ring draws, which are
      deliberate. Converged: tokens govern the shared surfaces, remaining
      per-component values are intentional. The goal stays standing -
      upheld on every future UI change, new motion uses lib/motion tokens.
      **Side-find during increment 4 - FIXED (2026-07-10):** the SOAR
      metrics tab rendered a hardcoded "Cases by Type (Last 30 days)" list
      (Phishing 284, …) as if live - the one fabrication-sweep miss on that
      tab (the neighbouring Automation Metrics and KPI table were already
      live). Now derived from the same live case list the KPI table uses
      (30-day window honoured, top 7 types, honest empty state when no cases
      exist). Verified live: renders the real seeded types (Account
      Compromise 2, …); the fabricated numbers are gone.

### Frontend polish backlog

- [x] **Asset network map** - pan-shake and scroll-zoom bugs fixed earlier;
      the eased look shipped 2026-07-11 as motion polish on the existing SVG
      (staggered node entrance, link draw-in, eased button zoom, SMIL gated
      on reduced motion) rather than an R3F rewrite: the 2D map's working
      interactions (drag, pan, pinch, selection, attack-path trace) are the
      product value, and a 3D scene would have put them at risk for looks.
- [x] **Exported reports** - findings grouped by severity (earlier); shipped
      2026-07-11: per-domain narratives carry an honest prior-window trend
      sentence (never invented when no baseline exists), the printable HTML
      gains a static SVG severity donut beside the KPI tiles, and print
      quality rules (@page margins, no stranded headers, findings/KPIs kept
      whole across page breaks).

---

## CHANGELOG (done)

_Move completed items here with the date so the roadmap stays honest._

- **2026-07-09 · Batched ingest writes: ~5.7x Postgres EPS, verified empirically
  before committing to the approach.** `ingest_lines` issued one
  `conn.execute(INSERT …)` per parsed event - fine on SQLite's in-process file
  access, but every row paid a real client↔server round trip on Postgres (the
  root cause the prior baseline-measurement pass identified). Before writing
  any fix, benchmarked the actual options against a local Postgres instance:
  `executemany` measured ~6x a row-by-row loop (72k vs 11k rows/sec), matching
  a hand-built multi-row `VALUES` INSERT's throughput with far less code - and
  `PgConnection.executemany` already existed in `db_backend.py`, so no new
  plumbing was needed. Collected the batch's rows and switched to one
  `executemany` call; confirmed on the real pipeline via `bench.py`:
  ingest+detect went from ~670 to ~3,800 EPS. Also investigated the
  "detection-claim path" the original roadmap wording named and found it was
  already batched (`event_queue.claim`/`complete`) - corrected that inaccuracy
  rather than leaving it. No correctness change: parse-time per-line error
  isolation happens before rows are ever collected for the insert. Verified:
  full SQLite suite (516 passed); full Postgres suite with a baseline (git
  stash) comparison confirming the only failures are pre-existing full-suite
  connection-pool flakiness already documented earlier this session, not a
  regression. `docs/LOAD_LIMITS.md` updated with the new measured numbers.
- **2026-07-09 · Sigma community-pack bulk import.** `POST
  /siem/rules/import-sigma-pack` imports a whole pasted Sigma rule collection
  (standard `---`-separated multi-document YAML - the format a downloaded
  ruleset like SigmaHQ concatenates as) in one request instead of one rule at
  a time. Each document is parsed and inserted independently - one malformed
  rule doesn't abort the rest of the pack - and the response reports exactly
  which rules landed (id, name, mapping notes) and which failed (index +
  reason). Capped at 500 rules/request. `SigmaImportButton` detects a
  multi-document paste (by splitting and counting non-empty chunks, not just
  checking for `---`, since a single rule commonly starts with a leading
  `---` marker too) and routes to the new endpoint automatically, rendering a
  created/failed summary. Verified: 4 new backend tests, a live browser
  smoke test of the UI flow, full SQLite suite (516 passed), `tsc --noEmit`
  clean.
- **2026-07-08 · Per-theme color-contrast fix: `--ink-500` and the alert-count
  badge now pass WCAG AA everywhere.** Computed exact contrast ratios (not
  estimates) for `--ink-500` against all 4 surface levels each theme actually
  renders text on, not just `--bg` (a first attempt that only checked `--bg`
  missed that a lighter surface can sit closer to a muted foreground's own
  luminance, giving worse contrast than the darkest background) - fixed all 11
  themes with a minimal HSL-lightness bump, hue/saturation preserved, landing
  every one at ≥4.5:1 against its worst case. The alert-count badge
  (`bg-threat` + white text) measured 2.65-3.76:1 on 10 of 11 themes; fixed by
  darkening just the 2 badge instances' text rather than the shared `--threat`
  token (used in 40+ files, too broad to visually re-verify in one pass).
  `--ink-600` (480+ usages) also falls short of AA in some real-text contexts,
  but lightening it enough collapses it visually onto the now-fixed
  `--ink-500` - tracked above as a separate, properly-scoped follow-up
  (per-usage triage: much of it is likely legitimately WCAG-exempt disabled/
  inactive UI text). Verified: exact math for 11 themes × 2 tokens, a 3-theme
  visual screenshot pass, `color-contrast` re-enabled in the axe scan (0
  violations for the fixed tokens), full Playwright suite (23 tests)
  unaffected, `tsc --noEmit` clean.
- **2026-07-08 · CI caught 2 more unlabeled icon buttons (mobile-only render
  paths), plus a connector redirect hardening.** The new a11y spec passed
  locally against desktop-chromium, but the `mobile-safari` CI job (webkit
  isn't installable in the local dev sandbox) caught 2 more real violations
  only reachable via the sidebar's mobile/expanded state: the collapsible
  sub-menu chevron toggle and the mobile "close navigation" `X` button, both
  icon-only with no accessible name. Fixed with descriptive `aria-label`s
  (the chevron also gets `aria-expanded`); verified locally by emulating the
  iPhone 13 device profile in a headless Chromium context (reaches the same
  code path without needing the actual webkit binary). Also hardened
  `connectors._read_capped`: the original request's `params`/`json` are no
  longer resent on a redirect hop (the `Location` is already the resolved
  target - replaying stale query params on top of it, e.g. NVD's
  `resultsPerPage`, could produce a malformed request to the redirect
  target). New regression test; full SQLite suite: 512 passed.
- **2026-07-08 · Automated accessibility regression testing, and 4 real a11y
  bugs it caught on its first run.** Added `@axe-core/playwright` +
  `e2e/a11y.spec.ts`, scanning login/overview/SIEM/SOAR/Config with axe-core's
  WCAG 2.0/2.1 A+AA ruleset as a permanent CI gate rather than a one-off manual
  pass. It immediately found, and this fixed: a sitewide "Skip to content" link
  whose `#main-content` target didn't exist on the login page or anywhere in
  the dashboard layout (only marketing pages had it) - keyboard/screen-reader
  users invoking it landed nowhere; 6 Config-page form inputs with a visible
  `<label>` never programmatically associated with its `<input>` (fixed once at
  the shared `Field` component via `useId()` + `htmlFor`/`id`, covering every
  instance); two unlabeled `<nav>` landmarks on the Config page indistinguishable
  from each other (now `aria-label`ed). `color-contrast` is disabled in the new
  spec deliberately (not silently) - `--ink-500`/`--threat` measure ~3:1 against
  their default-theme backgrounds vs. the 4.5:1 AA threshold, but both are
  per-theme tokens (11 themes), so the real fix needs a visually-verified
  lightness pass, not a token edit landed from a headless run; tracked above as
  a concrete remaining item. Full existing Playwright suite (23 tests) still
  green; `tsc --noEmit` clean.
- **2026-07-08 · Measured (not assumed) Postgres EPS baseline; corrected an
  unverified claim in `LOAD_LIMITS.md`.** `bench.py` forced a fresh SQLite temp
  DB unconditionally, so there was never actually a way to run it against
  Postgres - the "documented Postgres EPS baseline" Tier-2 item stayed
  unmeasured. Fixed by having it respect `DASHBOARD_DB_BACKEND=postgres` +
  `DATABASE_URL` when already set (unchanged default: SQLite temp file), then
  measured against a disposable local Postgres 16 database. Result: Postgres
  is markedly **slower** than SQLite for the current pipeline (~670 EPS
  ingest+detect vs. ~10,800; ~450 vs. ~7,400 single-worker drain), and 4
  workers don't beat 1 on Postgres either - directly contradicting
  `LOAD_LIMITS.md`'s prior (unverified) claim that switching to Postgres alone
  would go "materially higher." Root cause, confirmed by reading the code, not
  guessed: `ingest_lines` and the detection worker each issue one
  `conn.execute(...)` round-trip per event row, no `executemany`/`COPY`
  batching - free on SQLite's in-process file access, but dominant over any
  network connection, even loopback. `docs/LOAD_LIMITS.md` now carries the
  measured Postgres table and the corrected explanation; the real fix (batch
  the hot ingest/detection-claim writes) is scoped as a new Tier-2 roadmap item
  above rather than attempted inside this measurement pass. `test_bench.py`
  (which strips backend env vars so it always benches SQLite) still passes
  unchanged.
- **2026-07-08 · Connectors: closed an SSRF-via-redirect gap.**
  `connectors._read_capped` fetched custom feed URLs with
  `httpx.stream(..., follow_redirects=True)`, which chases a `Location` header
  entirely inside httpx - invisible to `net_guard.validate_external_url`. A
  feed URL that validates fine right now (a public host) could 302 the
  dashboard straight at cloud instance metadata (`169.254.169.254`) or an
  internal/RFC1918 address, and the server would fetch that instead,
  completely unguarded - a real SSRF primitive gated only on
  `connectors.manage`. `webhooks.py` already closed the analogous gap for
  webhook/Slack targets via `net_guard.safe_post` (pin + block redirects); feed
  URLs legitimately need redirects (http→https, CDN), so the fix here follows
  each hop manually and re-validates the `Location` before following it,
  capped at 5 redirects. New regression tests in `test_connector_resilience.py`
  cover the safe-redirect, blocked-internal-target, and too-many-redirects
  cases. Full SQLite suite: 511 passed.
- **2026-07-08 · Simple vs Power organization mode (nav curation, not RBAC).**
  A small org drowning in a full SOC platform churns; a mature team hobbled by
  a stripped-down UI churns too - so the org itself now picks its posture
  instead of shipping two products. `dashboard_api/modes.py` defines a
  24-feature-area catalogue (mirroring the Sidebar's nav sections) and a
  10-area `simple` subset (Overview, SOC console, SIEM alerts/sources, Cases,
  core CTI, Feeds, Assets, Reports, Config); `GET`/`PUT /config/mode`
  (`config.manage`-gated for writes, open read for any authenticated user so
  the frontend can draw its own nav) persist the choice per org via the same
  `settings` table `key:{org}` convention as per-tenant quotas. Explicitly a
  **UI-surfacing preference, not a security boundary**: every endpoint keeps
  enforcing its real RBAC regardless of mode. The Sidebar now filters its nav
  by the org's feature list (`useOrgFeatures`), and the pre-existing
  client-side Normal/Power "Experience Mode" toggle (Config → General) is now
  the same control - flipping it persists to the backend and re-curates the
  nav, not just card density. Caught and fixed in the same pass: (1) a
  volume-dependent miss in `auto_trigger_playbooks` (same `LIMIT`-on-`ORDER BY
  ts DESC` bug class as the correlation engine, fixed by bounding the scan on
  the time window instead of a row cap); (2) one bad S3 object aborting an
  entire `s3_pull.poll()` batch and stalling the checkpoint, now isolated
  per-object with the checkpoint advancing up to the last good key; (3) an E2E
  regression where treating every `GET /config/mode` response as authoritative
  would have silently flipped every existing install's working Normal-mode
  default to the backend's Power fallback - fixed via a `has_explicit_mode`
  flag so the backend only overrides the frontend's pre-existing local default
  once an org has actually chosen. Full test coverage: `test_modes.py`,
  extended `test_playbook_engine.py` (auto-trigger volume + idempotency),
  extended `test_s3_pull.py` (failing-object isolation). See `CHANGELOG.md`
  for the dated per-fix detail.
- **2026-06-22 · Real Postgres query layer + connection pooling (audit A3/A4).**
  Replaced the brittle regex SQL-dialect rewriter with a real parser: `to_postgres`
  parses each statement with **sqlglot** and applies AST transforms for the SQLite
  idioms sqlglot doesn't map on its own - `INTEGER`→`BIGINT` (SQLite ints are
  64-bit), `INSERT OR REPLACE`→`INSERT … ON CONFLICT` (DO UPDATE for multi-col,
  DO NOTHING for PK-only), `datetime('now')`→`now()` - then renders Postgres. The
  regex rewriter is kept as a best-effort fallback for any statement sqlglot can't
  parse (or when sqlglot isn't installed). Connections now come from a
  **psycopg_pool** pool instead of opening/closing per call. The Postgres extras
  (`psycopg[binary]`, `psycopg-pool`, `sqlglot`) live in
  `dashboard_api/requirements-postgres.txt`. Validated end-to-end against a live
  Postgres 16 - full dashboard suite **386 passed / 2 SQLite-only skipped** - and
  in CI's backend-postgres job; the SQLite default is unchanged (**388 passed**).
- **2026-06-22 · De-mocked dashboard widgets + CI gate (audit findings F-1…F-4).**
  Wired the widgets that rendered hardcoded demo data to their live endpoints, or
  gave them honest empty states / "sample" badges:
  - **Overview Trending CVEs** → `/assets/vuln-findings`, sorted KEV → exploit →
    CVSS, with an empty state (was a hardcoded 2024 CVE list).
  - **CTI Sector Targeting** → derived from the tracked actors' `sectors`;
    **Threat Briefs** (Normal mode) → derived from the live actors (real
    description / TTPs / sectors / IOC counts), replacing the hardcoded lists.
  - **SOC Metrics** → new **`GET /soar/analysts`** (per-analyst case workload from
    `cases.owner`) backs the analyst throughput + leaderboard; playbook
    effectiveness → `/soar/playbooks`; the automation donut + disposition summary
    are computed from live SOAR/SIEM metrics. The no-op **time-range selector was
    removed**. The two genuinely-unbacked decorative charts (7-day alert-volume
    shape, 4-way disposition split) are explicitly badged **"sample"**.
  - **SIEM** in-page Threat-Hunt tab now links to the real `/siem/hunt` workspace
    (POST `/siem/search`) instead of a fabricated `HUNT_RESULTS` table.
  - **Scanner** Recent Scans is live from `/scans` with an empty state (dropped
    the bundled `acme-corp` history).
  - **CI**: `pip-audit --strict` now gates all three services (only the triaged
    starlette advisory PYSEC-2026-161 is ignored, FastAPI services only).
  Tests: `test_soar_analysts.py`; tsc + `check:routes` (227 links) + `next build`
  green; dashboard_api suite green.
- **2026-06-22 · Roadmap audit + prune.** Ran a full audit pass: all three
  backend suites green on a clean install (**413 tests** - log_api 20,
  threat_api 8, dashboard_api 385), re-verified `audit_fixes.md` against the
  current tree, and removed every finished `[x]` entry from the active roadmap
  (Phases 0-5 + the closed Tier-1 hardening) since they are recorded here. The
  roadmap above now carries only remaining work plus the new findings surfaced
  by this pass - chiefly that several dashboard widgets (Overview Trending CVEs,
  CTI sector/briefs, SOC-metrics analyst & playbook panels, the SIEM in-page
  Threat-Hunt tab, the scanner's demo history) still render hardcoded sample
  data rather than their live endpoints, the SOC-metrics time-range selector is
  a no-op, and the CI `pip-audit` gate is `--strict` only for `dashboard_api`.
- **2026-06-18 · SOAR metrics: live ATT&CK coverage (de-mocked).** The SOAR
  metrics page hardcoded a MITRE ATT&CK coverage grid (fabricated `82/74/61…`
  percentages) - a violation of the "every number traces to the API" principle.
  It now derives coverage **live** from `/siem/attack-coverage` (the same real
  endpoint the SOC console + SIEM navigator use): per tactic, the % of techniques
  that have an enabled detection rule, labelled with the ATT&CK tactic id, with
  the summary stats (avg / fully-covered / gaps) computed from the live data too.
  The page already fetched its other metrics live, so this just adds one more
  fetch + derivation and removes the mock constant. Verified with `tsc`, the route
  gate, and a production `npm run build`. (The rest of this metrics page still has
  some illustrative figures - analyst leaderboard, playbook effectiveness - left
  as a separate frontend-polish item.)
- **2026-06-18 · Per-device sessions for SSO/SAML logins.** The interactive
  login + self-service register created a listable/revocable per-device session
  row (JWT `sid`), but the OIDC callback and SAML ACS minted a `sid`-less token -
  so an SSO/SAML device couldn't be seen in "your sessions" or signed out
  individually (only the coarse token-epoch applied). Both now `record_session`
  (with best-effort device metadata from the request) and mint the token with the
  `sid`, closing the gap noted under Session management. Tests in
  `test_sso_saml_sessions.py` drive the callback/ACS with mocked providers and
  assert the token carries a `sid` backed by a real `sessions` row; the existing
  SSO/SAML/session suites stay green. This closes the Session-management section
  for GA. (Also corrected three stale roadmap notes whose work shipped earlier
  this session: break-glass + per-workspace RBAC, and the retention S3 writer.)
- **2026-06-18 · Multi-AZ Postgres HA guidance.** Closes the documentation half
  of the HA/DR item's Postgres gap. `docs/POSTGRES_HA.md` covers turning on the
  Postgres backend behind a highly-available endpoint, managed (RDS/Aurora
  Multi-AZ, Cloud SQL HA, Azure zone-redundant) vs self-managed (Patroni/repmgr)
  topologies, and - grounded in the actual architecture - **why failover is clean
  here**: stateless API replicas, per-request connections (no stale pool to
  drain → automatic reconnect through the HA endpoint), and the DB-backed leader
  lease that survives promotion so the background singletons stay single-run.
  Plus PgBouncer notes, RPO≈0 with a synchronous standby, RTO, and rolling
  upgrades against the schema-version gate. Linked from the README. (The only
  HA/DR piece left is an actual *tested* failover drill, which needs live
  multi-AZ infrastructure to run.)
- **2026-06-18 · UI dataset ceilings (list-endpoint limit caps).** An audit found
  ~12 list endpoints (overview rollups, jobs, audit-log, SOAR run history,
  discovered assets, service IOC pulls) took a **plain `limit: int = N` with no
  upper bound** - a client could request `?limit=10000000` and force an unbounded
  result set (memory/DoS). Each now uses `Query(default, le=cap)` (the same
  pattern the 15 paginated endpoints already used), so an over-cap value is
  rejected with 422 and the cap is the hard ceiling. Published the per-family
  ceilings in `docs/LOAD_LIMITS.md` (alongside the client-side 150-row windowing).
  Tests in `test_dataset_ceilings.py` (5 endpoints: over-cap → 422, cap → 200).
  Full suite green. (Only the live-Postgres EPS baseline remains on the
  load-limits item - it needs a real PG host to measure.)
- **2026-06-18 · Agentless S3 log pull (closes Parser & source breadth).** Logs
  already landing in object storage now flow into the SIEM with no agent or
  forwarder. `dashboard_api/s3_pull.py` tails an S3 (or S3-compatible) bucket
  prefix on an interval: `ListObjectsV2` after a stored checkpoint key, `GET` the
  new objects, split into lines, and `ingest_lines(... org_id=_ORG)` (per-tenant
  pull). The checkpoint advances to the last key, so a restart never re-ingests
  or skips. Stdlib-only **SigV4 GET signing with the canonical query string**
  (reusing `archive._signing_key`), cross-verified against botocore offline and
  then removed (tests stay stdlib-only). Driven by the leader-only connector
  scheduler (no double-ingest), honours `DASHBOARD_S3_PULL_SECONDS`, and surfaces
  on `GET /siem/log-listeners` (`s3Pull`). `config.py` + `.env.example` document
  the knobs. Tests in `test_s3_pull.py` (3): signed-GET shape, list→fetch→ingest
  →checkpoint with a stubbed transport, second-poll no-op, and status. With this,
  **Parser & source breadth is fully complete**. Full suite green.
- **2026-06-18 · CEF + LEEF envelope decoding.** The two ubiquitous security-
  appliance log envelopes now decode natively (no longer mis-parsed as generic
  key=value). `ingest.py` gained `_parse_cef` (ArcSight
  `CEF:Ver|Vendor|Product|Ver|SigID|Name|Severity|ext`, escape-aware header split
  + extension parser) and `_parse_leef` (QRadar `LEEF:` 1.0 tab / 2.0
  declared-delimiter), dispatched in `parse_line` **before** the kv path. A shared
  `_apply_envelope` classifies by the human Name/EventID via the content
  signatures (so an auth-failure envelope still feeds the brute-force rule),
  applies the device severity (numeric 0-10 or word), and maps the extension
  fields (`src`/`dst`/`dpt`/`suser`/`shost`/`act` for CEF; `src`/`dst`/`dstPort`/
  `usrName`/`sev` for LEEF) onto the native event. `cef`/`leef` added to the
  ingest format whitelist (auto-detected by prefix). Tests in
  `test_ingest_sources.py` (3): CEF auth/generic/malware mapping, LEEF 1.0 + 2.0,
  and an end-to-end CEF ingest. Matrix + docstring updated. Full suite green.
- **2026-06-18 · Org-scoped API keys (per-tenant collectors).** Closes the last
  optional multi-tenancy piece: a non-interactive collector now ingests into the
  right workspace. Added `api_keys.org_id` (migration; `SCHEMA_VERSION` 1→2, which
  exercises the new boot gate) - `auth._principal_from_api_key` returns the key's
  org, so a service principal acts in that workspace and `ingest_lines` stamps its
  events accordingly. `POST /config/api-keys` takes an optional `orgId` (defaults
  to the creator's workspace; a named workspace must exist), and the frontend
  client/type carry it. Tests in `test_api_key_org.py` (3): default-to-creator,
  unknown-workspace 404, and an end-to-end org-scoped-key ingest landing in its
  tenant. Full suite green. With this, **all code pieces for multi-tenant GA are
  in** - only the default-flip + an end-to-end validation pass remain.
- **2026-06-18 · Multi-tenancy: per-org ingest context.** The last data-path
  isolation gap. Ingested events now carry the **ingesting principal's
  workspace** (`ingest_lines(... org_id=…)` stamps the `events.org_id`; both
  `/siem/ingest` and `/siem/ingest/raw` pass `tenancy.org_of(user)`, which honours
  the X-Org-Id acting-org), and the detection writers propagate it: `run_detection`
  stamps each alert with **its triggering event's** `org_id`, and the TI-match path
  (`match_threat_intel` → `alert_from_intel` → `_insert_alert`) does the same. So
  under multi-tenancy a tenant only sees alerts from its own logs - including
  mixed-org batches drained by the multi-worker pool, since the org travels with
  each event. The *synthetic* background engine (`process_tick`) and the
  deployment log listeners stay in the default workspace **by design** (demo /
  deployment infrastructure, not a tenant's real data). Single-tenant installs are
  byte-for-byte unchanged (everything resolves to `org-default`, matching the
  column default). Tests in `test_per_org_ingest.py` (3): end-to-end event + TI
  alert land in the ingesting org, the alert writer stamps/defaults org, and the
  single-tenant no-op; the detection-pool/queue/stream suites stay green. With
  this, multi-tenancy's data-path isolation is complete - only an end-to-end
  validation pass (and optional org-scoped API keys) remain before flipping
  `DASHBOARD_MULTI_TENANT` on by default.
- **2026-06-18 · Data residency artifact + compliance control.** Closed the
  data-residency gap in the vendor-compliance posture (asked for in enterprise
  security questionnaires). `docs/DATA_RESIDENCY.md` enumerates **every** point
  where data could leave the deployment - threat-intel connectors, IOC
  enrichment, the AI assistant, Stripe, the audit sink, cold-storage archive,
  webhooks/Slack, SMTP, the SSO IdP, TAXII/OpenCTI - notes that each is opt-in
  and SSRF-guarded, and gives a strict in-region / air-gapped checklist (the
  self-hosted store is the residency boundary). Added it as control
  `DR-RESIDENCY` (SOC 2 C1.1 / ISO A.5.23) in `compliance.py` + `docs/COMPLIANCE.md`
  (the compliance test guards the matrix's shape/honesty - still green). RPO/RTO
  targets were already documented in `docs/BACKUP_RESTORE.md`; the *tested*
  failover remains infra-gated. Linked from the README docs index.
- **2026-06-18 · Multi-tenancy: per-tenant quotas + retention.** Each workspace
  can now be capped and aged independently. `tenancy.py` stores per-org limits as
  org-scoped settings (`set_org_limits`/`quota_usage`/`enforce_quota`/
  `org_retention_days`), managed via `GET`/`PUT /orgs/{id}/limits` (config.manage,
  with usage). **Quotas**: `enforce_quota` raises HTTP 402 at create time when a
  workspace is at/over its `users` or `assets` cap - wired into user creation
  (per-tenant seats, on top of the global license seat check) and asset creation;
  a value of 0 clears a limit. **Retention**: the purge job now honours each
  workspace's `org_retention_days` override under multi-tenancy (refactored to a
  per-(table, org) `_purge_scope`, archival-before-delete preserved per scope).
  All gated by `enforced()`, so single-tenant installs are byte-for-byte
  unchanged (proven: the existing retention tests still pass). Tests in
  `test_tenant_quotas.py` (6): set/get limits, user + asset 402 enforcement,
  per-tenant retention window vs the global default, and the single-tenant no-op.
  Regenerated the `/v1` contract surface. Full suite green.
- **2026-06-18 · Multi-tenancy: tenant lifecycle tooling (suspend/export/delete).**
  Advances *Finish multi-tenancy for GA* with the MSSP offboarding controls.
  `tenancy.py` gained `is_org_active`, `export_org`, and `purge_org`. **Suspend**:
  a workspace with `status=suspended` is blocked from auth - enforced in both
  `login` and `current_user` (gated by `enforced()`, so single-tenant is a no-op),
  and the default workspace is protected (can't be suspended or deleted, or the
  platform admin would lock themselves out). **Export**: `GET /orgs/{id}/export`
  (config.manage) dumps every row for the org across the tenant tables + its users
  with secrets scrubbed - data portability for offboarding. **Delete**:
  `DELETE /orgs/{id}` (config.manage) hard-purges every row across all tenant
  tables (+ users, per-workspace grants, break-glass) and the org itself, guarded
  by a **suspend-first** two-step (409 otherwise) so it can't be one-click data
  loss; every step audited. Tests in `test_tenant_lifecycle.py` (5): suspend
  blocks login + live tokens + resume, default-org protection (suspend & delete),
  export-without-secrets, delete-requires-suspend-then-purges. Regenerated the
  `/v1` contract surface. Still open for GA: per-org engine/ingest context and
  per-tenant quotas. Full suite green.
- **2026-06-18 · HA/DR: migration-gating on upgrade (rollback safety).** Added a
  `SCHEMA_VERSION` marker (`dashboard_api/db.py`) recorded in the DB's `settings`.
  On boot `init_db` runs `_schema_version_gate` BEFORE touching data: it **adopts**
  a fresh/pre-versioning DB, **bumps** the marker after a normal additive upgrade,
  and **raises `SchemaVersionError` (refuses to start)** when the DB is newer than
  the code - an older binary rolled back onto a newer schema - unless
  `DASHBOARD_ALLOW_SCHEMA_DOWNGRADE=1`. Surfaced for ops at `GET /ready`
  (`schema.{code,db}`) and `python -m dashboard_api.ops schema-version` (rc=1 if
  the DB is newer). Fixed a latent bug uncovered en route: `seed(force=True)`
  wiped the whole `settings` table (including the version marker) after `init_db`
  set it, so `_seed_settings` now re-stamps `schema_version` (safe: the gate has
  already rejected any too-new DB by then). Documented the contract + runbook in
  `docs/OPERATIONS.md`. Tests in `test_schema_gate.py` (6): fresh adopt, downgrade
  gated, override allows, upgrade bumps, `/ready` + CLI surfaces. Full suite green.
- **2026-06-18 · Scale-grade RBAC: per-workspace role assignment.** Completes the
  Scale-grade RBAC item. A `user_org_roles` table + new `/orgs/{id}/members`
  endpoints (`PUT`/`GET`/`DELETE`, gated by `users.manage`) let an operator grant
  a user a **distinct role within another workspace** (MSSP/SaaS), with the same
  no-privilege-escalation guard as custom roles (you can't grant a role beyond
  your own). `permissions.workspace_role(user, org)` resolves the effective role
  (home → base role; elsewhere → the grant, or None = no access). `current_user`
  now reads an optional `X-Org-Id` header: under multi-tenancy, a member acting in
  another workspace takes their **granted role AND data scope** there (resolved
  once, so `org_of`/scoping/stamping and `require_perm` all follow consistently);
  asking for a workspace you're not in is a 403. Single-tenant installs ignore the
  header entirely - byte-for-byte unchanged. Tests in `test_workspace_roles.py`
  (7): grant/list/resolve, acting-org role+scope switch, non-member 403,
  require_perm honouring the acting role, no-priv-escalation, revoke, and the
  single-tenant no-op. Note: the engine/ingest background context is still
  home-scoped (tracked under *Finish multi-tenancy for GA*). Full suite green.
- **2026-06-18 · Scale-grade RBAC: break-glass / audit-everything mode.** Added
  time-boxed **emergency RBAC elevation** for the case where the normal approver
  is unavailable. New `dashboard_api/break_glass.py` + a `break_glass` table:
  a user whose **base** role holds the new `break_glass.use` capability (admin +
  manager by default - analyst/viewer can never self-elevate) calls
  `POST /auth/break-glass` with a reason; while the session is live, `require_perm`
  grants any capability the base role lacks **and audits each such elevated use
  individually** (`rbac.break_glass`, target = the capability), so the trail shows
  exactly what the emergency access did. Activation/deactivation are audited and
  raise a **critical notification**; sessions auto-expire
  (`DASHBOARD_BREAK_GLASS_MAX_MINUTES`, default cap 240) and can be ended early
  (`POST /auth/break-glass/deactivate`); `GET /auth/break-glass` shows your state,
  `GET /auth/break-glass/active` (users.manage) lists all live sessions, and
  `/auth/permissions` reflects the elevation so the UI unlocks. The default
  install is byte-for-byte unaffected (no session = ordinary RBAC); the change to
  `require_perm` only touches the would-be-denial path. Tests in
  `test_break_glass.py` (5): no self-elevation for viewer, manager gains
  license.manage only while active + per-use audit, expiry, endpoint lifecycle,
  admin session list. Full suite green.
- **2026-06-18 · Retention cold-storage: object-storage (S3) writer.** Closed the
  last open piece of Retention tiering - cold storage no longer has to be a local
  disk. `dashboard_api/archive.py` grew a second, independently-enableable sink:
  alongside the local gzip-NDJSON dir, setting `DASHBOARD_ARCHIVE_S3_BUCKET`
  (+ `_PREFIX`/`_REGION`/`_ENDPOINT`) writes each purged batch as an **immutable
  gzip object** via an **AWS SigV4-signed `PUT`** - stdlib-only (hmac/hashlib),
  no boto3 - that works against S3 and S3-compatible stores (MinIO, Cloudflare R2,
  Backblaze B2 via the path-style `_ENDPOINT`). Credentials come from the standard
  AWS environment. Both sinks gate the purge: any sink failure raises `OSError`,
  so rows are never deleted unarchived (the existing retention guard, unchanged).
  The retention response now reports `archiveTargets` ({dir?, s3?}). The SigV4
  signer is factored into a testable `_sign()`; `test_retention_archive.py` adds a
  **known-answer test against AWS's published S3 GET-Object example**
  (cross-verified against botocore, then botocore removed so tests stay
  stdlib-only), plus signed-PUT structure, path-style endpoint, dual-sink, and
  fail-closed-on-error cases. Full suite green.
- **2026-06-18 · API stability contract: versioned `/v1` + deprecation policy +
  per-release OpenAPI.** Closed the last open piece of the API-stability item.
  Added `dashboard_api/api_versioning.py`: a pure-ASGI `ApiVersionMiddleware`
  (added outermost) rewrites a leading `/v1` off the request path before routing,
  so **every** endpoint is served under `/v1` as an exact alias of the canonical
  path (`/v1/siem/alerts` == `/siem/alerts`) with one route table and no
  duplicated OpenAPI operations; `/v1` responses carry `X-API-Version: v1`. The
  bundled frontend keeps using the unversioned (legacy-alias) paths unchanged.
  Wrote the **deprecation policy** (`docs/API_VERSIONING.md`): URL-versioning,
  the additive-only stability guarantee within a major, RFC 8594 `Deprecation`/
  `Sunset` signalling via a new tested `mark_deprecated()` helper, and a ≥6-month
  grace process. **Per-release OpenAPI**: `scripts/openapi_snapshot.py` emits the
  stable path surface (`docs/api/v1-paths.json`, 220 paths) and, with `--full`,
  the complete schema (FastAPI also serves `/openapi.json` + `/docs` live).
  Enforced by `test_api_contract.py` (7 tests: `/v1` alias parity inc. login +
  meta, version header present/absent, unknown-path 404, `mark_deprecated`
  headers, and **a contract gate that fails if a documented path is removed
  without a version bump**). No behaviour change to existing clients.
- **2026-06-18 · Roadmap honesty pass (stale `[~]` → `[x]`).** Audited the
  in-progress markers against the actual code/CHANGELOG and corrected six whose
  stated "Remaining:" work had already shipped: **Billing** (Stripe self-serve
  done - `billing.py`/`routers/billing.py`/`test_billing.py`), **Postgres option**
  (validated against live PG 16 + a CI service-container job), **E2E suite** and
  **Mobile-responsive** (34 Playwright tests green across desktop-chromium +
  mobile-safari in CI), **SSO** (OIDC + SAML 2.0 + SCIM 2.0 all shipped, incl.
  deprovisioning), and **Detection content library** (content-update channel via
  `POST /siem/content/apply`). No code change - roadmap accuracy only; genuine
  follow-ups were re-noted on each item.
- **2026-06-18 · Parser & source breadth: EDR + M365 + firewalls + TLS syslog.**
  The ingest pipeline recognised Windows/Sysmon and the three clouds; this closes
  the rest of the enterprise source list. New `_apply_*` mappers in
  `dashboard_api/ingest.py` normalise five more vendor shapes onto the native
  event vocabulary so the same detection rules fire on them: **CrowdStrike
  Falcon** (Streaming-API `metadata.eventType` / `event_simpleName`, and
  DetectionSummaryEvent → `malware_detected` carrying its `TechniqueId`/
  `SeverityName`), **SentinelOne** (nested `threatInfo`/`agentRealtimeInfo` →
  `malware_detected`, ransomware → T1486), **Microsoft 365 Defender** Advanced
  Hunting (`ActionType`: LogonFailed → `failed_login`, AntivirusDetection →
  `malware_detected`, ConnectionSuccess → `network_connect`), the **Office 365 /
  M365 unified audit log** (`Operation`: UserLoginFailed → `failed_login`,
  New-InboxRule → `mailbox_rule`, Consent-to-application → `app_consent`,
  Disable-Strong-Auth → `mfa_disabled`), and **firewalls** - **Palo Alto PAN-OS**
  (TRAFFIC/THREAT, subtype → `ips_alert`/`malware_detected`/`firewall_deny`) and
  **Fortinet FortiGate** (JSON *and* its native key=value syslog, with quoted-value
  support added to `_parse_kv`). Discriminators are tight (each requires a
  vendor-distinctive companion field) so arbitrary JSON still falls through to the
  ECS/heuristic path - proven by "not hijacked" cases. Auth failures from **every**
  source now land as `failed_login`, so the brute-force/spray detection fires
  uniformly. **TLS syslog (RFC 5425)** also lands: `log_listeners.deframe_syslog`
  is a unit-tested octet-counting + newline deframer (carries frames that span TCP
  segments), behind an env-gated TLS listener (`DASHBOARD_SYSLOG_TLS_PORT` +
  cert/key, optional `…_TLS_CA` for mTLS); `/siem/log-listeners` reports its state.
  Published the **supported-sources matrix** (`docs/SUPPORTED_SOURCES.md`) and
  wired README + the frontend `LogListenerStatus` type. 22 new assertions in
  `test_ingest_sources.py` (per-vendor mappings, anti-hijack guards, an
  ingest-endpoint round-trip, and deframer framing); full suite green. Still
  ahead: agentless S3/blob pull and CEF/LEEF decoding.
- **2026-06-18 · Background-service HA (leader election).** The engine tick,
  connector/report scheduler and file-watcher were single-instance - two app
  replicas would double-generate telemetry, double-import connectors,
  double-deliver scheduled reports and double-ingest a shared watch dir. Added
  `dashboard_api/leader.py`, a DB-backed lease (`leader_lease` table, integer
  epoch expiry): a node takes/renews a named lease via one atomic conditional
  `UPDATE` (`WHERE holder=self OR expires_at<now`), which is single-winner on
  both SQLite (global write serialisation) and Postgres (row lock). The engine
  loop drives election (acquire/renew each 20s tick); the scheduler and
  file-watcher check `is_leader()` and idle on followers. Failover happens within
  one TTL (default 60s, `DASHBOARD_LEASE_TTL`); graceful `release()` hands off
  immediately; `DASHBOARD_LEADER_ELECTION=0` opts out (single-node by
  construction). New `GET /config/leader` shows the holder. The syslog UDP
  listener remains single-writer by deployment (bind one node/VIP). Tests in
  `test_leader.py` (single-holder contention, renew, post-expiry takeover,
  release, endpoint) pass on **both** backends.
- **2026-06-18 · Collector ecosystem + API-key authentication.** Two gaps
  closed together. **(1) API-key auth** - issued keys (`to_sk_live_…` etc.) were
  minted and stored but nothing actually *accepted* them on requests, so no
  non-interactive client could authenticate. `auth.current_user` now resolves a
  presented API key (Bearer **or** `X-API-Key`) into a synthetic service
  principal, verified against `api_keys` (sha256, revocation-checked,
  last_used-stamped); scope maps onto the role matrix (read→viewer,
  write→analyst, admin→admin) so every `require_perm` gate works unchanged.
  Tests in `test_api_key_auth.py` (both headers, scope→permission, revocation,
  forged-key rejection). **(2) Collector ecosystem** - a single-file stdlib
  agent `collector/threatorbit_collector.py` that tails files, **checkpoints
  read offsets** (atomic state file → restart never re-ships or drops a line),
  handles rotation/truncation, batches, and honours ingest backpressure (429 +
  Retry-After); plus **certified configs** for Fluent Bit, Vector, and
  Filebeat→Logstash. To accept what those agents emit natively, added
  **`POST /siem/ingest/raw`** (plain text / NDJSON / JSON array → lines), sharing
  one `_ingest_core` with `/siem/ingest` (validation, backpressure, audit).
  systemd unit + env template + README (install, scoped-key enrolment, mTLS).
  Tests: `collector/tests/test_collector.py` (tail/checkpoint/rotation/at-least-
  once, wired into CI) and `test_ingest_raw.py` (all vendor shapes + auth).
- **2026-06-18 · SOC Console (analyst dashboard).** Split the two audiences:
  Overview stays the executive at-a-glance; a new **SOC Console**
  (`/dashboard/soc`, top-level nav under Overview) is the analyst's live
  operational surface. New backend endpoint **`GET /siem/triage`** returns the
  open-alert queue rolled up by severity, the unassigned load, the status
  breakdown, the oldest-open age, and **SLA breaches classified ack-vs-resolve**
  - ages computed from real alert timestamps, thresholds admin-tunable via
  `sla_ack_<sev>_mins` / `sla_resolve_<sev>_mins` settings (sane per-severity
  defaults). The page composes that with the existing `/siem/kpis` (MTTA/MTTR/
  EPS), `/config/engine` queue backpressure (depth/in-flight/lag, load-shedding
  bar), `/siem/attack-coverage` (coverage ring), and `/siem/log-listeners`, on a
  20s live refresh. Worst-first breach rows deep-link into the SIEM queue.
  Tests: `test_soc_triage.py` (open rollup, ack/resolve classification,
  unassigned count, threshold override). No synthesised numbers.
- **2026-06-18 · Dead-link gate + actor-profile crash fix.** Two frontend
  roadmap items closed. (1) **Dead hyperlinks**: swept every internal
  `href`/`href:`/`link:`/`router.push` target in `app|components|lib`; all 222
  resolve to a real route (the only leading-slash literals that *aren't* routes
  are the `path:` keys documenting backend REST endpoints on the docs page,
  which are correctly excluded). Added `frontend/scripts/check-routes.mjs` - it
  discovers the route set by walking the App Router tree (handling route groups
  and `@slots`), validates template-literal links on their literal prefix, and
  fails the build on any link to a non-existent route; wired into the frontend
  CI job (`npm run check:routes`) so dead links can't regress. (2) **Actor
  profiles "dead"**: the live-actor mapping in `cti/actors/page.tsx` guarded
  `campaigns`/`malware`/`motivations` but not `aliases`/`sectors`/`ttps`, so a
  live actor missing any of those arrays crashed the detail panel's `.map()`
  render. Now all three are `Array.isArray(…) ? … : []` guarded.

- **2026-06-17 · Per-table retention windows.** Retention used one global
  `data_retention_days` for every table; now each table reads its own
  `retention_days_<table>` setting (falling back to the global default), so noisy
  raw `events` can be kept shorter than `alerts`. The enforce response reports the
  per-table windows; archival-before-purge still applies per table.
  `test_retention_archive.py` proves a 20-day-old event is purged under a 7-day
  window while a same-age alert survives a 90-day one.

- **2026-06-17 · External code-review remediation (audit_fixes.md).** Worked
  through a deep third-party review across ~17 commits: persisted log_api results
  + per-job reports (no in-memory leak / shared file), tenant-scoped webhooks
  (cross-tenant leak), log_api constant-time keys + safe CORS + no exception-text
  leakage, CSP/HSTS, non-root + healthcheck + gunicorn for threat_api/log_api, MFA
  TOTP-replay rejection, OIDC exact-kid match, ingress byte cap + report escaping,
  and the **ML detector** fixed (no by-construction false positives on benign
  logs; MITRE technique derived from the real signal, not hardcoded T1595). Added
  the first real unit tests to threat_api + log_api (1→8 each: parsers, detectors,
  normalisation, correlation, trust-scoring, STIX). Honest positioning (README
  "Project status", OSINT/ML framing), MIT LICENSE, untracked `.pyc`, language
  bar. **Also caught a real Postgres deadlock + claim-overlap in the multi-worker
  detection pool** (invisible on SQLite) that had been failing the backend-postgres
  CI job - fixed via fired-rules-only / sorted `last_fired` updates and a
  `FOR UPDATE SKIP LOCKED` claim; the Tests workflow is green again.

- **2026-06-15 · Measured load baseline (`bench.py` + `docs/LOAD_LIMITS.md`).**
  "Load limits" were a guess; now there's a repeatable benchmark and a captured
  baseline of **real measured throughput** on the host. On 4 vCPU + SQLite WAL it
  sustains **~10k EPS ingest+detect** and **~7k EPS pure detection** (single
  worker). The benchmark surfaced an **honest, valuable finding**: the detection
  worker pool is *slightly slower* with more workers on SQLite (single-writer
  contention) - so the pool is for correctness + Postgres scaling, not SQLite
  throughput, and the doc says so plainly and points to Postgres / a columnar
  store for higher EPS. `test_bench.py` runs the benchmark in an isolated
  subprocess as a smoke check.

- **2026-06-15 · Multi-worker detection pool (event-pipeline increment 3).** The
  queue seam (increment 1) and bounded ingest (increment 2) were in, but detection
  was still a single inline worker - the documented P0 scale ceiling.
  `detection_pool.py` adds the concurrency-safe pool: each worker claims a batch
  under a **write-locked transaction** (SQLite `BEGIN IMMEDIATE` on an autocommit
  connection - the lock is taken *before* the SELECT, so a concurrent claim blocks
  then sees the rows already taken), then processes it through the unchanged
  `run_detection` path (now accepting a pre-claimed `claimed=` batch). At-least-once
  via the existing lease/`requeue_stale`. `POST /siem/detection/drain?workers=N`
  exposes a pooled backlog drain (`DASHBOARD_DETECTION_WORKERS`). The **inline
  engine tick is deliberately untouched** (worker engine-0), so the default path
  is byte-for-byte unchanged. `test_detection_pool.py` proves the decisive
  invariant - a 6-worker drain yields exactly the same alerts as a 1-worker drain
  of identical input (no event claimed/alerted twice, none missed) - plus the
  drain endpoint. Full suite green (268).

- **2026-06-15 · DPA template (GDPR Art. 28).** Enterprise procurement asks for a
  Data Processing Agreement before a PoC ends; there wasn't one. `docs/DPA_TEMPLATE.md`
  is a complete, realistic template - roles, Art. 28(3) processor obligations,
  sub-processor change/objection, data-subject assistance, breach notice, audit,
  deletion/return, international transfers - with four annexes (processing
  details, **TOMs grounded in the controls the product actually implements**,
  the real optional sub-processors, SCCs). Honest throughout: it foregrounds the
  **self-hosted vs managed** distinction (self-hosted = vendor isn't the
  processor) and explicitly flags that no independent SOC 2 / pentest is done yet.
  Referenced from `docs/COMPLIANCE.md`. Pure additive doc.

- **2026-06-15 · Kubernetes Helm chart.** Deployment was docker-compose only -
  no story for the orchestrated, HA deployment an enterprise buyer runs.
  `deploy/helm/threatorbit` (chart `0.1.0`) deploys all four services modelled
  exactly on `docker-compose.yml` and the Dockerfiles: Deployments + ClusterIP
  Services for threat-api/log-api/dashboard-api/frontend, HTTP liveness/readiness
  probes (dashboard readiness hits `/ready`, which checks the DB), a
  Secret/ConfigMap split (secrets overridable or via `existingSecret`), per-PVC
  storage for the SQLite services with `Recreate` strategy (single-writer), and
  an **optional Postgres** mode that flips the dashboard to multi-replica rolling
  updates. Internal service DNS is wired (dashboard → `…-threat-api:8000` /
  `…-log-api:8000`); ingress supports a web host + a dedicated API host. NOTES.txt
  warns on missing required secrets and the multi-replica-needs-jwtSecret pitfall;
  a chart README documents build/install/HA/ingress. Validated structurally
  (brace/control balance + every manifest's YAML skeleton parses to the right
  kinds); pure additive (`deploy/helm/**` only - no app code touched).

- **2026-06-15 · Per-rule noise ratings.** Completes the detection-content item.
  A fresh pack rule's observed `fp_rate` is 0 (no fires yet), so analysts had no
  signal for which rules to tune first. Each pack rule now carries an authored
  **noise rating** (`low|medium|high`) - honest content metadata kept in a new
  `detection_rules.noise` column, deliberately *distinct* from the observed
  fp_rate (so it's not an invented statistic). E.g. Large Outbound Data Transfer
  = high (backups), Ransomware mass-encrypt = low. Surfaced as a colour-coded
  stat in the rule detail. `test_detection_pack.py` asserts every pack rule has a
  valid rating. Full suite green.

- **2026-06-15 · Cloud source breadth: Azure AD/Entra + GCP Cloud Audit.**
  Completes the three-major-clouds story (AWS CloudTrail shipped alongside the
  Windows/Sysmon work). JSON ingest now recognises **Microsoft Entra / Azure AD**
  sign-in logs (status.errorCode → login_success/failed_login, with UPN, IP and
  country) and directory **AuditLogs** (add-member-to-role → group_change), and
  **GCP Cloud Audit** records (methodName → event_type:
  CreateServiceAccountKey→create_access_key, SetIamPolicy→policy_change, with
  principalEmail, callerIp, and gRPC status → allow/deny). So a failed cloud
  sign-in on any of the three lands as `failed_login` and feeds the brute-force /
  spray rules; a new cloud key feeds the persistence rule. Guarded so generic
  JSON carrying a `category` isn't hijacked. `test_ingest_sources.py` covers both.
  Full suite green.

- **2026-06-15 · Source breadth: Windows Security + Sysmon + AWS CloudTrail.**
  JSON ingest was generic-only; the sources every SOC actually onboards landed as
  unclassified `log` rows. `ingest.py` now recognises **Windows Security events**
  (raw EVTX-JSON and winlog/Beats nesting), **Sysmon** operational events, and
  **AWS CloudTrail** records and maps their distinctive fields onto the native
  vocabulary - crucially EventID/eventName → `event_type` (Security:
  4625→failed_login, 4732→group_change, 4688→process_start, 1102→log_cleared;
  Sysmon: 1→process_start, 3→network_connect, 8→remote_thread, 22→dns_query;
  CloudTrail: CreateAccessKey→create_access_key, ConsoleLogin-failure→
  failed_login, StopLogging→log_cleared) plus user/host/src_ip/dest/process and
  an ATT&CK id. So the **starter-pack rules fire on real Windows/Sysmon/AWS
  telemetry** with no extra config. Guarded against false positives (arbitrary
  JSON carrying an EventID isn't hijacked; Sysmon vs Security route by channel;
  service-principal "source IPs" are dropped). `test_ingest_sources.py` (all three
  shapes at parse level + an end-to-end ingest storing the right event_type).
  Full suite green.

- **2026-06-15 · SSE stream tenant-scoping (real-time leak closed).** The
  in-process SSE broker fanned every event to every connected browser, so with
  isolation on a user would see another tenant's alerts/cases stream in live -
  the real-time half of the search leak. The broker now tags each subscriber
  queue with its org (the SSE endpoint passes the validated user's org) and
  `publish(...)`/`dispatch(..., org=)` deliver a tenant event only to that org's
  subscribers when isolation is enforced; system events with no org (engine
  ticks) still reach everyone, and with isolation off the broker broadcasts
  exactly as before (default path unchanged). The five request-path producers
  (alert.created, case.created, incident.resolved, ioc.confirmed,
  darkweb.takedown) now publish with the actor's org. `test_stream_scope.py`
  proves explicit-org and payload-`org_id` scoping, system-event broadcast, and
  the off path. Engine-path events still broadcast (per-org engine context is the
  remaining multi-tenancy item). Full suite green (260).

- **2026-06-15 · Curated starter detection pack.** A fresh install had the Sigma
  importer but an empty rule list - nothing detecting until you authored content.
  `detection_pack.py` ships **10 real Sigma rules** (brute-force/spray, ransomware
  mass-encrypt + shadow-copy deletion, DNS tunneling, large egress, LOLBin tool
  transfer, C2 beacon, cloud access-key creation, impossible travel) that parse
  through the existing importer onto evaluable definitions - and every selection
  targets a field/value the platform's **own event stream actually produces**, so
  they fire on real telemetry rather than being shelf-ware. Each carries an
  ATT&CK technique + tactic. `POST /siem/rules/load-pack` (idempotent by name) +
  a one-click "Starter pack" button on the rules page. `test_detection_pack.py`
  (all 10 parse to non-`raw` precise conditions with ATT&CK tags; load creates
  then fully skips on re-run; a loaded rule is live + evaluable). Full suite
  green (259), tsc + build green.

- **2026-06-15 · Audit-trail external streaming (tamper-evidence).** The audit
  log lived only in the same DB an intruder could alter. Every `audit()` event is
  now also shipped to an external endpoint (the customer's SIEM / append-only
  store) when `DASHBOARD_AUDIT_SINK_URL` is set - fire-and-forget on a background
  worker so the request path is never blocked, optionally HMAC-signed with
  `DASHBOARD_AUDIT_SINK_SECRET` (the outbound-webhook scheme, so the same
  `verify_signature` validates it). Copy-on-write / at-least-once; unset URL is a
  complete no-op (in-DB behaviour unchanged). `test_audit_sink.py` (disabled
  no-op; signed-event round-trip; an audited admin action mirrored + verified).
  Full suite green (257).

- **2026-06-15 · Retention archive (cold storage before purge).** Retention
  enforcement DELETE'd old alerts/events/dark-web/scans/notifications outright -
  regulated buyers need raw logs kept cheaply, not destroyed. With
  `DASHBOARD_ARCHIVE_DIR` set, each batch is now written to compressed NDJSON
  (`<table>-<YYYYMMDD>.ndjson.gz`, append-friendly) **before** deletion; if
  archival fails the table is left intact rather than purged unarchived (data is
  never lost silently). Unset = pure purge, so existing installs are unchanged.
  The enforce response reports archived counts + the dir; the UI message notes
  the cold-storage step. `test_retention_archive.py` (helper writes/reads gz +
  disabled no-op; endpoint archives-then-purges and the rows survive only in the
  archive). Full suite, tsc and build green.

- **2026-06-15 · Global search is tenant-scoped.** The one search box queried
  alerts/IOCs/assets/cases/actors/dark-web with no org filter, so with isolation
  on it would surface another workspace's hits - a cross-tenant leak. It now
  applies `tenancy.scope_sql(org_of(user))` to every table (each carries
  `org_id`), with the scope clause placed **inside** each match group's parens so
  it ANDs across the whole `LIKE … OR LIKE …` rather than just the last term. A
  no-op when isolation is off (single-tenant behaviour identical).
  `test_search_scope.py` proves the foreign workspace's alert + IOC vanish with
  the flag on and return with it off. Remaining tenancy gap: the SSE stream
  (tracked above). Full suite green.

- **2026-06-15 · Webhook delivery retries (exponential backoff).** A transient
  blip on the subscriber's side dropped events permanently (one attempt, then
  marked `failing`). Delivery now retries up to 3 times with exponential backoff
  (1s, 2s); the idempotency id + signature are computed once and **reused across
  attempts**, so a subscriber sees the same delivery and dedupes it. Marked
  `failing` only after all attempts fail; backoff sleeps are skipped under the
  test sync-delivery path. `test_webhook_signing.py` proves retry-then-succeed
  with a single stable delivery id; full suite green.

- **2026-06-15 · Outbound webhook signing + idempotency.** Subscribers had no
  way to verify a delivery genuinely came from ThreatOrbit (anyone who learned
  the URL could forge events). Each webhook now has a `whsec_` signing secret
  (shown once at create, rotatable via `POST /config/webhooks/{id}/rotate-secret`,
  never re-listed); every delivery is signed **`X-ThreatOrbit-Signature:
  t=<unix>,v1=<hmac>`** - HMAC-SHA256 over `"<t>.<body>"`, the exact bytes sent,
  the same scheme as the inbound Stripe verifier - and carries an
  **`X-ThreatOrbit-Delivery`** uuid so consumers dedupe retries plus an
  `X-ThreatOrbit-Event` header. `verify_signature()` is shipped as the reference
  verifier (and the UI banner documents the scheme). Frontend: the API/webhooks
  page reveals the secret once with copy + a rotate action. `test_webhook_signing.py`
  (sign/verify round-trip incl. tamper/wrong-secret/stale-timestamp, secret
  shown-once-then-hidden, signed+idempotent live delivery, rotate invalidates
  the old secret); full suite, tsc and build green.

- **2026-06-15 · Idle timeout (sliding inactivity sign-out).** The "Session
  Timeout (minutes)" setting was decorative - stored, shown, never enforced.
  It's now a real **idle window**: `current_user` reads it (per-device
  `last_seen` already tracked) and signs out a session left inactive longer than
  the window, even though the JWT's 12h hard expiry hasn't fired. Defaults to the
  hard-expiry (a no-op until an admin lowers it); `0` disables it. The setting is
  read inside the existing auth connection (no extra round-trip), and only for
  `sid`-bearing tokens. UI relabelled **Idle Timeout** with an honest hint.
  `test_sessions.py` proves a back-dated session is rejected and a fresh login
  works; full suite, tsc and build green.

- **2026-06-15 · Password screening (NIST SP 800-63B aligned).** Every
  set-password path only enforced an 8-char floor - `password`, `12345678`,
  `qwerty123` all sailed through. New `password_policy.validate_password`
  screens length (8…256, the ceiling caps a PBKDF2 DoS lever), an offline
  **common/breached-password list** (exact, case-insensitive - so strong
  passphrases that merely contain a word still pass), and trivial
  self-references (the password being your own name/email). Wired into
  **register**, **admin create-user**, and **change-password** (400 with the
  specific reason). Also fixed the frontend `api()` error extractor to read the
  `{"error": …}` envelope (it only read `{"detail": …}`), so these messages -
  and every other API error - now surface to the user instead of a generic
  fallback; the change-password form shows the exact reason.
  `test_password_policy.py` (helper + all three endpoints); full suite, tsc and
  build green.

- **2026-06-15 · Active sessions list (see your devices, sign out one).** The
  token-epoch counter was an all-or-nothing kill switch; you couldn't see *which*
  devices were logged in or drop a single suspicious one. Each login (and
  self-service register) now writes a **per-device `sessions` row** and the JWT
  carries its id as a `sid` claim. `current_user` checks the row isn't revoked
  (sid-less tokens - older sessions, SSO/SAML - fall through on the epoch check,
  so it's fully backward compatible) and advances a throttled `last_seen`.
  New: `GET /auth/sessions` (your devices, the current one flagged, with
  parsed device + IP + last-active) and `POST /auth/sessions/{id}/revoke` (sign
  out one device - 404 if it isn't yours). The `revoked` flag stays consistent
  with the coarse mechanism: change-password keeps the current device and drops
  the rest, revoke-all and admin-revoke clear the list. Frontend: an **Active
  Sessions** panel in Settings → Security (per-row Sign out + "Sign out other
  devices"). `test_sessions.py` grew 4 tests (list/current-flag, individual
  revoke kills only that token, cross-user revoke 404s, revoke-all + change-
  password list consistency); full suite, tsc and build all green.

- **2026-06-15 · MFA recovery codes (a lost authenticator is no longer a
  lockout).** TOTP-only meant losing the phone locked a user out for good - an
  enterprise non-starter. On `mfa/verify` we now issue **10 one-time recovery
  codes** (shown once, `xxxxx-xxxxx`), storing only their SHA-256 hashes
  (`users.mfa_recovery_codes`, JSON). At login, a failed TOTP falls back to
  consuming a recovery code (one-time, audited `auth.mfa_recovery_used`);
  `mfa/status` reports `recoveryCodesRemaining`; `POST /auth/mfa/recovery-codes`
  regenerates the set (TOTP-gated, invalidates the old one); `disable` clears
  them. Hashes never leave the server (`_public` + `current_user` strip them).
  Frontend: the config MFA panel shows the codes once at enrol with **Copy
  all** / **I've saved them**, a remaining-count, and a **Regenerate** action.
  `test_mfa_recovery.py` (4 tests: issue→consume→reuse-fails→regenerate→disable
  + pure helpers); full suite green; tsc + build green.

- **2026-06-15 · UX bug-fix batch (user-reported).** (1) **Dashboard health
  showed 0** in normal mode - the gauge bound to org *risk* but presented it as
  *health*; inverted to `100 - risk` (see earlier entry). (2) **Asset delete
  didn't persist** - there was *no* `DELETE /assets/{id}` endpoint, so the
  frontend only filtered local state and the asset returned on refresh. Added
  the org-scoped, audited endpoint (recomputes fleet risk) + a `deleteAsset`
  client; the Remove button now calls it, optimistically updates, **confirms
  first** (was no warning), and restores on failure. (3) **No logout / profile
  menu** - the TopBar "user" block was static text ("Admin"/"SOC Analyst") with
  no handler; replaced with a real account menu (avatar + name/role/email,
  "Profile & settings" → /dashboard/config, and **Sign out** wired to
  `logout()`). (4) **Actor mapping** guarded an unchecked `a.campaigns.map`
  (live actor data could silently fall back to seed). Backend test for the
  delete; tsc + build green. Remaining user-reported items tracked in the
  "Frontend UX & polish backlog" below.

- **2026-06-15 · Revocable sessions (stateless JWTs you can actually kill).**
  Closes the "can't sign out a stolen/old session" gap. Each JWT now carries a
  monotonic **token-epoch** (`ep`); `current_user` rejects any token whose epoch
  is behind the user's current `token_epoch` (a new `users` column). Bumping the
  counter therefore invalidates every earlier token at once - **race-free** (a
  counter, not a timestamp, so there's no same-second ambiguity). Endpoints:
  `POST /auth/sessions/revoke-all` (sign out everywhere - this session too),
  admin `POST /users/{id}/revoke-sessions` (`users.manage`, for suspected
  compromise), and **password change auto-revokes** other sessions while issuing
  a fresh token so the current one continues seamlessly (frontend persists it).
  Backward-compatible: a pre-existing token with no `ep` reads as 0 and stays
  valid until the first revoke. 4 tests (revoke-all + relogin, change-password
  old-dies/new-lives, admin revoke, permission gate). Suite 244 → **248**.

- **2026-06-15 · Custom RBAC roles (additive, no privilege escalation).** The
  fixed 4-role matrix gains operator-defined roles without touching the
  load-bearing path. The four built-ins stay **code-authoritative** in
  `permissions.py` (zero behaviour change - the other 237 tests, all on built-in
  roles, still pass); `perms_for()`/`has_perm()` now fall back to a `roles` table
  for custom roles, **validated against the capability catalogue and fail-closed**
  on any error so a missing/garbled role never grants access. `/roles` CRUD
  (`users.manage`): list (built-ins + custom + the catalogue), create, edit,
  delete (refused while users are assigned). A **no-privilege-escalation** guard
  rejects granting a capability the creator doesn't hold (a manager can't mint a
  `users.delete` role). `update_user`/`create_user` accept custom role ids via
  `role_exists()`. 7 tests incl. require_perm honouring a custom role's caps
  (grant AND deny) on the real auth path + the escalation guard. Suite 237 → **244**.

- **2026-06-15 · GDPR data-subject tooling (access + erasure).** `/privacy`
  endpoints: `GET /privacy/me` (self-service export), `GET /privacy/export/{id}`
  (a DSAR response, `users.manage`), and `POST /privacy/erase/{id}` (right to be
  forgotten, `users.delete`). Erasure **anonymises** rather than hard-deletes
  (`privacy.py`): the user row's PII is replaced + the account disabled, and the
  subject's email is rewritten to an `…@anonymized.invalid` placeholder
  everywhere it appears as an identity (their audit trail + records they
  own/authored). Each rewrite is `WHERE col = <subject email>`, so only this
  subject's references change - never threat-actor attribution. Self-erasure is
  refused (would lock out the operator). Added a `PR-DSAR` control to the
  compliance matrix. 5 tests (export shape, anonymisation + login disabled +
  audit-trail rewrite, permission gate, self-erase guard). Suite 232 → **237**.

- **2026-06-15 · Compliance control mapping (SOC 2 / ISO 27001 self-assessment).**
  Procurement asks "map your controls" before the first PoC ends.
  `dashboard_api/compliance.py` is the single source of truth: 19 controls mapped
  to SOC 2 Trust Services Criteria + ISO/IEC 27001:2022 Annex A, each citing
  **real in-repo evidence** (MFA, RBAC, OIDC/SAML/SCIM, Fernet-at-rest, SSRF
  guard, audit logging, signed evidence bundles, supply-chain, backups …), with
  honest `status` (14 implemented, 2 partial, 3 planned). Served at
  `GET /compliance/controls` for an in-product view / questionnaire auto-fill;
  `docs/COMPLIANCE.md` is the human-readable matrix. Crucially **honest**: a
  prominent disclaimer states this is a self-assessment, **not** a SOC 2 report
  or certification, and the gaps (independent pen test, formal audit, HA) are
  listed as `planned`, not hidden - `test_compliance.py` (6 tests) enforces that
  honesty (disclaimer present, pen-test/audit stay `planned`, every control cites
  evidence). Read-only, no DB writes. Suite 226 → **232**.

- **2026-06-15 · Detection-content update channel (rules without a code
  release).** A real SIEM ships new detections as content, not code. Rules now
  load from versioned JSON **packs** in `content/rules/*.json`; `content.py`
  validates them (refusing a malformed pack whole), and `POST /siem/content/apply`
  **upserts** them into `detection_rules` idempotently - refreshing the content
  fields while **preserving an operator's enable/disable choice and hit stats** -
  and records each pack's applied version in `settings`. `GET /siem/content`
  shows available packs + what's pending. So updating detections = drop in a
  newer pack file + apply, no redeploy. The built-in 15 stay code-shipped
  (engine.py untouched); packs add to / refresh the library. First pack
  (`threatorbit-windows-extras` v1) ships 4 real Windows detections - service
  install (T1543.003), security-tool tampering (T1562.001), scheduled task
  (T1053.005), event-log clear (T1070.001) - that fire on ingested Windows logs.
  7 tests incl. an end-to-end (apply → ingest a matching event → alert with the
  right MITRE). Suite 219 → **226**.

- **2026-06-15 · HA/DR: full-stack backup + tooled restore + automated drill.**
  Operationalised the backup story (previously dashboard-only snapshots with a
  *manual* restore runbook and no restore test). `dashboard_api/backup.py` takes
  a live-safe online-backup snapshot of **all three** service databases
  (dashboard / threat / log), integrity-checks each, and bundles them into one
  timestamped `tar.gz`; **restore** verifies every snapshot before it overwrites
  a live file, refuses to clobber without `--force`, drops stale WAL/SHM
  sidecars, and rejects path-traversal archive members. Thin `scripts/backup.sh`
  / `restore.sh` wrappers (Docker `/data` defaults) + `docs/BACKUP_RESTORE.md`
  runbook (scheduling, off-box shipping, RPO/RTO, encryption, Postgres note).
  The gap this closes - **an automated restore drill** - is now `test_backup.py`
  (6 tests: round-trip real data, corruption detection, force-guard, stale-WAL
  cleanup, zip-slip block). Complements the existing dashboard-only
  `GET /config/backup` (ops.py), which stays. Suite 213 → **219**.

- **2026-06-15 · Event pipeline, increment 2: bounded ingest queue (429
  backpressure).** `POST /siem/ingest` now sheds load with **HTTP 429 +
  `Retry-After`** once the detection backlog reaches `DASHBOARD_INGEST_MAX_BACKLOG`
  (default 100 000; 0 disables), rather than unbounded best-effort inserts the
  pipeline can't drain - the "bounded queue + 429" half of the backpressure
  definition-of-done. The cap and a live `shedding` flag are on `GET
  /config/engine`. Also fixed the `StarletteHTTPException` handler to **propagate
  exception headers** (so `Retry-After` / `WWW-Authenticate` actually reach the
  client). 2 tests (sheds over cap, accepts under). Suite 211 → **213**.

- **2026-06-15 · Event pipeline, increment 1: the ingest/detection queue seam +
  backpressure visibility.** First safe step on the P0 EPS-ceiling gap.
  `event_queue.py` turns the `events` table into a **lease-based work queue**
  (`claim` a batch → process → `complete`; `requeue_stale` reclaims a dead
  worker's lease) via two additive columns (`claimed_by`/`claimed_at`). The
  engine's `run_detection` now pulls its batch through the queue as worker
  "engine-0" - **behaviour-preserving** for the single inline worker (full suite
  205 → 211, green) but the seam a worker *pool* needs. **Backpressure is now
  observable** (it was invisible before): queue depth, in-flight, and oldest-
  pending **lag** are on `GET /config/engine` and as Prometheus gauges
  (`threatorbit_event_queue_depth` / `_lag_seconds`). 6 tests prove the lease
  semantics (exclusive-within-lease claim, complete clears it, stale re-queue) +
  that detection flows through the queue + the status surface. Deliberately
  scoped: the multi-worker pool / ingest-only cutover (needs per-worker
  `BEGIN IMMEDIATE` claim txns), a bounded 429 ingest queue, and the columnar
  store are the next increments - not rushed into the load-bearing heartbeat.

- **2026-06-15 · SAML 2.0 SP SSO (completes the SAML/SCIM unit).** SP-initiated
  Web Browser SSO for IdPs that speak SAML rather than OIDC (config `SAML_IDP_*`;
  unset → 404). `saml.py` builds the AuthnRequest (HTTP-Redirect binding) and
  verifies the IdP's **signed assertion** with **signxml** against the pinned
  X.509 cert - and crucially reads attributes **only from the element signxml
  reports as signed** (`signed_xml`), which defeats XML signature-wrapping. It
  enforces Issuer, Audience, SubjectConfirmation Recipient, the Conditions +
  confirmation time windows (clock-skew tolerant), binds the response to our
  request via a signed-RelayState **InResponseTo**, and rejects **replayed**
  assertions (one-time-use). XML is parsed by signxml's hardened (no-XXE)
  parser. `routers/saml.py` mirrors the OIDC flow (status / login / ACS → JIT
  provision → session token in the URL fragment). New deps: `signxml` + `lxml`
  (pure pip, no system xmlsec). Frontend: a "Sign in with SAML" button alongside
  the OIDC one (same fragment callback). **`test_saml.py` is the security proof
  (16 tests)**: a locally-minted IdP signs real assertions; the SP accepts valid
  ones and **rejects** unsigned / tampered / wrong-signing-key / expired / wrong
  audience / wrong issuer / wrong recipient / InResponseTo-mismatch / replay.
  Dashboard suite 189 → **205**; frontend tsc + build green.

- **2026-06-15 · SCIM 2.0 provisioning (the security-critical deprovisioning
  half of SSO).** An IdP can now push user lifecycle to the dashboard over a
  bearer-token `/scim/v2` surface (config `SCIM_TOKEN`; unset → 404, feature
  off). Implemented: `User` create / read / list with `userName eq` filter +
  pagination / PUT replace / **PATCH active:false** (the deprovision path Okta &
  Entra use) / DELETE (soft-disable so owned records aren't orphaned), plus the
  ServiceProviderConfig / ResourceTypes / Schemas discovery docs IdPs probe.
  Auth is a constant-time bearer compare; provisioned users land in the same
  `users` table and sign in via the existing OIDC SSO; role defaults to
  `SCIM_DEFAULT_ROLE` and maps from a SCIM role via `SCIM_ROLE_MAP`. Pure
  mapping helpers in `scim.py`; 12 tests in `test_scim.py` (degradation, auth,
  full lifecycle, role mapping, mappers). Dashboard suite 177 → **189**, green.
  This closes the "ex-employee keeps access" finding. **SAML 2.0 SP is the next
  commit in this unit.** Follow-ups: SCIM Group→role push, externalId filter.

- **2026-06-15 · Detection content: built-in rule pack 7 → 15 across 8 ATT&CK
  tactics.** The first chunk of the curated detection-content gap (a SIEM's core
  value). Added 8 high-fidelity rules with full MITRE mapping - ransomware mass
  encryption (T1486) + shadow-copy deletion (T1490) bringing the **Impact**
  tactic in for the first time, kerberoasting (T1558.003) + password spraying
  (T1110.003) deepening **Credential Access**, cloud access-key creation
  (T1098.001, **Persistence**), DNS tunneling (T1071.004) + ingress tool transfer
  (T1105, **C2**), and impossible-travel login (T1078). Each ships with a paired
  telemetry scenario in the live engine so the detection fires on real generated
  events (not a dangling rule), with re-balanced scenario weights (sum 1.0).
  New `test_detection_rules.py` (7 tests) enforces it: every rule well-formed
  (Txxxx/TAxxxx, unique ids, real conditions), content breadth ≥15 rules / ≥6
  tactics incl. Impact, **every telemetry scenario matched by a rule whose
  technique agrees with the event** (caught a real T1098 vs T1098.001 mismatch
  during dev), a benign event trips nothing, and the new rules seed + evaluate
  through `run_detection`. Full dashboard suite 170 → **177**, green.

- **2026-06-15 · FastAPI `on_event` → `lifespan` (tech debt the dep bump
  surfaced).** Migrated both services off the deprecated `@app.on_event("startup")`
  hook (which a future FastAPI major will remove) to the `lifespan`
  async-context-manager passed to `FastAPI(lifespan=...)`. log_api's startup is a
  one-liner (`init_db()`) inlined into the lifespan; dashboard_api's richer
  startup (schema init, secret-at-rest migration, demo/live seeding, engine +
  connector + log-listener threads) stays a `_startup()` the lifespan calls.
  Verified: dashboard 170 + log 1 still pass (test-neutral - conftest inits the
  DB itself with a bare `TestClient`), the `on_event` DeprecationWarning is gone
  (log_api passes under `-W error::DeprecationWarning`), and a `with TestClient`
  smoke confirms the **real** lifespan startup runs cleanly (dashboard seeds demo
  data + `/ready` true; log_api `/health` ok).

- **2026-06-15 · Docker image build-validation in CI (`docker-build.yml`).**
  Closed the supply-chain gap that nothing in CI built the images: the test gates
  run the app directly, so a base-image bump or a bad dependency pin could merge
  green and only break at `docker build` / deploy. The new workflow builds all
  four service images (dashboard_api / threat_api / log_api / frontend, the last
  with its `NEXT_PUBLIC_API_URL` arg) via a matrix - **build-only, no registry
  push** - with GHA layer caching, plus a `compose-config` job that validates
  `docker-compose.yml` resolves. Scoped by `paths` to the inputs that affect a
  build (Dockerfiles, requirements, frontend package/nginx, compose, the workflow
  itself) so it doesn't re-run on every source edit, but **does** run on
  Dependabot's docker base-image PRs - giving a real "it still builds" signal.
  Re-enabling docker digest auto-merge now only needs this job marked a
  *required* check in branch protection (a repo setting).

- **2026-06-15 · Backend dependency groups (the three pip majors).** Cleared the
  oldest waiting Dependabot PRs (#9/#11/#13), each held from auto-merge because
  its group contained a major. Bumped across the three services: **cryptography
  46→49** (dashboard_api - Fernet + the OIDC RS256 verify path), **numpy 1.26→2.4
  + scikit-learn 1.5→1.9** (log_api ML anomaly detector), **pytest 8→9** (all
  three), plus minor/patch on fastapi 0.118→0.137, uvicorn 0.30→0.49, pydantic
  2.9→2.13, httpx, flask 3.0→3.1, flask-cors, requests, stix2, python-multipart,
  pyyaml. Verified in a clean venv: **threat_api 1, log_api 1, dashboard_api 170
  - all pass** (the SSO test exercises RS256 under cryptography 49; the ML test
  imports numpy 2 / sklearn 1.9). Tracked tech debt surfaced by the run: FastAPI
  `@app.on_event("startup")` is deprecated (dashboard_api/main.py, log_api) -
  still works in 0.137 but should migrate to a `lifespan` handler before a future
  FastAPI major removes it (own small unit).

- **2026-06-14 · React 19 + the react-three-fiber v9 chain (last outdated major
  set).** Took the riskiest remaining upgrade as its own unit: react/react-dom
  18→**19.2.7**, @react-three/fiber 8→**9.6.1**, @react-three/drei 9→**10.7.7**,
  @react-three/postprocessing 2→**3.0.4**, framer-motion 11→**12.40.0**, plus
  @types/react(-dom) 19. The blast radius was small where it counted - the 3D
  stack is used in only 4 `components/effects/` files, and those type-checked
  clean under v9 (no scene code changes needed). The real work was two React 19
  type migrations: (a) `useRef<T>()` now requires an initial value - fixed the
  two rAF-handle refs to `useRef<number | undefined>(undefined)`; (b) `icon:
  React.ElementType` collapsed icon props to `never` because R3F v9's JSX
  augmentation balloons `keyof JSX.IntrinsicElements` - replaced all 30 icon-slot
  `React.ElementType`s with `React.ComponentType<any>` (behavior-preserving, no
  new imports). Also bumped **lucide-react 0.417→1.18** for React 19 support;
  v1 dropped brand icons, so the `Github` glyph now ships as a local
  `components/ui/GithubIcon.tsx` (drop-in, same call sites). Verified locally:
  `tsc --noEmit` clean, the **static export builds** (all 50+ routes prerender),
  `npm audit` has **0 high/critical** (only the 2 known triaged postcss
  moderates), and no removed framer-motion v12 APIs are used. **E2E is the gate**
  and runs in CI (Playwright's browser CDN isn't reachable from this env, so the
  suite couldn't run locally). This supersedes Dependabot PRs #14/#17/#19/#20/#21
  (Dependabot auto-closes superseded PRs on its next cycle).

- **2026-06-14 · Supply-chain hardening: SBOM + image/secret scanning + Docker
  auto-update.** Continuing the dependency-security push: (a) **SBOMs** -
  `scripts/sbom.sh` generates CycloneDX SBOMs for the backend (resolved Python
  environment, 124 components) and the frontend (npm tree, 448 components), and
  `.github/workflows/supply-chain.yml` publishes them as artifacts on every
  push/PR/weekly run - the procurement "give us your SBOM" ask. (b) **Trivy**
  scans the repo for vulnerable deps + committed secrets (fails on a fixable
  CRITICAL) and for Docker/IaC misconfigurations (report-only artifact). (c)
  **Dependabot** now also tracks the **Docker base images** (python-slim,
  node-alpine, nginx-alpine) so they stay patched. Both SBOM generators
  verified locally.

- **2026-06-14 · Digest-pinned base images + signed, provenance-backed
  releases.** Closing out the P0 supply-chain gap: (a) all four Dockerfiles now
  pin their base image by **digest** (`python:3.11-slim@sha256:ae52c5…`,
  `node:22-alpine@sha256:9385cd…`, `nginx:1.27-alpine@sha256:65645c…`) - all
  three digests resolved and re-verified against the live Docker Hub registry,
  so a build can no longer silently pick up a re-pushed tag; Dependabot's docker
  ecosystem keeps the digests current. (b) **`.github/workflows/release.yml`**
  (fires only on a `v*` tag, a harmless no-op against any other ref) builds the
  CycloneDX SBOMs + a reproducible source archive + a SHA256SUMS manifest,
  **cosign-keyless-signs** each artifact (Sigstore Fulcio cert + Rekor
  transparency-log entry, detached `.cosign.bundle` - no long-lived signing key
  to leak), and generates **SLSA3 build provenance** via the official
  `slsa-github-generator` (pinned `@v2.1.0`), all attached to the GitHub
  release. Verify instructions are in the workflow header. Remaining: signing
  published **container images** (deferred until a registry-push pipeline
  exists - nothing pushes images today).
  - **Auto-update policy hardened the same day (caught live).** Within minutes
    of pinning, Dependabot's docker group rebased and proposed *major* runtime
    jumps (python 3.11→**3.14**, node 22→**26**) in PR #24 - and because **no CI
    job builds the images**, such a jump could break `pip install` / `npm ci`
    without any gate going red, then auto-merge. Fixed: `dependabot.yml` now
    keeps the base-image **tags fixed** (python 3.11 / node 22 LTS / nginx 1.27)
    and only refreshes their `@sha256` **digests** (ignore semver major+minor),
    and `dependabot-auto-merge.yml` **excludes the docker ecosystem** so every
    base-image PR gets human review. PR #24 closed. Follow-up **DONE
    (2026-06-15)**: `docker-build.yml` now build-validates all four images in CI
    (see CHANGELOG). Re-enabling docker digest auto-merge still needs that job
    added as a *required* check in branch protection (a repo setting, not code).

- **2026-06-14 · Automated dependency updates + fixed a missed CVE + honest gap
  analysis.** Prompted by a fair user catch (the install prints "5
  vulnerabilities" and a service was on an old version): (a) **fixed a real
  miss** - `threat_api` pinned `flask-cors==4.0.1` (CVE-2024-6221 /
  CVE-2024-1681); bumped to flask-cors >=6.0.1 + requests >=2.32.4 (threat_api
  tests green). The earlier security pass had bumped dashboard_api/log_api but
  not threat_api's Flask stack. (b) **Added the auto-update feature**:
  `.github/dependabot.yml` watches all four services (pip ×3 + npm) and the CI
  actions with grouped weekly PRs (security PRs immediately), and
  `dependabot-auto-merge.yml` auto-merges patch/minor bumps once the
  Tests/E2E/Security gates pass - majors stay manual. (c) Wrote a deep,
  self-critical **"Honest gap analysis"** in plan.md (supply chain, event-pipeline
  ceiling, HA/DR, detection content, identity depth, compliance, multi-tenancy,
  API contract, UX/a11y, testing) with priorities and definitions of done. The
  npm advisories (Next.js 14) and the major upgrades (next@16, react@19, …) are
  now tracked as units to do with full E2E rather than left as silent triage.
- **2026-06-14 · Cleared the 5 npm advisories: upgraded Next.js 14 → 16.**
  The remaining frontend advisories (Next.js image-optimizer DoS, the
  eslint-config-next/glob command-injection, postcss XSS) all fixed at next@16.
  Took the low-risk path: next@16 still supports **React 18**
  (`peerDeps: ^18.2.0 || ^19.0.0`), so the whole react-three-fiber / three /
  motion stack stays put - no React-19 chain. Breaking changes handled: the
  metadata route handlers (`robots`/`sitemap`/`manifest`) now declare
  `export const dynamic = 'force-static'` for the static export, and tsconfig
  picked up Next 16's `jsx: react-jsx`. Production `npm audit` now has **no
  high/critical** (2 moderate build-time postcss advisories remain, below the
  gate threshold); the `.audit-allowlist.json` Next triage entries were removed
  since the advisories are genuinely fixed. Type-checks + builds clean; the E2E
  gate validates the runtime. (react@19 + R3F v9 remain a separate tracked unit.)

- **2026-06-14 · SSO via OIDC (Tier 2, opt-in).** Single sign-on against any
  OpenID Connect provider (Entra ID / Okta / Google / Auth0 / Keycloak):
  authorization-code flow with `/auth/sso/login` → IdP → `/auth/sso/callback`,
  which exchanges the code, **verifies the ID token's RS256 signature against
  the provider's JWKS** (using `cryptography` - already a dep via Fernet, no
  PyJWT), checks issuer/audience/expiry/nonce, then JIT-provisions the user and
  maps an IdP groups claim to a role (admin|manager|analyst|viewer). CSRF state
  + nonce are carried in a value signed with the dashboard JWT secret (no
  server session store); the callback hands the normal session token to the
  frontend in the URL fragment so it never hits a server log; an optional
  email-domain allowlist gates provisioning. New `oidc.py` + `routers/sso.py`;
  the login page shows a "Sign in with SSO" button when configured and
  completes the callback. **Entirely opt-in** - no `OIDC_ISSUER` means the
  endpoints report "not configured" and email+password is unaffected. Tests
  mint a local RSA key and prove signature verification, claim checks, signed
  state, role mapping and the domain allowlist (170 backend tests green;
  frontend builds clean). Remaining for full enterprise SSO: SAML + SCIM
  deprovisioning.

- **2026-06-14 · Stripe self-serve billing (Tier 1, opt-in).** Layered onto the
  existing signed-license-key system so enforcement is unchanged: a completed
  Stripe Checkout **mints the plan's license key and stores it**, and the
  seat/connector limits in `licensing.py` just work. New `billing.py`
  (Stripe REST over httpx - no SDK dependency; stdlib-HMAC webhook
  verification) + `routers/billing.py` (`/billing/status|checkout|portal|
  webhook`). The webhook is unauthenticated but every event is
  signature-verified before it can touch the plan; cancellation reverts the
  minted key. **Entirely opt-in** - with no `STRIPE_SECRET_KEY` the endpoints
  return "not configured" and the config Billing card falls back to license-key
  activation, so the default install and demo are untouched. Frontend Billing
  card (plan, upgrade buttons -> Checkout, manage -> portal, post-redirect
  status). Tests: honest degradation + webhook activation/revert + bad-signature
  rejection (165 backend tests green; frontend builds clean).

- **2026-06-13 · E2E (Playwright) suite green in CI (Tier 1).** The suite had
  failed on *every* run since it was added (the workflow existed but nothing
  made it pass). Root-caused and fixed, iterating against CI: (a) the API was
  booted in a separate step and reaped before the tests ran - boot it in the
  same step so it stays up (this alone took it 34-fail → 28-pass); (b)
  `trailingSlash: true` meant the app lands on `/dashboard/` but `login()`
  waited for the glob `**/dashboard` - match a trailing-slash regex; (c) the
  SIEM/CTI specs asserted Power-mode text while the suite runs in default
  Normal mode - assert the real "Acknowledge/Dismiss" and "Tracked
  Actors"/IOC UI; (d) a `fill()`-vs-React race left the submit button disabled
  - type with `pressSequentially`; (e) the bad-credentials test now asserts an
  accessible `role="alert"` (also a real a11y win) instead of brittle error
  wording, and CI disables the login throttle so the suite's many logins can't
  trip it. Result: **34 passing** across desktop-chromium + mobile-safari
  (~1.6 min, was a 19-min wall of failures).

- **2026-06-13 · Validated the Postgres backend against a live server + CI gate
  (Tier 1).** Ran the full dashboard test suite against a real Postgres 16
  (`DASHBOARD_DB_BACKEND=postgres`) and fixed the dialect gaps the live run
  surfaced - all centralised in the `db_backend` translation seam so SQLite is
  untouched: (a) SQLite's 64-bit `INTEGER` → Postgres `BIGINT` (32-bit
  `INTEGER` overflowed on stored counts/uptime); (b) scalar `MIN(n,…)`/`MAX(n,…)`
  → `LEAST`/`GREATEST` (Postgres has no 2-arg min/max); (c) comment-aware
  statement splitting (a `;` inside a schema `--` comment broke `executescript`);
  (d) `Decimal` (psycopg's type for `AVG`/`NUMERIC`) normalised to `float` in
  the row adapter so results match SQLite and stay JSON-serialisable; (e) the
  one camelCase SQL alias quoted so Postgres preserves its case; plus a
  case-insensitive `PgRow`. Added **`.github/workflows/tests.yml`** which runs
  all backend suites (previously **none** ran in CI) and the dashboard suite
  against a Postgres **service container** every push/PR, so the staged path
  can't silently rot. Result: **161 passed on SQLite**, **159 passed + 2
  SQLite-only skipped on Postgres**.
- **2026-06-13 · Live attack map -> real choropleth** (user-requested). Replaced
  the point-marker map with a true country-area choropleth: real country
  polygons (world-atlas TopoJSON rendered with d3-geo's Natural Earth
  projection, bundled in-package - no network), each country **filled by its
  attack count** on a cold->hot scale, **hovering highlights the whole country
  area** (brightened fill + white outline) with a tooltip, and a
  **Countries / Continents toggle** that re-buckets and recolours by continent.
  The join is reliable: `/overview/geo` now emits the ISO-2 code, mapped to the
  polygons' ISO-numeric ids via a compact build-time-generated `countryMeta`
  (so the heavy `world-countries` stays a dev dependency). Added a colour
  legend, flag-tagged top-origins panel with bidirectional hover, and **made
  the map much larger** (full-width-ish, 480px). Frontend builds clean; 161
  backend tests green.
- **2026-06-13 · Reports: meaningful synthesis + a real "Overall" report**
  (user-requested). The exported reports no longer dump rows "as is". (a) The
  **Asset Risk & Vulnerability Report** now synthesises the real scanner
  findings (`vuln_findings`): headline (assets, distinct CVEs, actively
  exploited, avg patch age), a narrative that calls out CISA-KEV / public-
  exploit CVEs and how many assets they hit, breakdowns (open CVEs by severity,
  assets by criticality, most-affected assets), and a **prioritised CVE list**
  ordered by real-world exploitability (KEV → public exploit → CVSS → blast
  radius) with CVSS / flags / affected-assets / fix version per CVE - the same
  "turn raw data into meaning" treatment we give IOCs. (b) The **Overall
  Security Report** (renamed from "Executive Summary", surfaced on the
  dashboard) is now a true cross-domain consolidation: one narrative over SIEM
  / SOAR / CTI / vulns / dark-web, multi-domain breakdowns, the most urgent
  findings from every area, and a single de-duplicated priority action list
  (patch KEV first, reset leaked creds, triage criticals…). Backend-only
  (`reports.py`); the generic renderer needed no change. 161 tests green.
- **2026-06-13 · Security hardening pass (audit-driven)** - a full defensive
  audit (SQLi/LFI/SSRF/XSS/IDOR/authz/crypto/DoS) found and fixed real gaps,
  choosing fixes that harden production without breaking the local/demo start.
  (a) **SSRF guard** (`net_guard.py`) on every user-supplied outbound URL -
  webhooks, custom connectors, personal Slack - rejecting the local host and
  private/link-local/reserved ranges (incl. `169.254.169.254`); http(s)-only;
  `DASHBOARD_ALLOW_PRIVATE_URLS` escape hatch for local dev. (b) **No shared
  default secrets**: `DASHBOARD_JWT_SECRET`, when unset, is auto-generated and
  persisted per-install (never the old `dev-insecure` default) so an attacker
  can't forge tokens with a known key; `DASHBOARD_REQUIRE_SECRETS` /
  `DASHBOARD_ENV=production` make explicit secrets + a non-default admin
  password mandatory (fail-fast). (c) **CORS** wildcard refused while
  credentials are enabled. (d) **PBKDF2** 260k → 600k (OWASP/NIST 2023+) with
  self-describing hashes so the cost rises without breaking existing logins.
  (e) **Constant-time** API-key comparison on the Threat API. (f) **IDOR**:
  id-addressed detail reads (`/cti/actors|iocs/{id}`, `/soar/cases/{id}`) are
  now org-scoped under multi-tenancy (`tenancy.cross_org`). (g) **XSS**: the
  log-report HTML now escapes user-controlled fields (source_ip, username,
  detector, finding_type). (h) name length cap on registration; `.jwt_secret`
  git-ignored. New `test_net_guard.py`; 161 dashboard tests green (+ threat/log
  suites), OWASP Top-10 alignment refreshed in SECURITY.md.
- **2026-06-13 · Appearance: 11 themes + in-depth customization, plus 3 UI
  fixes** (user-requested batch). (a) **Appearance panel** (config →
  Appearance): five new palettes (nebula, oceanic, cyber, slate, ember →
  **11 total**); a **custom accent** (12 presets + native hex picker) that
  overrides the active theme's primary across the whole dashboard via an
  inline `--magenta` RGB-triplet override; **UI scale** 90-110% and
  **Comfortable / Compact density** both applied through the document's rem
  baseline by `ThemeScope` (a genuine zoom / density change, not a cosmetic
  flag - restored on leaving the dashboard); and a **Reduced-motion** toggle
  that stops animations/transitions. All four prefs persist per-browser
  (`to-dashboard-prefs`) and sync across open tabs, scoped to the dashboard
  so the marketing site is untouched. Retired the old decorative no-op
  toggles (Dark Mode / Compact View / Animated Effects / Auto-refresh) now
  that real controls exist. (b) **Monochrome contrast** - solid accent
  buttons forced dark text (white-on-white fixed); faint tints untouched.
  (c) **Hero/orbit scroll flicker** - the 3D scenes mounted the `<Canvas>`
  conditionally, so a sudden scroll tore down and rebuilt the WebGL context
  (a blank frame); they now mount once and stay alive, pausing the render
  loop (`frameloop: demand`) off-screen. (d) **Logo** - flat hex replaced
  with a faceted, beveled 3D gem (lit/shaded half-faces, specular crown,
  cast shadow, glow bloom behind the core). Frontend builds + type-checks
  clean.
- **2026-06-13 · Dashboard assistant + map rehaul + top-actors fix + dash sweep**
  (user-requested batch). (a) **Security-bounded AI assistant**
  (`dashboard_api/assistant.py`, `/assistant/chat|status`, floating
  `AssistantWidget`): answers/reviews/recommends/redirects over a fixed
  registry of READ-only tools executed as the caller, no secrets ever
  selected, tool output treated as untrusted data (prompt-injection
  contained), navigation proposed not executed, bounded loop, per-user rate
  limit, audited. Anthropic Messages API over httpx (model `claude-opus-4-8`,
  `ANTHROPIC_API_KEY`); honest-degrades to a deterministic intent router over
  the same tools when no key. (b) **Top Threat Actors** fixed in live mode via
  the curated `threat_actor_library` + real attributed-indicator ranking. (c)
  **Live attack map** rewritten (752→~330 lines) on real `/overview/geo` data:
  top-countries panel, bidirectional hover, smooth animations, honest empty
  states. (d) Replaced all long dashes (em/en) with hyphens across the
  frontend + backend app code. Tests cover the assistant's basic mode, the
  secrets-never-leak guarantee, and the agentic tool-loop (147 backend tests
  green; frontend build clean).
- **2026-06-13 · Fix combined-install conflict (build)** - the security-pass
  backend bump (fastapi 0.118+/python-multipart 0.0.27+) left `log_api`
  pinned to the old `fastapi==0.115.0` / `python-multipart==0.0.9`. The
  Windows bats (`windows-start.bat`, `windows-test.bat`) install all three
  services' requirements in one `pip install`, so the divergence produced a
  hard `ResolutionImpossible` and both bats died at the install step before
  any test/app ran. Aligned `log_api`'s shared pins with `dashboard_api`
  (same FastAPI/uvicorn/python-multipart stack, same upload-DoS fix - its
  tests already pass on the new versions). Combined install now resolves;
  all three suites green (143 + 1 + 1); frontend builds + type-checks clean.
- **2026-06-12 · Security pass: audits in CI + patched deps + disclosure
  (Tier 1)** - `.github/workflows/security.yml` runs pip-audit (strict) and
  a frontend audit gate on every change plus weekly. The npm gate
  (`frontend/scripts/audit-gate.mjs`) implements triage-with-expiry: any
  untriaged high/critical fails, and so does any allowlist entry past its
  expiry - the 14 Next.js *server* advisories are consciously accepted until
  2026-09-30 because production deploys the static export (no Next server);
  the real fix is the tracked next@16 major. Running the audit for real
  found and fixed backend exposure: python-multipart 0.0.9 → ≥0.0.27 (upload
  parsing DoS - this API accepts uploads), fastapi 0.115 → 0.129 +
  starlette 0.52, cryptography ≥46.0.7, with the full 143-test suite green
  on the new set; starlette's PYSEC-2026-161 (fix needs starlette 1.x, no
  FastAPI supports it yet) is triaged in-workflow with the mitigation
  documented. SECURITY.md ships the disclosure policy + honest triage table,
  explicitly stating the pentest has NOT happened yet.
- **2026-06-12 · Deployment hardening (Tier 1)** - a
  SecurityHeadersMiddleware stamps nosniff / DENY-framing / no-referrer /
  no-store on every API response including errors (tested); the API
  Dockerfile drops to an unprivileged `app` user (uid 10001) with only the
  `/data` volume writable (registry rate-limits block a local build-verify -
  standard pattern, verify at deploy); and `docs/DEPLOYMENT.md` ships the
  topology (TLS at the proxy, app ports internal-only), nginx and Caddy
  reference configs (HSTS, frontend CSP for the static export, SSE-safe
  proxy settings, upload size), the env checklist that should fail a deploy
  when unset, compose hardening, digest pinning, and an honest "what the
  platform refuses to pretend about" section (no app-level TLS, /metrics
  gating, plain-UDP syslog until Tier-2 RFC 5425).
- **2026-06-12 · Observability baseline (Tier 1)** -
  `dashboard_api/observability.py`, stdlib-only: a pure-ASGI middleware
  records every request under its resolved route TEMPLATE (so
  `/siem/alerts/{alert_id}` is one series, ids never leak into label
  cardinality) with latency sums; engine loop and ingest feed domain
  counters (ticks, tick failures, events, alerts, unhandled errors);
  `/metrics` renders Prometheus text exposition plus on-scrape row-count
  gauges for core tables, optionally gated by `DASHBOARD_METRICS_TOKEN`.
  `DASHBOARD_LOG_FORMAT=json` flips root logging to one-line JSON records;
  `SENTRY_DSN` initialises sentry-sdk when installed and says so when it
  isn't. Documented in docs/OPERATIONS.md; tests cover the exposition
  content, template aggregation, token gating, and the JSON formatter
  (142 passed).
- **2026-06-12 · Backup/restore/upgrade (Tier 1)** - `dashboard_api/ops.py`
  takes transactionally consistent SQLite snapshots with the online-backup
  API (never a raw file copy under WAL) and integrity-verifies them
  (PRAGMA integrity_check + core-table counts). `GET /config/backup`
  (admin, audited) streams a verified snapshot; the CLI
  (`python -m dashboard_api.ops backup|verify`) is cron-able; Postgres
  deployments are pointed at pg_dump and the endpoint refuses there.
  `docs/OPERATIONS.md` documents the offline restore drill, the
  additive-only upgrade/rollback contract, and key management - including
  that backups carry `enc:v1:` credentials and are only complete together
  with `DASHBOARD_ENCRYPTION_KEY`. 141 passed.
- **2026-06-12 · Real TOTP MFA (Tier 1)** - `dashboard_api/mfa.py` implements
  RFC 6238 with the stdlib (proven against the RFC's SHA-1 test vectors).
  Flow: `/auth/mfa/enroll` generates a 160-bit secret (returned once with
  the otpauth:// URI; stored Fernet-encrypted), `/auth/mfa/verify` proves
  the authenticator works before switching MFA on, login then requires the
  code (password verified first so it's no enumeration oracle; wrong codes
  count against the login throttle; ±1-step skew window), and
  `/auth/mfa/disable` demands a valid current code so a hijacked session
  can't strip the factor. Admins can only reset MFA off (clears the secret)
  - never enable it for someone. The login page gains the step-up code
  field; Config → Security gains an enrol/verify/disable panel; the dead
  "Enforce MFA" toggle and the backend-less OIDC/SAML dropdown options are
  removed per the data-honesty rule. The login response also stops leaking
  slack_webhook/mfa_secret via `_public`. 140 passed.
- **2026-06-12 · Secrets at rest (Tier 1)** - `dashboard_api/secretstore.py`
  Fernet-encrypts every DB-stored credential (connectors.api_key,
  integrations.api_key, users.slack_webhook) as `enc:v1:<token>` under
  `DASHBOARD_ENCRYPTION_KEY` (falls back to the JWT secret; the
  rotate-without-pinning caveat is documented and a failed decrypt reads
  back empty so features degrade to not-configured, never sending corrupt
  credentials). Encryption happens on every write path; decryption only at
  the four points of use (connector runner, integration action runner, Slack
  fan-out, owner's GET /auth/me/slack). `encrypt_existing` upgrades legacy
  plaintext rows on boot. `cryptography` pinned in requirements. Tests cover
  round-trip/idempotence/legacy passthrough, encrypted-at-rest assertions
  for all three stores, plaintext at the choke points, the boot migration,
  and the rotated-key degrade path (139 passed).
- **2026-06-12 · Frontend virtualisation (Phase 5)** - a dependency-free
  `useWindowedRows` hook (rAF-coalesced scroll tracking, overscan, spacer
  padding) windows long uniform tables; wired into the SIEM alert queue with
  a 150-row activation threshold so huge queues scroll smoothly while small
  ones render byte-for-byte as before (row stagger animation disabled only
  when windowed). Remaining Phase 5 items are environment-gated and
  documented as such: Stripe self-serve purchase (needs a processor
  account), live-Postgres validation, and the CI-executed E2E/mobile runs.
- **2026-06-12 · Attack-surface panel (Phase 4 closed)** - the assets page
  gains an AttackSurfacePanel over the live `/assets/exposure` +
  `/assets/discovered` APIs: the internet-facing inventory with per-asset
  exposure bands and contributing factors (hover for weights) and summary
  KPIs (facing/critical/avg/top driver), plus passively discovered unmanaged
  hosts (events/alerts/last-seen from real telemetry) with one-click
  promotion into the managed inventory (refreshing the asset list). Active
  probing is documented as deliberately out of scope (passive only).
- **2026-06-12 · NVD catalogue sync (Phase 4)** - the NVD connector now feeds
  the vulnerability scanner: `nvd_to_catalogue` parses NVD 2.0
  `configurations` CPE matches (versionStart/End incl/excl + exact-version
  CPEs; applications only; unbounded rows skipped as unscannable) into a new
  `cve_catalogue` table (upsert keyed cve+product), and `scan_asset` merges
  the synced rows with the built-in catalogue (per-product lists concatenate)
  - so live NVD imports flow straight into asset scanning. The scanner gains
  a `bounds` matcher for NVD's inclusive/exclusive range semantics. Also
  corrected the module docstring, which previously claimed an IOC-store
  augmentation that was never wired. End-to-end test: connector run → synced
  row → affected version flags CVE-2026-12345, fixed version doesn't.
- **2026-06-12 · Intel report authoring panel (Phase 3 closed)** - the CTI
  hub gains an IntelReportsPanel over the existing `/cti/reports` store:
  draft authoring (title, TLP marking, executive summary, full body, tags),
  status filtering, one-click publish/unpublish, expandable reading view
  with author/actor/IOC metadata, per-report MISP-event download (new
  `exportIntelReportMisp` client), and delete with optimistic rollback.
- **2026-06-12 · Live enrichment providers (Phase 3)** - with an API key in
  the environment, the external enrichers now perform the real lookup:
  VirusTotal v3 (`last_analysis_stats` → X/N engines verdict, URL ids
  base64url-encoded), GreyNoise community (scanner classification), Shodan
  host (open ports + known vulns ⇒ suspicious), and WHOIS (registration age;
  <30 days ⇒ suspicious). Type gating is honest (GreyNoise/Shodan IPs only,
  WHOIS domains only), 404s map to "not seen", and any network/HTTP failure
  reports `available:false, lookup failed` - never a fabricated verdict.
  Unit-proven against canned provider payloads and a connection-error path.
- **2026-06-12 · Integration credential entry (Phase 2 closed)** - new
  `PATCH /soar/integrations/{id}` sets/clears the vendor base URL + API key
  (write-only; every payload exposes only `credentialed`) and persists the
  enable toggle. The integrations page gains a per-tool credentials form
  (save/clear, configured badge), live-API/no-credentials badges on cards,
  a previously local-only enable toggle that now persists (optimistic with
  rollback), and optional base URL/key fields on Connect Tool. Also fixed a
  real credential leak: the test-connection endpoint returned the raw row
  including `api_key` - now sanitised.
- **2026-06-12 · Search joins across sources (Phase 1 fully closed)** - the
  hunt language gains `| join <field> <subquery>`: keep left-side rows whose
  field value also appears in the subquery's matches over the same window
  (e.g. `event_type=login_success | join src_ip event_type=failed_login` -
  successful logins from IPs that also brute-forced). Pipes compose (join
  first, then `| stats count by`), ECS aliases work as the join field, and
  the response's `interpreted.join` reports rightHits/keyCount so the UI can
  show what the correlation did. Example added to the search panel.
- **2026-06-12 · Time-boxed suppression windows (Phase 1 closed)** -
  suppressions can now carry an absolute expiry (`expires_hours` → stamped
  `expires_at`) and/or a recurring daily HH:MM-HH:MM UTC window (overnight
  wrap supported). The engine only honours currently-active entries
  (`rule_engine.suppression_active`); creation retro-closes open alerts only
  when the rule applies right now; the list endpoint computes `active` and
  the SuppressionsPanel gains expiry/window inputs + an active/inactive
  badge. Tests cover the pure window/expiry math and the end-to-end
  behaviour: an out-of-window suppression doesn't drop a brute-force alert,
  an in-window time-boxed one does.
- **2026-06-12 · ECS ingest-time normalization (Phase 1 closed)** - the JSON
  ingest parser now resolves Elastic Common Schema documents - nested Beats
  style (`{"source": {"ip": …}}`) and dotted keys (`"source.ip"`) - into the
  native event columns through the same alias map the query layer uses, so
  ECS logs land fully normalised at write time. Precedence is explicit flat
  keys > ECS fields > raw-line regex heuristics (ECS is authoritative over
  regex guesses; confident content signatures like `failed_login` are kept).
  Also hardened the flat-key mapper to scalars so nested objects can't bind
  as SQL params. Test ingests nested + dotted ECS docs and asserts the
  stored row (src_ip, hostname, dest_port, username, country, action).
- **2026-06-12 · Signed evidence bundles (Phase 0 closed)** - the audit
  pack's last piece: `GET /soar/cases/{id}/evidence-bundle` exports the
  case's full investigation record (case + evidence with per-item SHA-256
  chain-of-custody + war room + tasks + the case's audit-log slice) as
  canonical JSON signed with HMAC-SHA256 (key pinnable via
  `DASHBOARD_EVIDENCE_SECRET`); `POST /soar/evidence/verify` honestly
  re-verifies - one edited byte fails. Case drawer gains "Export signed
  bundle" (downloads the JSON) and the previously dead "Add evidence" button
  now works; live evidence rows show real ts/addedBy/sha256 instead of
  undefined seed-only fields. Exports are audited.
- **2026-06-12 · Per-user Slack routing (Phase 0 closed)** - each user can
  register a personal Slack incoming-webhook URL with a minimum-severity
  floor (GET/PUT `/auth/me/slack` + an honest `/test` send; panel in Config →
  Notifications). Every platform notification at/above the floor is mirrored
  to the user's Slack on the webhook engine's fire-and-forget thread. The URL
  is treated as a quasi-secret - scrubbed from `/auth/me` and all user
  payloads, visible only to its owner via the dedicated endpoint. Tests cover
  the round-trip, threshold filtering, clearing, and the no-leak guarantee.
- **2026-06-12 · Saved views in the page UIs (Phase 0 closed)** - a shared
  `SavedViewsButton` component (list / save-current-filters / apply / delete,
  backed by the per-user `/saved-views` API) now sits in the SIEM queue
  header (q + severity + status + tactic), assets (q + type + criticality),
  dark web (q + category) and feeds (severity). Defaults are stripped before
  saving; applying a view restores the page's filter state.
- **2026-06-12 · RBAC: capability checks everywhere (Phase 0 closed)** - the
  last `require_role` call sites are gone: config → `config.manage`,
  connectors → `connectors.manage`, services → `services.run`, report
  schedules → `reports.manage`, audit export + retention → `config.manage`,
  users → `users.manage`/`users.delete`, IOC decay → `cti.write` (its
  catalogue entry always named decay). Licensing gets its own admin-only
  `license.manage` capability (managers keep config but not license keys).
  Authorisation is now a single matrix in permissions.py; tests assert the
  new admin/manager split and that analysts are denied connectors + license.
- **2026-06-12 · Real SOAR trends (data honesty)** - `/soar/metrics` no longer
  returns fabricated "↓ 12% / ↑ 8%" trend strings: `mttrTrendPct` is the real
  week-over-week movement of average response latency and
  `automationTrendPp` the percentage-point change in playbook-driven closure
  rate, both null when there is no prior-week baseline. The SOAR KPI strip
  renders the real numbers (or "no prior-week baseline"), and the invented
  "≈ $127K analyst time" sub was replaced with the actual run count behind
  the time-saved figure.
- **2026-06-12 · Tenant scoping on aggregates - multi-tenancy complete
  (Phase 0)** - the last seam: every overview rollup (KPIs, threat vectors,
  hourly volume, MITRE heatmap, recent alerts/incidents, top actors, geo,
  live feed) and every section summary (SIEM KPIs, SOAR metrics, CTI summary,
  assets summary + risk distribution, dark web summary, feeds summary) now
  applies the workspace scope via the tested `tenancy.scope_sql` helper. The
  isolation test proves flag-on KPI totals exclude exactly the foreign-org
  rows. With reads, writes and aggregates wired, the multi-tenancy roadmap
  item is closed (131-test suite green, flag off by default).
- **2026-06-12 · Tenant write stamping (Phase 0)** - every user-driven create
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
- **2026-06-12 · Tenant read isolation: all TENANT_TABLES (Phase 0)** - the
  rollout completes the read side: defaulted `org_id` migrations on the 13
  remaining tables (events, threat_actors, log_sources, feeds, connectors,
  playbooks, playbook_runs, saved_hunts, scans, suppressions, notifications,
  saved_views, report_schedules) and the workspace clause on every list
  endpoint that serves them (12 endpoints across siem/cti/soar/feeds/
  connectors/platform). The isolation test adds playbooks as the secondary-
  store representative; tenancy.py docs updated from "staged" to "wired, off
  by default". Defaults unchanged (130-test suite green with the flag off).
- **2026-06-12 · Tenant isolation: assets + dark web + rules (Phase 0)** - the
  rollout reaches all six primary stores: defaulted `org_id` migrations on
  `assets`, `dark_web_findings` and `detection_rules`, and the 3-line
  `tenancy.enforced()` workspace clause on `GET /assets`,
  `GET /darkweb/findings` and `GET /siem/rules`. The isolation test now also
  inserts two-workspace assets and proves they vanish/reappear with the flag;
  defaults remain byte-for-byte unchanged (130-test suite green).
- **2026-06-12 · Tenant isolation: cases + iocs (Phase 0)** - the alerts
  reference pattern applied to the next two primary stores: defaulted
  `org_id` migrations on `cases` and `iocs`, and the 3-line
  `tenancy.enforced()` workspace clause on `GET /soar/cases` and
  `GET /cti/iocs`. The isolation test now proves all three: with
  `DASHBOARD_MULTI_TENANT` on, a foreign workspace's alerts, cases and IOCs
  all disappear from the caller's views; with it off (default), behaviour is
  byte-for-byte unchanged (full 130-test suite green).

- **2026-06-12 · Tenant isolation reference pattern (Phase 0)** - the breaking
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

- **2026-06-12 · Postgres adapter (Phase 5)** - the staged flip is now
  implemented, still opt-in and zero-impact by default. `PgConnection` adapts
  psycopg to the sqlite3-ish interface every call site already uses: `execute`/
  `executemany` translate each statement through the tested `to_postgres`
  dialect layer (PRAGMAs become no-ops), `executescript` splits statements
  string-literal-safely, and `PgRow` supports BOTH `row["col"]` and `row[0]`
  access so `row_to_dict`/positional reads work unchanged. `_apply_migrations`
  is backend-aware (`information_schema.columns` instead of PRAGMA on
  Postgres). The SQLite default path is byte-for-byte untouched - the full
  129-test suite proves it. Honest remaining step: validation against a live
  Postgres server (unreachable from this environment) before any cutover.

- **2026-06-10 · UEBA learned baselines (Phase 1)** - entity risk gains
  deviation-from-self anomaly scoring: `_entity_baseline` computes each entity's
  own daily-alert-volume norm (mean + population stddev over its prior days) and
  the latest day's z-score, flagging `deviating` at z≥2 with a confidence band
  from the history length - real behavioural-baseline anomaly detection, not
  just raw volume. Surfaced in the Entity Risk drawer (today vs norm, z-score,
  deviating/normal badge). Tested: insufficient-history guard, a spike over a
  steady baseline flags deviating, a normal day does not.

- **2026-06-10 · Syslog UDP listener + file/dir watcher (Phase 1, closes log
  ingestion)** - `log_listeners.py`: a long-running syslog UDP listener
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

- **2026-06-10 · SMTP email delivery channel (Phase 0)** - scheduled reports can
  now be emailed, not just webhooked. `mailer.py` sends a real MIME multipart
  email via SMTP when the deployment provides settings (SMTP_HOST/PORT/USER/
  PASSWORD/FROM/TLS), and honestly reports `not-configured` otherwise - never
  raises (a mail failure can't break a request or the engine tick). Report
  schedules gained an `email` target (`run` delivers the report's summary +
  findings as HTML); `GET /config/email` shows readiness and
  `POST /config/email/test` sends a test (admin/manager). Frontend clients +
  the schedule email field shipped. Tested: not-configured default, configured
  send (mocked smtplib asserts host/recipient/body), report-schedule email
  delivery, RBAC.

- **2026-06-10 · Scheduled hunts → alerts (Phase 1)** - a saved hunt becomes a
  detection over time. `POST /siem/hunts/{id}/schedule` sets an interval
  (+ auto_alert); `run_due_scheduled_hunts` (engine tick + `POST
  /siem/hunts/run-scheduled`) runs each due hunt's query through the
  event-stream search and, on hits, raises a SIEM alert ("Scheduled hunt
  matched …", rule R-HUNT) carrying the matched entity/technique, then stamps
  `last_scheduled` so it's throttled to its interval. saved_hunts gains
  schedule_minutes / last_scheduled / auto_alert. Tested: schedule → run →
  alert raised, throttle (second immediate run does nothing), off, range
  validation, 404, viewer-blocked.

- **2026-06-10 · TAXII 2.1 write/push (Phase 3, closes STIX/TAXII)** - the TAXII
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
  (Phase 2, closes case depth)** - `POST /soar/cases/{id}/evidence` attaches an
  evidence item with **tamper-evident chain-of-custody** (SHA-256 of the
  content + a custody log of who collected it, when). `…/link` relates two
  cases (related|duplicate, recorded on both sides). `…/merge` folds a source
  case into the target (dedup-combines entities, concatenates war-room +
  evidence, sums alert counts, closes the source as a duplicate with a
  system note). `…/split` spins selected entities off into a linked child
  case. `cases.linked_cases` column (migrated). Frontend clients shipped.
  Tested: evidence sha256 + custody, two-sided link, split parent/child links,
  merge (entities combined, alerts summed, source closed, note), 400/404/RBAC.

- **2026-06-10 · Real SOAR action integrations + action trail (Phase 2)** -
  response actions actually call vendor APIs. `integration_actions.py` builds
  the real request per category (EDR→CrowdStrike `devices-actions` contain,
  firewall→`/api/blocklist` deny, identity→IdP suspend, ticketing→Jira issue,
  else generic webhook POST) and, when the integration has a `base_url` +
  `api_key` configured, performs the live outbound httpx call (short timeout,
  failures recorded never crash) - otherwise records a `not-configured` action
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

- **2026-06-10 · Visual playbook builder + versioning (Phase 2)** - a real
  authoring canvas over the (already-real) execution engine. `PlaybookBuilder`:
  a step-kind palette (`GET /soar/step-kinds` - the 11 executable kinds with
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

- **2026-06-10 · E2E suite + responsive contract (Phase 5)** - a real Playwright
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

- **2026-06-10 · Postgres backend foundation (Phase 5)** - the seam to scale
  past single-file SQLite, shipped non-breaking. `db_backend.py`: backend
  selection (`DASHBOARD_DB_BACKEND`, default `sqlite`; `DATABASE_URL`), a guarded
  Postgres connection path (lazy psycopg import with a clear error; only taken
  when explicitly selected - SQLite installs are byte-for-byte unchanged), and
  a **pure, unit-tested SQLite→Postgres dialect translator** (`to_postgres`):
  `?`→`%s` placeholders (string-literal-aware), `INSERT OR REPLACE`→
  `INSERT … ON CONFLICT … DO UPDATE` (rewritten after the VALUES list),
  `AUTOINCREMENT`→`BIGSERIAL`, `datetime('now')`→`now()`, `PRAGMA` stripped.
  `GET /config/database` reports the active backend + psycopg readiness. The
  breaking flip (wiring the translator into every execute + a row-dict factory)
  is staged behind the flag so it lands reviewably on its own - `main` stays
  green. Frontend: a Storage card on Config → General. Tested: translation
  units (placeholders/idioms/upsert) + the backend endpoint + RBAC.

- **2026-06-10 · Data-layer performance (Phase 5)** - hot-path indexes for the
  queries every dashboard refresh runs: alerts (ts, severity+status, hostname,
  src_ip, username), iocs (value - the per-event TI match, status, actor),
  playbook_runs (alert_id, playbook+ts), vuln_findings (asset_id), dark-web
  (url dedupe, category), sightings/enrichments, audit action, events
  hostname. Verified with EXPLAIN QUERY PLAN that SQLite actually uses them
  (tests assert the plan). `init_db` gained a safe upgrade path: schema →
  migrations → schema again, so indexes on migrated columns apply cleanly to
  old databases (covered by an upgrade-path smoke test on a pre-migration DB).

- **2026-06-10 · Licensing & plan limits (Phase 5)** - the pricing tiers become
  real. `licensing.py`: license keys are base64url JSON payloads (plan, seats,
  connectors, expires, org) **HMAC-SHA256-signed** with
  `DASHBOARD_LICENSE_SECRET`, so they can't be forged or tampered with;
  expired/forged keys are rejected at activation AND at resolution (a stored
  key that goes invalid falls back safely). Default is a built-in enterprise
  license (unlimited) so existing installs lose nothing. Enforcement is
  server-side: adding a user or connector beyond the active plan's limit fails
  with **402** naming the limit. Endpoints: `GET /config/license` (plan,
  limits, live usage), `POST /config/license/activate`,
  `POST /config/license/issue` (vendor side - a self-hosted operator mints
  keys for their tenants; admin-only), `DELETE /config/license`. Frontend:
  License card on Config → General (plan, seat/connector usage bars, key
  activation). Tested: sign/verify/tamper/expiry units + the full
  activate→402-block→clear→restore flow + RBAC.

- **2026-06-10 · Onboarding wizard (Phase 5)** - `GET /config/onboarding`
  computes the first-run checklist from REAL platform state (a step is done
  only when the thing actually exists - org named, bootstrap admin password
  rotated (verified against the hash), 2+ users, an enabled connector, a log
  source with events flowing, enabled detection rules, a delivery webhook, a
  generated report), so the wizard can never drift from reality;
  `POST /config/onboarding/dismiss` persists dismissal. The overview shows an
  OnboardingCard (progress bar, next undone steps deep-linked) that hides once
  complete or dismissed. Tested: state-derived steps, the report step flipping
  after a real generation, dismiss persistence.

- **2026-06-10 · Dark-web depth (Phase 4, closes Phase 4)** -
  `darkweb_logic.py` + connector/router wiring. (1) **Credential matching**:
  credential-leak findings are checked against the *real* user directory -
  exact email or org-domain match stamps `matched_user`, escalates to critical
  and raises a force-reset notification; runs on engine ticks, on feed import,
  and on demand (`POST /darkweb/match-credentials`). (2) **Takedown workflow**:
  `POST /darkweb/findings/{id}/takedown` stamps the request (status
  `takedown-requested`, audit note) and emits a `darkweb.takedown` webhook for
  external takedown/ticketing services; new status in the lifecycle + a
  Request-takedown button in the finding drawer; summary gains
  workforceMatches/takedownsRequested. (3) **Real source connectors**: new
  `darkweb-json` connector kind - any leak-DB / paste-site / breach-monitor
  API returning JSON maps (field-mapped) into findings, deduped by URL, with
  credential matching on the way in; darkweb mutations now require
  darkweb.write. Tested: directory match + escalation + notification, takedown
  flow + 404/403, feed connector import/dedupe/workforce-match.
  **Phase 4 (Asset, Vuln & Dark Web depth) is now complete.**

- **2026-06-10 · Asset ↔ alert ↔ case linkage (Phase 4)** - one click from a
  host to all its activity. `GET /assets/{id}/activity` joins everything tied
  to the asset's name/value: its alerts (with MITRE + status), the cases whose
  entities reference it, recent raw events, open CVE findings, and the playbook
  runs that responded - with a summary rollup. The asset drawer gained a
  “Linked activity” section (CVE findings with CVSS, alerts deep-linking into
  the SIEM queue, cases linking to SOAR). Also replaced the assets page's fake
  random “Re-scan” simulator with the real vulnerability scanner
  (scan → reload real risk/findings; restores status honestly on API failure).
  Tested: ingest + scan + case → all linked through one call, 404 guard.

- **2026-06-10 · Attack-surface discovery (Phase 4)** - `attack_surface.py`.
  **Passive discovery**: hosts emitting telemetry that are NOT in the asset
  inventory (shadow IT) surface as vetted candidates with their observed
  activity (event/alert counts, first/last seen, sample line);
  `POST /assets/discovered/promote` registers one into the inventory (tagged
  `discovered`, 409 on duplicates, assets.write). **Exposure scoring**: a
  transparent, factor-weighted score per asset - public IP/domain,
  internet-facing tag, risky listening ports (RDP/Telnet/SMB/databases/
  plaintext HTTP), and open critical/high CVEs on the exposed surface - with
  the factors returned alongside the score so it's explainable;
  `GET /assets/exposure` ranks the fleet and summarises (internet-facing
  count, critical exposure, top factor). Frontend clients shipped. Tested:
  scoring units (weights, ordering, cap, public-IP detection) + the
  discover→promote lifecycle (telemetry host found, promoted, vanishes from
  candidates, 409/400/403 guards).

- **2026-06-10 · Real vulnerability scanning (Phase 4)** - assets carry CVE
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

- **2026-06-10 · Actor attribution scoring (Phase 3, closes Phase 3)** -
  `attribution.py` scores which tracked actor observed activity maps to, with
  transparent weighted evidence: IOC overlap (strongest - an indicator already
  attributed to the actor), then malware, ATT&CK technique (base-id matched so
  T1059==T1059.001), targeted sector, and origin. Scores normalise 0-100
  against the top candidate; confidence bands reflect corroboration across
  independent signal types. `POST /cti/attribution` (techniques/iocs/malware/
  sectors/origin) and `GET /cti/attribution/case/{id}` (pulls a case's linked
  alert techniques + entity indicators and attributes it). Frontend clients
  shipped. Tested: pure scoring/weighting/normalisation/confidence units +
  the API (decisive IOC match → 100/high, technique evidence, case
  attribution, 400/404 guards). **Phase 3 (CTI depth) is now complete.**

- **2026-06-10 · Campaign & report management + MISP interop (Phase 3)** -
  analyst-authored CTI reports and community sharing. New `intel_reports` store
  + `/cti/reports` CRUD (title, TLP, draft→published, actor/IOC references,
  tags; cti.write-gated). `misp.py` does real MISP **Event** interop: export
  the IOC store, a single report's indicators, or import an Event -
  `to_misp_event` maps each indicator to the correct MISP attribute type +
  category (ip-dst, domain, md5/sha1/sha256, vulnerability…) with a TLP tag and
  `to_ids` from severity; `parse_misp_event` maps attributes back to indicators
  (composite types handled, unknown types skipped not guessed) and imports them
  with a per-attribute tally. Endpoints: `/cti/reports/{id}/misp`,
  `/cti/misp/export`, `/cti/misp/import`. Frontend clients shipped (report CRUD
  + MISP import/export). Tested: MISP round-trip units + report CRUD + export +
  import tally + viewer-blocked.

- **2026-06-10 · IOC enrichment pipeline (Phase 3)** - pluggable enrichers with
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

- **2026-06-10 · CTI relationship graph at scale (Phase 3)** - the intelligence
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

- **2026-06-10 · Multi-tenancy foundation (Phase 0)** - the org/workspace model,
  shipped non-breaking. New `orgs` table + `users.org_id` (migrated); a
  bootstrapped default workspace that every existing/seeded user joins, so
  single-tenant installs are unchanged. The authenticated principal carries
  `org_id` (defaulted when unset); `/orgs/current` shows the caller's workspace
  (+ member count + isolation status), `/orgs` CRUD lets an admin stand up
  tenants (config.manage). The *breaking* half - isolating every data table by
  org_id - is **staged, not enforced**: `dashboard_api/tenancy.py` holds the
  pure, unit-tested seam (`scope_sql`, `org_of`, `TENANT_TABLES` checklist)
  gated behind `DASHBOARD_MULTI_TENANT` (default off), so it can be wired into
  queries table-by-table later without touching this foundation - `main` stays
  green. Frontend: a Workspace card on Config → General. Tested: workspace
  lifecycle, membership inheritance, viewer can't manage the directory, and the
  scope helper no-ops off / scopes on.

- **2026-06-10 · RBAC depth (Phase 0)** - authorization is now a capability
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
  (`can('siem.write')`) gates write controls - e.g. the Rules page hides New
  Rule / Import Sigma for viewers. Tested: matrix introspection + viewer-blocked
  / analyst-allowed across SIEM/SOAR/CTI with audited denials.

- **2026-06-10 · Real-time push / SSE (Phase 0)** - the dashboard updates
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

- **2026-06-10 · STIX 2.1 / TAXII 2.1 server (Phase 3)** - ThreatOrbit is now a
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

- **2026-06-10 · IOC lifecycle (Phase 3)** - threat indicators now age like real
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

- **2026-06-10 · Sigma rule import/export (Phase 1 close-out)** - community
  detection content ports in: `POST /siem/rules/import-sigma` parses Sigma
  YAML (selections + field modifiers |contains/|re/|cidr/|gt…/|startswith,
  lists → `in`, and/or conditions, `count() by` aggregation → threshold rule,
  level → severity, attack.* tags → MITRE) into a live, evaluable rule -
  field names resolve through a Sigma map + the ECS alias layer, unmappable
  fields degrade to raw-contains with explicit import notes; unsupported
  grammar (`not`/`1 of`/grouping) is rejected with a clear error, never
  silently weakened. `GET /siem/rules/{id}/sigma` exports: original YAML for
  Sigma-imported rules, generated Sigma for native ones (round-trips, incl.
  aggregation). UI: “Import Sigma” modal on SIEM → Rules + “Export Sigma”
  download in the rule panel. Tested incl. detection firing on live ingest.

- **2026-06-10 · Case depth: SLA tracking, linked evidence, post-incident
  reports (Phase 2)** - every case read now carries computed SLA state
  (deadline, % elapsed, within / at-risk / breached for open, met / breached
  for closed; `slaBreached` in SOAR metrics). `/soar/cases/{id}/related` links
  the case to its real evidence through its entities: matching alerts, IOC
  records, and the playbook runs that responded, plus a MITRE-mapped merged
  timeline (war room + alert + response activity) and a technique frequency
  list - shown as a “Linked evidence” section in the case drawer with deep
  links into the SIEM. Post-incident reporting: `GET /reports/incident?case_id`
  assembles the full report (severity/alerts/actions/SLA-verdict headline,
  narrative, severity + technique breakdowns, chronological findings,
  conditional lessons-learned recommendations) rendered in the standard
  print/PDF report viewer via a “Report” button on the case (period selector
  hidden for case-scoped reports).

- **2026-06-10 · SOAR playbook execution engine (Phase 2)** - playbooks now
  actually run. `playbook_engine.py`: 11 executable step kinds that act on the
  real stores - enrich (IOC + alert history), condition gate, block_ip (IOC
  blocklist + firewall-integration action), isolate_host (asset tag + EDR
  action), disable_user (IdP action), create_case (real SOAR case, feeds the
  automation rate), add_note, close_alerts (resolve triggering/same-entity
  alerts), notify, webhook, and approval (human-in-the-loop pause →
  approve/reject resumes/cancels, with notification). Every execution persists
  to `playbook_runs` with a per-step status/detail audit trail; dry-run
  previews all steps with zero writes. Playbook CRUD validates step kinds;
  **automation triggers**: auto playbooks with `trigger_match`
  (severities/techniques/rule) run on matching fresh alerts - once per alert,
  throttled per tick - wired into the live engine. The 8 canonical playbooks
  (shared demo/live) carry real step definitions. Frontend: Run history panel
  on SOAR → Playbooks (live, expandable per-step results, approve/reject
  inline), enable-toggle persisted, run button reports real outcomes. New
  webhook events `playbook.completed`/`playbook.action`. Verified: live boot →
  20 ticks → 40 auto-runs, 41 alerts auto-contained, 33 playbook-opened cases.

- **2026-06-10 · ECS field normalization (Phase 1)** - detection rules and event
  searches are now vendor-neutral. `rule_engine.ECS_ALIASES` + `canonical_field`
  resolve Elastic Common Schema names (source.ip → src_ip, user.name → username,
  destination.port → dest_port, event.action → action, threat.technique.id →
  mitre_tech_id, message → raw, …) to native fields at evaluation time, so rules
  ported from Elastic/Splunk content match unchanged. The search parser
  recognises ECS names (including the `| stats count by` field, grouped on the
  native column) and `/siem/rule-schema` advertises the alias map. Tested:
  alias resolution, ECS-authored conditions/searches, and the schema endpoint.

- **2026-06-10 · Event-stream search language (Phase 1)** - a real, compact
  field-operator query language over the raw `events` stream (what hunting
  actually searches, not just alerts). `POST /siem/search` parses
  `field=value`, `!= > < >= <=`, `~regex`, `:contains`, `field in a,b,c`, bare
  full-text tokens, and a `| stats count by <field>` aggregation; every term
  compiles to the same condition shape `rule_engine.matches_event` evaluates, so
  search and detection stay consistent. New Event-stream search panel on the
  Hunt page (interpreted-as chips, raw-event rows, or grouped-count bars).
  Tested: parser units + the live search/agg/validation path.

- **2026-06-10 · Alert tuning workflow (Phase 1)** - the false-positive feedback
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

- **2026-06-10 · UEBA entity risk (Phase 1)** - `/siem/entities` ranks
  users/hosts/IPs by behavioural risk (severity-weighted alert volume +
  ATT&CK technique diversity, banded normal→critical); `/siem/entities/detail`
  gives a per-entity risk timeline, top techniques, and contributing alerts.
  New Entity Risk page under SIEM with ranking bars + a drill-down panel and
  deep-link into the alert queue. Auto-refreshes.

- **2026-06-10 · Phase 0 platform bundle** - `routers/platform.py` +
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

- **2026-06-10 · Log ingestion + ATT&CK navigator + TI matching (Phase 1)** -
  native log collector (`ingest.py`, `POST /siem/ingest`): parses syslog,
  Apache/Nginx, JSON, and key=value lines into events (content-signature
  inference for event_type/MITRE), then runs the detection rules on them - so
  production logs stream in (a Log Collector panel on SIEM → Sources lets you
  paste/forward lines). Threat-intel matching: any event IP matching a
  critical/high IOC raises an enriched R-TIMATCH alert. ATT&CK Navigator
  (`/siem/attack-coverage` + new page): coverage matrix by tactic, per-technique
  rule/alert counts, gaps highlighted, drill-down to alerts/rules/MITRE.

- **2026-06-10 · Detection rule engine + editor (Phase 1)** - the SIEM now
  works like a real SIEM: the live engine emits raw telemetry into an `events`
  table, and enabled detection rules evaluate that stream to fire alerts.
  `rule_engine.py` supports field conditions (equals/contains/in/gt/lt/regex/
  cidr…), AND/OR logic, and threshold-over-window aggregation (brute-force /
  beaconing style). 7 built-in rules ship; analysts author custom rules in a
  new visual `RuleEditor` (condition builder + aggregation + **live backtest**
  via `POST /siem/rules/test`) and `/siem/rule-schema` exposes the fields/
  operators. Rules carry MITRE mapping; alerts are produced by the matching
  rule, so triage/KPIs/correlation all flow from real detections.

- **2026-06-10 · Reporting engine** - structured, sectioned reports
  (`dashboard_api/reports.py` + `/reports/*`): executive + SIEM + SOAR + CTI +
  assets + dark-web, each with an executive summary, headline KPIs, severity/
  category breakdowns, detailed findings, and recommendations. Daily / weekly /
  monthly / custom ranges. Frontend `ReportButton` on every section header
  opens a paginated, print-to-PDF + HTML-download viewer (Nessus/Acunetix
  style, not a CSV dump). Tested across all kinds.
- **2026-06-10 · Universal drill-down** - `DetailDrawer` (window-event based,
  mounted in the dashboard layout) makes previously dead "clickable" overview
  items open a real detail view with rows + deep-link actions; wired recent
  alerts, incidents, and the live threat feed. Also wired the dead SIEM
  "Refresh" button and added live polling to the SIEM queue.

- **2026-07-23 · Frontend → Node SSR deployment (was static export).** Migrated
  the Next.js frontend from `output: 'export'` (static, nginx/CDN-served) to a
  **Node SSR deployment** (`next start`). Rationale + security handling:
  • The 9 open Next.js advisories were previously non-applicable because a
    static export ships no server runtime; SSR makes them apply, so the move is
    paired with a genuine fix - `next` pinned to **16.3.0-canary.94** (the first
    build carrying the patches; `npm audit --omit=dev` now reports **zero**
    high/critical). `.audit-allowlist.json` is empty again (nothing to triage).
    Re-pin to 16.3.0 stable when it ships (canary is a pre-release).
  • **Security headers** now come from `next.config.mjs headers()` (X-Frame-
    Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS,
    the full CSP) - static export ignored `headers()`, so they used to be set by
    nginx.conf / vercel.json only. The Node server now enforces them on every
    response and on every host (verified via `curl -I`).
  • Scaffolding retargeted: `Dockerfile` runs `next start` on a Node runtime
    (no nginx); `linux-start.sh` starts the SSR server; `package.json`
    start/start:e2e use `next start`; `vercel.json` uses `framework: nextjs`
    (set the Vercel project Root Directory to `frontend`). `serve_frontend.py`
    is now legacy (unused).
  • Verified: build clean; `next start` serves with headers; audit-gate passes;
    lint 0 errors; check:routes clean; 20 e2e (auth/deep-links/workflows/
    analyst-flow/a11y) green against the live SSR stack.
  Trade-off recorded honestly: SSR adds a Node server process (vs. a static
  bundle any host can serve) and pins a Next pre-release until 16.3.0 ships.
