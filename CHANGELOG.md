# Changelog

All notable changes to ThreatOrbit‑V2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project tracks the
roadmap in [`plan.md`](plan.md) (completed roadmap items land here).

> Status framing lives in the README's **"Project status — read this first"**
> and **§15 Limitations & honest caveats** — read those before pitching this.

## [Unreleased]

### 2026-07-13 — Ship Prometheus alert rules for the platform's own health
- `deploy/prometheus/alerts.yml` + README: ready-to-use alert rules over the
  metrics `GET /metrics` already exposes — target down, `/ready` returning 503
  (DB unreachable), unhandled-error rate, engine-tick failures, detection queue
  depth/lag, and mean request latency. Thresholds mirror the in-app self-health
  defaults so a Prometheus/Alertmanager team gets paged on the same conditions
  the System Health card shows, even when nobody's looking at the dashboard.
  README documents the scrape_config, the metric table, and a PrometheusRule
  CRD wrapper for the prometheus-operator. YAML + rule structure validated.
- **Doc-accuracy fix:** observability.py's docstring claimed unhandled errors
  land in `threatorbit_errors_total`; the metric is actually exposed as
  `threatorbit_domain_total{counter="errors"}`. An operator alerting on the
  named-but-nonexistent series would have gotten no data — corrected.

### 2026-07-13 — Platform self-health surface + a real /ready readiness contract
- **Bug: `/ready` lied to orchestrators.** The readiness probe returned HTTP
  **200** with a `{"ready": false}` body when the database was unreachable.
  A k8s/LB `httpGet` readiness probe treats any 2xx as READY, so a pod whose
  DB had gone away stayed in service rotation and kept receiving traffic it
  couldn't serve — the Helm chart already points its `readinessProbe` at
  `/ready`. Fixed to return **503** when the DB check fails; `/health`
  (liveness) stays a cheap always-200 on purpose (don't kill+restart a pod
  for a DB outage a restart can't fix).
- **Feature (plan.md: "alerting on the platform's *own* health").** New
  `dashboard_api/self_health.py` aggregates real, cheap subsystem signals —
  database reachability + measured round-trip latency, code-vs-DB schema
  version, detection-queue depth/lag backpressure, background-work leader
  lease, and process uptime/error counters — into one verdict. The overall
  status is the worst *gating* check (database `down` ⇒ down; schema drift or
  a queue past its env-tunable thresholds ⇒ degraded); informational checks
  never gate, and DB-dependent checks are marked `unknown` rather than
  fabricated when the DB is down. Exposed as authed `GET /self-health`
  (same access as `/config/leader`).
- **UI.** Settings → General gains a **System Health** card that renders the
  live verdict + per-subsystem rows, polling every 10s. Every value is
  measured, never assumed. Verified in-browser (demo boots Healthy, DB
  ~0.7 ms) with a Playwright screenshot; new e2e fence pins the card.
- Tests: `test_self_health.py` (readiness 503 regression, verdict logic for
  ok/degraded/down, endpoint auth) — green on fresh SQLite **and** Postgres;
  full backend suite (550) green; `frontend tsc` clean; `e2e/self-health.spec.ts`.
- **Proactive alerting.** A leader-gated background monitor (live mode) samples
  the verdict every `DASHBOARD_HEALTH_MONITOR_SECONDS` (default 60s) and raises
  a `platform.health` notification — into the bell, SSE, and Slack routing —
  only on a *verdict transition* (ok→degraded→down and recovery), so a
  steadily-degraded platform never spams. Severity maps warning/critical/info;
  leadership is a read-only `is_leader()` check so exactly one replica alerts
  and it never fights the engine's lease. When the DB is itself the fault the
  INSERT can't land, so the CRITICAL log line (+ /metrics, Sentry) is the
  out-of-band channel. Transition logic covered by 5 more tests (no-alert on
  first observation / steady state, degrade/recovery severities, DB-down
  persist-failure swallowed).

### 2026-07-12 — Globe hotspot pulse: smooth breathe, not a cusped snap (user-reported "not smooth")
- The threat-globe's city hotspot rings pulsed with `Math.abs(Math.sin(t))`,
  which has a sharp cusp (V-shape) at every zero crossing — the ring
  expanded, shrank back, then *bounced* abruptly at its smallest point.
  Across a dozen hotspots that read as a repeating "snap": the "repeating
  but not smooth" the user described on the second planet. Swapped for
  `sin²(t)` — identical 0→1→0 breathing range and period, but it touches
  both extremes tangentially (zero derivative), so the pulse is C¹-smooth
  with no cusp. The globe's rotation and the attack-arc fades were already
  continuous. Build + render verified, zero console errors.

### 2026-07-12 — Box-shaped dots on the globe + IOC-network scenes (user-reported, round 2)
- The earlier landing-scene fix covered the hero and the *first* orbital
  scene, but the user meant the visuals further down: the "second orbital
  planet" (the rotating **ThreatGlobe** in "Threats move worldwide") and
  the **IOC network** below it. Their node dots were tiny `sphereGeometry`
  meshes (globe radius 0.018, IOC 0.04) that aliased into visible **squares**
  at sub-pixel size — and antialiasing couldn't help because both scenes
  render through a bloom `EffectComposer` pass, which bypasses the canvas
  MSAA.
- New reusable `RoundPoints` component renders the dots as point sprites
  with a fragment shader that discards fragments outside the circle —
  crisp and round at any size or DPR, independent of bloom. It carries
  per-point colour + size (so the IOC actor/IOC size hierarchy survives)
  and an optional GPU-side pulse (per-point phase), so the IOC network
  keeps its out-of-sync "breathing" with no per-frame JS over the node
  list. Both `ThreatGlobe.Nodes` and `IOCNetworkScene.NodeMeshes` now use
  it.
- Browser-verified with zoomed crops: every dot on both scenes is now a
  clean circle (was distinctly square), size hierarchy intact, zero
  console/shader-compile errors.

### 2026-07-12 — Pin `three` back to 0.184 (incompatible Dependabot bump)
- A Dependabot "frontend-minor" bump pushed `three` to 0.185.1, but our
  `postprocessing@6.39.1` (under `@react-three/postprocessing`, which
  drives the bloom on every landing 3D scene) has a peer range
  `>= 0.168.0 < 0.185.0` — 0.185.1 is one patch outside it. The scenes
  still rendered, but the package tree carried an unsatisfied peer, and
  the CI **supply-chain / SBOM** job (`npm ls --json --long --all`)
  failed with `invalid: three@0.185.1` (plus an `@emnapi/runtime`
  extraneous entry from the same regeneration).
- Reverted `three`→`^0.184.0` and `@types/three`→`^0.184.1` (the last
  peer-compatible pair, and the exact versions the scenes were verified
  on earlier this session) via an incremental `npm install` — a minimal
  16-line lockfile diff, no unrelated transitive churn. `npm ls --all`
  and `scripts/sbom.sh` now exit 0; tsc + build green.
- Also gitignored the `sbom/` output dir so SBOM runs don't leave stray
  artifacts.
- **Prevention**: added a Dependabot `ignore` so `three`/`@types/three`
  only receive patch bumps (not the minor jumps that clear
  postprocessing's ceiling), until a human takes the
  `@react-three/postprocessing` upgrade — so this exact incompatible
  auto-merge can't recur every Dependabot cycle.

### 2026-07-11 — Overview rollups: windowed SQL cuts + a heatmap honesty fix
- Three Overview endpoints (`hourly-volume`, `alert-analytics`,
  `mitre-heatmap`) fetched **every alert row** into Python though each only
  uses a bounded window (24h / 7d / 7d). They now cut with `ts >= cutoff`
  in SQL (ISO-text `ts` rides `idx_alerts_ts`), and `alert-analytics`
  aggregates its all-time disposition breakdown with `GROUP BY` instead of
  a Python loop over the table.
- **Heatmap honesty fix**: the MITRE tactic × time heatmap claimed six
  ~28h buckets over the last week, but its `min(5, …)` clamp piled **every
  alert older than a week into the oldest cell**, so that column inflated
  forever and misrepresented the last-7-days claim. Now honestly excluded
  at 168h. New `test_overview_windows.py` pins both: a 90-day-old alert is
  excluded (not clamped) and a 5-day-old alert stays out of the 24h
  volume. Full suites green on fresh SQLite (540) and fresh Postgres (538
  + 2 skipped).

### 2026-07-11 — /siem/kpis: 60× faster at scale (SQL aggregation)
- The SIEM page polls `/siem/kpis` every 30 s, and the endpoint fetched
  **every alert row** into Python to count severities/dispositions — a
  full-table transfer per poll. It now aggregates with a single
  `GROUP BY severity, status, disposition` (the fetched `risk_score` was
  never even used). Identical output, verified by the existing tests.
- Measured on Postgres 16 with 210k alerts (median of 5 runs): fetch-all
  1650 ms → GROUP BY **27 ms**. Documented in LOAD_LIMITS ("Polled
  rollups at high alert volume"). Full suites green on fresh SQLite
  (538) and fresh Postgres (536 + 2 skipped).

### 2026-07-11 — E2E: the core analyst workflow, end to end
- New `e2e/analyst-flow.spec.ts` exercises the product's value chain for
  real (not just page loads): open a seeded brute-force alert, assign it,
  escalate it into a SOAR case via the drawer action, extract the real
  case id from the toast, and assert the case is genuinely on the SOAR
  board (served by the API, not local state). A second spec runs a
  playbook from the library and asserts the card records the run
  ("Just now").
- Verified on desktop chromium (2 passed) and all selectors checked on an
  iPhone-13 viewport (the probe created a real case and saw it appear on
  the mobile board) before CI's webkit project runs it.

### 2026-07-11 — Overview: honest movement note on Active Threats
- The trends buckets gained a per-day `severe` count (critical+high
  alerts raised that day, pinned in the bucket-math test), and the
  Overview's Active Threats card now shows a real movement note: "±N new
  critical/high vs yesterday". The KPI itself is a STOCK (open
  critical/high right now), so the note is the clearly-labelled FLOW —
  not a mislabelled volume delta — and hides when flat or without a
  baseline rather than inventing a movement. The card's vague "across
  all sources" sub also became precise ("open critical/high alerts",
  which is what the API actually counts).
- Browser-verified against the live DB: card renders "-12 new
  critical/high vs yesterday", matching the API buckets exactly. Full
  suites green on fresh SQLite (538) and fresh Postgres (536 + 2).

### 2026-07-11 — Reports: prior-window trends, severity donut, tighter print
- Every windowed report narrative (SIEM, SOAR, CTI, dark web) now carries
  an honest prior-window comparison — "Volume is up/down N% against the
  preceding window (M alerts)" — computed over the preceding window of
  equal length, with an explicit no-baseline note instead of an invented
  movement when the prior window is empty. Table/column pairs the helper
  may query are allow-listed; naive/aware datetime windows normalised
  (custom ranges arrive tz-naive and previously crashed the subtraction —
  caught by the existing all-kinds test).
- The printable/downloadable HTML report gains a static SVG severity
  donut (total in the centre, per-severity legend) beside the KPI tiles,
  and print-quality rules: `@page` margins, headers that never strand at
  a page break, findings/KPIs/donut kept whole (`break-inside: avoid`).
- Tests: `test_report_trends.py` (trend sentence deterministic via a
  planted prior-window alert; all six report kinds still build). Full
  suites green on fresh SQLite (538) and fresh Postgres (536 + 2
  skipped). Browser-verified: viewer narrative shows the trend, the print
  popup contains the donut and break rules.

### 2026-07-11 — Network map: eased motion + reduced-motion-correct SMIL
- The asset network map (the "clean, eased look" backlog item) now
  animates properly: nodes scale/fade in with a small stagger on mount
  (an inner group animates so the entrance can never fight the drag
  translate), links draw in once, and the +/− zoom buttons ease the
  viewBox through interpolated frames instead of jumping (wheel/pinch
  stays instant — it must track the finger). All on the shared motion
  tokens.
- Accessibility fix: the map's SMIL animations (traffic particles along
  links, critical-pulse rings, live-dot blink) ignore both the global
  reduce-motion CSS rule and framer's MotionConfig — they now gate on
  `useReducedMotion()` directly and disappear entirely for those users.
- Browser-verified with sampled opacity during entrance (0 → 0.54 →
  0.95 → 1), interpolated viewBox frames on button zoom landing on the
  exact target, node click/detail panel and pan still working, and a
  reduced-motion context rendering zero SMIL elements.

### 2026-07-11 — E2E data-honesty fences (regression lock-in)
- New `e2e/honesty.spec.ts` (runs in the CI Playwright workflow) pins this
  session's fabrication fixes so hardcoded demo values can't silently
  return: SIEM header annotations computed (old static strings asserted
  absent), analytics cards free of the demo series, alert-detail
  identity/host tabs showing real UEBA (no "Department"/"Kerberos"/fake OS
  rows), playbooks KPI strip live with the success-rate asserted a sane
  percent (poll-after-count-up), Config → API without the invented rate
  limit, and the SOAR board showing skeletons — never an empty-state
  flash — under a delayed response. Full desktop e2e suite: 28 passed.
- `playwright.config.ts` gains an optional `PW_EXECUTABLE_PATH` override
  so sandboxes with a pre-provisioned Chromium can run the suite without
  `playwright install`; CI is unaffected.

### 2026-07-11 — Playbooks: live KPI strip + 100× success-rate display bug
- The playbooks page's KPI strip was a hardcoded demo array ("Total
  Playbooks 18", "Scheduled 4 · Next: 17:00 UTC", "94.2% · +1.3% from
  last month") rendered as if live. Now computed from the loaded list:
  total + enabled count, running now + failed-last-run, auto-triggered
  count (the invented "Scheduled" schedule is gone), and a run-weighted
  average success rate "across N runs" — with count-ups and a first-load
  skeleton. The page also now treats the API's answer as authoritative
  even when empty (demo playbooks are offline-fallback only; previously
  an empty live library silently kept showing demo playbooks).
- **100× display bug (pre-existing, live deployments)**: the backend
  stores `success_rate` as a 0–1 fraction; every UI treated it as a
  percent, so live playbook cards and the SOAR-metrics success column
  rendered "0.9%" where the truth was 93.6%. Normalized once at the API
  boundary (`fetchPlaybooks`) so all four consumers agree; verified live
  (weighted KPI now 90.2%, metrics column shows true percents).

### 2026-07-11 — Real per-API-key usage telemetry (Config → API honesty)
- Config → API fabricated its request stats twice over: a "Rate Limit
  1M/mo" KPI for a quota that doesn't exist anywhere in the API, and a
  per-key Requests column that always rendered 0 on live deployments
  because the backend never tracked usage.
- Backend: new `api_key_usage` table (key_id × UTC day, upsert-incremented
  in the central key-auth path AND the TAXII key path on every
  authenticated request — rejected/revoked requests are never counted);
  `GET /config/api-keys` now returns `requestsToday`/`requestsTotal`.
- Frontend: the KPI strip shows the real today-sum, the table shows real
  per-key totals, and the fake rate-limit KPI became "Revoked Keys"
  (real). Demo seed keys remain for the offline preview only.
- Tests (`test_api_key_usage.py`, both backends): counted on use, honest
  zeros when fresh, per-key isolation, last_used stamped, revoked-key
  requests rejected AND uncounted. Full suites green on fresh SQLite
  (536) and fresh Postgres (534 + 2 skipped). Live-verified end to end:
  key created via API, used 5×, page renders today: 5 / total: 5.

### 2026-07-11 — SIEM header + alert-detail honesty; count-ups on stat strips
- **SIEM header KPI strip**: the six sub-annotations were static demo
  strings shown unchanged next to live values ("-12% vs yesterday",
  "+4 in last hour", "↓ from 28% (7d)"). All six are now computed: alerts
  vs yesterday from the trends buckets (em-dash when there's no baseline),
  critical/high in the last hour counted from the live queue, MTTD/MTTR/FP
  against real 7-day averages (days without telemetry excluded rather than
  dragging the average down), and the MTTA "< 15m target ✓/✗" tick decided
  by the actual value. "Total Alerts Today" now shows *today's* count
  (trends bucket) instead of the all-time total its label contradicted.
- **Alert-detail Identity tab**: was fully fabricated ("Domain CORP",
  "Department Finance", "UEBA 44/100 ↑ from baseline 12", "Last Login 11h
  ago (New York)", a whole Kerberos/NTLM "Authentication" section). Now
  renders the real per-user UEBA record from `/siem/entities/detail`:
  risk score, related-alert count, daily volume vs the user's own learned
  baseline (mean ± σ, z-score, DEVIATING flag), top MITRE techniques — and
  an honest note that directory/IdP attributes need an IdP integration.
- **Alert-detail Host tab**: fabricated OS build, vuln counts ("3 critical,
  7 high, 12 medium"), patch age, owner dept, PID and parent process all
  removed; now shows the alert's real host fields + the host's UEBA risk /
  related alerts / baseline deviation, and links to the real fleet-vulns
  page instead of inventing counts.
- **Count-ups**: SIEM header values, threat-feed KPI strip, and SOAR
  header stats now tick up via the shared `AnimatedNumber` (SOAR's strip
  was already honest — real week-over-week trends — so only motion was
  added there).
- Browser-verified: demo strings absent, computed subs present, Identity
  tab shows a real user record (risk 100/100 over 20 alerts, z = 0.11
  normal vs own baseline, real techniques), zero console errors; tsc +
  build + route guard green.

### 2026-07-11 — First-load skeletons across every major list surface
- Extends the skeleton pattern shipped with the SIEM queue to the rest of
  the app: SOAR case board (Normal-mode kanban columns) and Power-mode
  case list, the asset inventory (table AND cards views), the fleet
  vulnerabilities table, both threat-feed columns, and the dark-web
  findings list (whose text loader migrated to the shared component).
  While the first API answer is pending these show pulsing placeholder
  rows instead of flashing "No cases" / "No assets match your filters" /
  "No unconfirmed threats - feed is quiet" — an honesty bug as much as a
  polish one, since a busy SOC briefly reads as empty on every load.
- Power-mode SOAR previously rendered a completely blank list when the
  case store was empty — it now has a real empty state ("No cases yet —
  correlated alerts escalate here automatically") after loading.
- Browser-verified on all five pages with request-delay interception
  (skeletons appear, empty-state text never flashes, page resolves);
  tsc + build + route/anchor guard green.

### 2026-07-11 — SIEM analytics: live 7-day trends + loading skeletons (fabrication-sweep miss)
- The analytics tab's four trend cards (Alert Volume, MTTD, MTTR, False
  Positive %) rendered a hardcoded `SPARKLINE_DATA` series (2,847
  alerts/day, MTTD 4.2 min, …) as if it were live telemetry. New backend
  endpoint `GET /siem/analytics/trends?days=N` (1–30, default 7) returns
  per-day buckets — alert count, MTTD/MTTR from the same latency columns
  `/siem/kpis` uses, FP rate — zero-filled so a quiet day is an honest 0,
  always ending today (UTC). The cards now render it; `SPARKLINE_DATA`
  survives only as the documented first-load-offline fallback (same policy
  as the demo alert queue).
- New shared `Skeleton`/`SkeletonRows` components (CSS pulse — frozen by
  the existing global reduce-motion rule): the trend cards show skeletons
  until the first answer (no demo-number flash), the alert queue shows
  skeleton rows during its first fetch instead of flashing "No alerts
  match the current filters", and the FP-triage list gets the same
  treatment while scoring.
- Sparklines now draw in left-to-right on mount (framer `pathLength`,
  honours MotionConfig reduced-motion).
- Tests: `test_siem_trends.py` (bucket math pinned against merged
  pre-existing + planted telemetry, zero-fill/range/bounds, future-dated
  rows ignored) — full suites green on fresh SQLite and fresh Postgres.
  Browser-verified: live values render (honest 0 for the just-started
  day), skeletons appear under a delayed request and resolve to live data,
  demo values never leak, zero console errors.

### 2026-07-10 — Landing 3D scenes: box-shaped artifacts + jerky orbital motion (user-reported)
- **Square "box" dots**: WebGL point sprites render as squares unless the
  shader masks them round — the orbit dots in `OrbitalScene` and the hero
  starfield used the raw `pointsMaterial`, so every dot riding the orbit
  rings read as a tiny box. Swapped both onto drei's `PointMaterial`
  (circular mask), verified round in zoomed screenshots.
- **Hero hex prisms read as solid boxes**: on the no-bloom path (mobile /
  degraded GPUs — also the path headless Chromium takes) the floating
  shapes used a flat unlit `meshBasicMaterial`, so a hex prism sitting
  edge-on rendered as a featureless filled rectangle. The shaded material
  is now used in both modes with a directional key light standing in for
  bloom (point lights decay to ~nothing at scene distance), and the prisms
  get an initial face-on tilt (Float's wobble is bounded, so they can no
  longer drift edge-on). The big pink "box" beside the hero terminal now
  renders as a faceted hexagonal gem.
- **Orbital planet flattened into a disc**: same no-bloom path — emissive
  1.1 with `toneMapped=false` saturated every pixel of the planet into a
  flat pink circle. Emissive lowered to 0.55 there + the directional key
  light, so the limb shades and it reads as a sphere again.
- **"Repeating but not smooth" orbital motion**: the ScrollStory planet's
  rotation mapped RAW `scrollYProgress` to degrees, so each ~100px wheel
  step snapped the rotation through discrete angles. It now derives from
  the same spring-smoothed progress the narrative beats already use.
- **Globe arc pop**: threat-globe arcs teleport to a new random curve at
  the end of each cycle, but the line opacity floor was 0.12 — the swap
  was visible as a dim line snapping across the globe every ~3s. The
  opacity envelope is now `0.44·sin(π·t)` (fades fully out before the
  curve swap, brighter at mid-flight).
- All verified against the rebuilt static export in a real browser with
  before/after zoomed crops; zero console errors; route/anchor guard green.

### 2026-07-10 — SOAR metrics: "Cases by Type" wired to live data (fabrication-sweep miss)
- The SOAR metrics tab rendered a hardcoded "Cases by Type (Last 30 days)"
  list (Phishing 284, Endpoint/Malware 127, …) as if it were live data — the
  one remaining fabrication on that tab (the Automation Metrics block and
  the KPI table beside it were already computed from the live API). Spotted
  while adding the tab-switch animation, tracked, and fixed: the chart is
  now derived from the same live case list the KPI table uses — genuine
  30-day window, top 7 types, and an honest empty state when no cases exist.
- Verified live against a fresh seeded install: the block renders the real
  case types (Account Compromise 2, Privilege Escalation 1, …) and the
  fabricated numbers are gone; zero console errors, tsc + build green.

### 2026-07-10 — Animations increment 4: tab transitions on every remaining tabbed surface
- The keyed tab-switch transition proven on the SIEM page now covers all
  remaining tabbed surfaces: SOAR main tabs (cases/playbooks/metrics), the
  SOAR case-detail tabs (overview/warroom/tasks/evidence), the Config
  settings tabs, and Config-Users (users/roles — whose existing plain fades
  also migrated onto the shared `fadeInUp` token).
- Verified live on all three pages by watching inline opacity during a
  switch (each keyed wrapper observed animating to 1 from below 0.5), zero
  console errors; tsc + production build green.
- Side-find (tracked in plan.md, not yet fixed): the SOAR metrics tab
  renders a hardcoded "Cases by Type (Last 30 days)" list as if live — a
  fabrication-sweep miss to wire to real case data next.

### 2026-07-10 — Animations increment 3: KPI count-ups + hover-lift micro-interactions
- New reusable `AnimatedNumber` component: stat values count up from the
  previously shown value whenever the data changes (0 → value on first load,
  so numbers arriving reads as a tick-up rather than a jump cut). Reduced
  motion is honoured explicitly via `useReducedMotion` — imperative
  `animate()` calls bypass `MotionConfig`, so the component sets the final
  value instantly for those users. Wired into the Overview KPI cards in both
  Power and Normal mode.
- Two defects caught by live verification rather than assumed: the target
  value flashed for one frame before the count began (useEffect runs after
  paint — fixed by rendering the previously-committed value), and the shared
  `hoverLift` token originally carried a top-level `transition` prop that
  collided with elements setting their own enter transition (fixed by
  embedding the gesture transitions inside the hover/tap targets).
- Shared `hoverLift` micro-interaction (subtle rise on hover, settle on
  press) applied to the Overview KPI/status cards.
- Verified live: monotonic count-up 0→31 over ~0.8s on data arrival,
  reduced-motion jumps instantly to the final value, zero console errors;
  tsc + production build green.

### 2026-07-10 — Animations increment 2: SIEM tab transitions + FP-triage list stagger
- SIEM dashboard tab switches now replay a smooth `fadeInUp` enter (the tab
  content is a keyed motion wrapper on the shared tokens), and the FP-triage
  list staggers its rows in via `listContainer`/`listItem`.
- A subtlety caught live rather than assumed: children mounting into a
  motion parent that has already settled at its "show" state don't animate —
  the FP-triage items arrive async, so the list container is keyed on
  band + item count and the remount on data arrival is what makes the
  stagger actually play. Verified by sampling inline opacity during the
  transitions (both the tab wrapper and the row labels observed animating
  0.000 → 1), zero console errors.
- `IocLifecyclePanel` migrated from hand-rolled inline motion props onto the
  shared `fadeInUp` variant (same visual, one source of truth).

### 2026-07-10 — Deterministic list ordering (id tie-breaker) + third tie-order test flake fixed
- **Product fix:** `GET /siem/alerts`, `GET /cti/iocs`, and the FP-triage
  working-set window now append an `id` tie-breaker to every ORDER BY.
  Alert/IOC timestamps have second precision, so a burst of rows ties on any
  sort key; without a total order, tied rows come back in arbitrary,
  backend/plan-dependent order — which makes **offset/limit pagination able
  to skip or duplicate rows across pages** for every API consumer, the UI
  included. Verified the Postgres translation of the two-key ORDER BY is
  clean, and that no existing test depended on the old tie order (full suite
  green on both backends).
- **The CI flake that surfaced it** (third instance of the tie-order class,
  and the last — the class audit is now exhaustive):
  `test_fp_feedback_bumps_rule_fp_rate` hardcodes `203.0.113.214`, the one
  suite IP range in which three other tests draw **random** `203.0.113.x`
  addresses; one of those plants a critical IOC on its draw. On a 1-in-250
  collision this test's single ingest fires TWO alerts in the same second
  (brute-force + TI-match — mechanics **reproduced deterministically**, not
  assumed: planted the IOC, observed `alerts: 2, tiMatches: 1` with identical
  timestamps), `items[0]` picks arbitrarily on Postgres, and the FP bump
  lands on the wrong rule. Fixed by selecting the brute-force alert by
  `rule_name` (engine alerts all carry `rule_id='R-ENGINE'`, so the name is
  the discriminator), with a loud assert message listing what was found.
  Audited every other `["items"][0]`-after-search site in the suite: all
  others use draw-free IP ranges with suite-unique values, or don't depend
  on which row they get — this was the only exposed one.

### 2026-07-10 — Animation foundation: shared motion tokens + global reduced-motion + page transition
- New standing sub-end goal (owner): smooth animations everywhere. Laid the
  foundation the rest builds on:
  - `frontend/lib/motion.ts` — one shared easing curve (`[0.22,1,0.36,1]`), a
    3-step duration scale (fast/base/slow), and reusable variants (`fadeInUp`,
    `fadeIn`, `scaleIn`, `drawerRight`, `listContainer`/`listItem`,
    `pageEnter`). Before this, 84 framer-motion files each hand-rolled their
    own durations/easings, so timings had drifted; now they can share one
    system.
  - `<MotionConfig reducedMotion="user">` at the app root
    (`app/providers.tsx`) — every framer-motion animation in the app now
    honours the OS "reduce motion" setting automatically (framer drops the
    movement/transform, keeps harmless opacity fades). The existing CSS
    `@media (prefers-reduced-motion)` rule only covered CSS animations, not
    framer's JS-driven ones, so this closes a real accessibility gap.
  - A smooth per-route **dashboard page transition**: `PageScale` keys a
    `motion.div` on the pathname so the `pageEnter` fade-up replays on every
    navigation (keyed remount — the robust App-Router pattern, no exit flash).
- Verified live in a browser: the transition fades smoothly in normal mode
  (opacity 0→1 over ~150ms) and renders correctly under emulated reduce-motion
  with zero console/page errors; tsc + production build green.

### 2026-07-10 — No-dead-links guard + canonical repo URL
- New standing sub-end goal (owner): the app must have **no dead links**.
  Extended `frontend/scripts/check-routes.mjs` (already CI-gated in
  `tests.yml`) from route-only to **route + in-page-anchor** integrity: a
  bare `href="#"` (goes nowhere) and an anchor to a non-existent `id` now
  both fail the build, alongside the existing "link to a route no page
  serves" check. Verified the guard both ways (injected a dead anchor and a
  bare `#` → build fails; removed → green). Current tree: 227 route links +
  2 in-page anchors, all valid.
- Audited the whole frontend for dead links: no `href="#"`, no empty/stub
  `onClick`, no "coming soon" placeholders, both anchor targets
  (`#main-content`, `#tiers`) resolve. The only real fix was the GitHub
  repository URL, which still pointed at the pre-rename
  `github.com/Sami9211/ThreatOrbit-V2` and worked only via GitHub's rename
  redirect (a soft dead link) — updated to the canonical
  `github.com/Sami9211/ThreatOrbit` in the footer, the landing CTA (link +
  clone/`cd` command), and the quick-start docs clone command.

### 2026-07-09 — Bulk FP-triage view: score, filter, and dismiss a cluster at once
- New `GET /siem/alerts/fp-triage`: scores a bounded working set (the most
  recent 300 open alerts) with `fp_scoring.score_alert`, filters by
  likelihood band, and sorts by score — the "process a whole likely-noise
  cluster at once instead of one alert at a time" phase from the FP-scoring
  design in `plan.md`. The working set is capped lower than a plain list
  endpoint because each row costs several scoring queries, not one; an
  honest bound documented in `docs/LOAD_LIMITS.md`, not a silent truncation.
- New `POST /siem/alerts/bulk-dismiss`: marks a selection of alerts
  false-positive/closed in one call — the same effect as the existing
  per-alert `PATCH`, batched, with every alert still individually
  audit-logged and each rule's `fp_rate` bumped once per rule (not once per
  dismissed alert).
- New Power-mode-only "FP Triage" tab in the SIEM dashboard: a band filter,
  a checkbox-selectable scored list, "select all", and "dismiss selected".
- Regression-tested (band filtering, score thresholds, bulk-dismiss state
  changes and audit trail, the rule fp_rate single-bump behaviour) on
  SQLite and a live Postgres instance; full backend suite green. Verified
  live in a browser: filtering to `likely-fp` isolated one seeded low-risk
  alert out of 74 scored, and dismissing it removed it from the view.

### 2026-07-09 — Evidence-based false-positive likelihood for alerts and IOCs
- New `dashboard_api/fp_scoring.py`: transparent, explainable false-positive
  likelihood scoring for SIEM alerts and CTI indicators, built entirely from
  data already collected elsewhere in the platform — never a black-box
  classifier, and never a silent auto-action. Score starts at a neutral
  midpoint (50) and each applicable signal shifts it by a signed, capped
  weight; banded into `likely-fp` / `uncertain` / `likely-real`.
- Alert signals: the firing rule's historical FP rate, live-joined asset
  criticality (the `alerts.host_criticality` column is never populated at
  insert time, so this joins `assets` by hostname/IP instead), standing
  suppression-rule proximity, time-windowed correlation against other
  unresolved high/critical alerts, direct IOC cross-reference (known-good or
  active malicious), and per-entity false-positive history.
- IOC signals: cached enrichment-provider consensus (`ioc_enrichments`),
  cloud/CDN CIDR range match, and a sighting-vs-alert-impact mismatch check.
- Surfaced via dedicated compute-on-demand sub-endpoints — the same pattern
  as the existing `GET /cti/iocs/{id}/enrichment` — rather than embedding in
  every list/detail response (avoids N+1 query cost on list views):
  `GET /siem/alerts/{id}/fp-assessment` and `GET /cti/iocs/{id}/fp-assessment`.
  A "FP Likelihood" button in the Power-mode alert detail drawer and the IOC
  lifecycle panel renders the band, score, and full evidence trail.
- Regression-tested per the testing discipline this feature was designed
  under: a correlated multi-alert attack plus a known-bad IOC match must
  stay `likely-real` even with one weak FP-leaning signal also present, so
  no single weak signal can mask a real incident.
- Verified: 13 new tests passing on SQLite and against a live Postgres
  instance; full backend suite green (529 tests); live-browser verification
  against the real pipeline (a critical-asset match plus an isolated alert
  nets `uncertain · 43`, exactly matching the signed-weight arithmetic).

### 2026-07-09 — Batched ingest writes: ~5.7x Postgres EPS (670 → 3,800), no correctness change
- `ingest_lines` issued one `conn.execute(INSERT …)` per parsed event — a
  Python loop, fine for SQLite's in-process file access, but on Postgres every
  row paid a real client↔server round trip (the root cause `docs/LOAD_LIMITS.md`
  identified in the earlier baseline-measurement pass). Fixed by collecting
  the batch's rows and issuing a single `conn.executemany(...)` call instead.
- **Verified empirically before committing to the approach**, not assumed: a
  standalone benchmark against a local Postgres instance measured
  `executemany` at ~6x a naive row-by-row loop (72k vs 11k rows/sec),
  matching a hand-built multi-row `VALUES` INSERT's throughput with far less
  code — and the abstraction layer already had `executemany` support
  (`PgConnection.executemany` in `db_backend.py`), so no new plumbing was
  needed. Confirmed on the real pipeline via `dashboard_api/bench.py`:
  ingest+detect went from ~670 to **~3,800 EPS** against the same local
  Postgres instance.
- **Investigated the detection-worker "claim" path too** (also named in the
  original roadmap item) and found it was already batched —
  `event_queue.claim` is one `UPDATE … WHERE id IN (…)`, `.complete` was
  already `executemany`. The `drain` benchmark stages are correctly unchanged
  by this fix; they're bound by per-match `_insert_alert` writes during
  detection processing, not the claim/complete plumbing, and are called out as
  a separate, lower-priority remaining item (matches are a small fraction of
  raw events in a realistic mix, unlike the benchmark's pathological
  all-match drain data).
- No correctness change: parse-time error isolation (one malformed/crafted
  line can't drop the rest of the batch) happens before rows are ever
  collected for the insert, unaffected by how the INSERT is issued.
- Verified: full SQLite suite (516 passed); full Postgres backend suite
  against a local instance, with a baseline comparison (git stash) confirming
  the only failures are pre-existing full-suite-only flakiness (a
  connection-pool timing issue already documented earlier this session,
  `test_darkweb_feed_connector` deterministically and 1-2 others that vary
  run-to-run) — not a regression from this change; `docs/LOAD_LIMITS.md`
  updated with the new measured numbers.

### 2026-07-09 — Sigma community-pack bulk import
- **New**: `POST /siem/rules/import-sigma-pack` bulk-imports a pasted
  collection of Sigma rules (e.g. a cloned SigmaHQ directory, or any
  downloaded rule set) in one request, instead of one rule at a time. The
  input is a standard multi-document YAML stream (`---`-separated, the
  format Sigma rule collections ship as); each document is parsed and
  inserted independently, so one malformed rule doesn't abort the rest of
  the pack — the response reports exactly which rules landed (id, name,
  mapping notes) and which failed (index + reason), a partial import is
  visible rather than silently incomplete. Capped at 500 rules per request
  (a DoS guard, matching the pattern already used for oversized feed bodies
  elsewhere). Extracted `_insert_sigma_rule` so the existing single-rule
  `/rules/import-sigma` endpoint and the new bulk one share one insert path.
- **Frontend**: `SigmaImportButton` now detects a multi-document paste
  (splits and counts non-empty `---`-separated chunks - not just checking
  for the presence of `---`, since a single rule commonly starts with a
  leading `---` document marker too) and routes to the pack endpoint
  automatically, showing a created/failed summary with per-rule failure
  reasons instead of the single-rule success message.
- Closes the "Sigma community-pack import" item under Detection content in
  `plan.md`'s open roadmap. Verified: 4 new backend tests (multiple valid
  rules, one bad rule isolated among good ones, empty input rejected, batch
  size cap enforced), a live browser smoke test of the actual UI flow
  (screenshot confirms the created/failed summary renders correctly), full
  SQLite suite (516 passed), `tsc --noEmit` clean.

### 2026-07-08 — Per-theme color-contrast fix: `--ink-500` and the alert-count badge now pass WCAG AA, everywhere
- `e2e/a11y.spec.ts` had `color-contrast` disabled pending a proper fix. Did
  the fix: computed exact WCAG contrast ratios (not estimates) for `--ink-500`
  against **all four surface levels** each theme actually renders text on
  (`--bg`/`--surface`/`--surface-2`/`--surface-3`), not just the darkest one -
  an important correction from a first attempt that only checked `--bg` and
  missed that a *lighter* surface can sit closer to a muted foreground's own
  luminance, giving *worse* contrast than the darkest background does. Fixed
  all 11 themes (`app/globals.css`) with a minimal HSL-lightness bump per
  theme (hue/saturation preserved), landing every one at ≥4.5:1 against its
  worst-case surface.
- The alert-count badge (`bg-threat` fill, 8px bold white text - Sidebar and
  TopBar) measured 2.65-3.76:1 across the 10 non-mono themes (mono already had
  a dark-text override). Rather than touch the shared `--threat` token (used
  in dozens of other contexts across 40+ files, too broad to verify visually
  in one pass), changed just the two badge instances to dark text
  (`text-[#0a0a0b]`), verified at 5.26-18:1 against every theme's `--threat`.
- **What's still open, and why it's out of scope here**: `--ink-600` (the
  most-muted tier) also measures below 4.5:1 in several real-text contexts
  (e.g. activity-feed timestamps), but it's used in 480+ places sitewide, and
  lightening it enough to clear AA collapses it visually onto the now-fixed
  `--ink-500` (both converge on nearly the same value under the same
  worst-case-background constraint) - destroying the ramp's gradation. A real
  fix needs per-usage triage: much of `--ink-600`'s usage is arguably WCAG SC
  1.4.3-exempt "inactive UI component" text (disabled buttons, placeholder-
  style hints) that doesn't require AA contrast at all, but that needs an
  actual per-site review, not a blind token bump. Tracked as a concrete,
  scoped item in `plan.md`.
- Verified: exact contrast math for all 11 themes × 2 tokens; a visual
  screenshot pass across 3 themes (no jarring regression - the lightening is
  subtle); the axe scan re-run with `color-contrast` re-enabled confirms 0
  violations for `--ink-500`/the badge, `--ink-600` timestamps remain the only
  (expected, tracked) violation; full existing Playwright suite (23 tests)
  unaffected; `tsc --noEmit` clean.

### 2026-07-08 — CI catch: 2 more icon-only buttons with no accessible name (mobile-only render paths)
- The new `e2e/a11y.spec.ts` (added earlier the same day) passed locally
  against `desktop-chromium`, but the `mobile-safari` CI job caught 2 more
  real violations that only render in the sidebar's mobile/expanded state -
  invisible to a desktop-only local check: the collapsible sub-menu chevron
  toggle (`Sidebar.tsx`, one per nav section with sub-items - SIEM/SOAR/CTI/
  Assets) and the mobile "close navigation" `X` button both had an icon and
  no text, `aria-label`, or `title` - a screen-reader user heard "button"
  with no indication of what it did. Both now carry a descriptive
  `aria-label` (the chevron's also reflects open/closed state via
  `aria-expanded`). Verified by emulating the mobile viewport locally (no
  webkit binary available in this environment, so re-checked via a headless
  Chromium context using the iPhone 13 device profile, which reaches the
  same code path) - 0 violations after the fix, confirmed again by CI.
- Also hardened `connectors._read_capped` (the SSRF-redirect fix earlier the
  same day): the original request's `params`/`json` are no longer resent on
  a redirect hop. The `Location` URL is already the fully-resolved target, so
  replaying the first request's query on top of it (e.g. NVD's
  `resultsPerPage`) could let httpx append a stale/duplicate query string
  onto whatever the redirect target expects; `headers` (auth) still carry
  over. New regression test in `test_connector_resilience.py`; full SQLite
  suite: 512 passed.

### 2026-07-08 — Automated accessibility regression testing (axe-core), and 4 real a11y bugs it caught immediately
- Added `@axe-core/playwright` and a new `e2e/a11y.spec.ts` that scans the
  login page, overview, SIEM alert queue, SOAR cases, and Config against
  axe-core's ruleset (WCAG 2.0/2.1 A+AA - the mechanically-detectable third of
  it) as a permanent CI gate, not a one-off manual pass that never repeats.
- The first run immediately found real, concrete bugs, all now fixed:
  - **The "Skip to content" link went nowhere on every dashboard/login page.**
    `app/layout.tsx` renders a sitewide skip-link targeting `#main-content`,
    but neither `app/dashboard/layout.tsx`'s `<main>` nor the login page's
    content region had that id (only the marketing pages did) - so keyboard
    and screen-reader users invoking it landed nowhere. Both now carry
    `id="main-content"` and `tabIndex={-1}` so focus actually moves there.
  - **6 Config-page form inputs had a visible label with no programmatic
    association** (`<label>` and `<input>` were unlinked siblings, not
    `htmlFor`/`id`-paired or wrapped) - a screen-reader user tabbing through
    General settings heard "edit text, blank" instead of "Platform Name, edit
    text". Fixed once at the shared `Field` component (`useId()` +
    `htmlFor`/`id`), covering every field built from it.
  - **Two unlabeled `<nav>` landmarks on the Config page** (the app's main
    Sidebar nav and the page's own settings-section rail/mobile-strip nav)
    were indistinguishable to landmark-based navigation. Each now has a
    distinguishing `aria-label`.
  - **No `<main>` landmark at all** on the login page, flagged separately
    from the skip-link gap.
  - `color-contrast` is deliberately disabled in the new spec, not silently
    dropped: a first run measured the `ink-500` (secondary/muted text) and
    `--threat` (alert-count badge) design tokens at ~3:1 against their
    default-theme backgrounds, short of the 4.5:1 AA text threshold - but
    both are defined per-theme (11 themes total), so a real fix needs a
    lightness pass verified visually across all of them, not a token edit
    landed sight-unseen from a headless test run. Tracked as a concrete
    follow-up in `plan.md` instead of left unstated.
- Verified: the new spec passes clean; the full existing Playwright suite (23
  tests) still passes unchanged; `tsc --noEmit` clean.

### 2026-07-08 — Measured the Postgres load baseline; corrected an unverified scaling claim
- **`bench.py`** forced a fresh SQLite temp database unconditionally before
  importing the app, so there was no actual way to run it against Postgres —
  the Tier-2 roadmap item "a documented Postgres EPS baseline" stayed
  unmeasured indefinitely. It now respects `DASHBOARD_DB_BACKEND=postgres` +
  `DATABASE_URL` when already set (the SQLite-default behavior for everyone
  else is unchanged), so `DASHBOARD_DB_BACKEND=postgres DATABASE_URL=... python
  -m dashboard_api.bench` measures the real thing.
- **Measured result, and a correction**: on the same host, Postgres came back
  markedly *slower* than SQLite for the current pipeline (~670 EPS
  ingest+detect vs. ~10,800; ~450 vs. ~7,400 single-worker drain), and the
  4-worker detection pool didn't beat 1 worker on Postgres either — the
  opposite of `docs/LOAD_LIMITS.md`'s prior (never-measured) claim that
  switching to Postgres alone would go "materially higher." Root cause,
  confirmed by reading the ingest/detection code rather than guessed:
  `ingest_lines` and the detection worker each issue one
  `conn.execute(...)` per event row with no `executemany`/`COPY` batching —
  free on SQLite's in-process file access, but every row pays a real
  client↔server round trip on Postgres, even over loopback, which dominates
  and erases whatever row-level-locking parallelism the worker pool could
  otherwise exploit. `docs/LOAD_LIMITS.md` now carries the measured Postgres
  table and this explanation instead of the old assumption; batching those hot
  writes is scoped as a new, concrete Tier-2 roadmap item in `plan.md` rather
  than attempted inside this measurement pass. `test_bench.py` (which strips
  the backend env vars so it always benches SQLite) is unaffected.

### 2026-07-08 — Connectors: a feed URL could 302 the dashboard into an SSRF (cloud metadata / internal targets)
- **Fixed a real SSRF gap**: `connectors._read_capped` fetched custom feed URLs
  (`json`/`csv`/`stix`/`darkweb-json` connector kinds, `connectors.manage`-gated
  but otherwise arbitrary) via `httpx.stream(..., follow_redirects=True)`.
  httpx's own redirect-following happens entirely inside the client, with zero
  visibility to `net_guard.validate_external_url` — so a feed URL that passes
  SSRF validation right now (it currently resolves to a public address) could
  still 302 the dashboard straight at `169.254.169.254` (cloud instance
  metadata / IAM credentials) or `127.0.0.1`/an RFC1918 address (an internal
  service), and the response would be fetched and parsed as if it were the
  feed — a full server-side-request-forgery primitive gated only on
  connector-management access, not on ever controlling a publicly-routable
  server. `webhooks.py`'s `net_guard.safe_post`/`safe_get` already close this
  exact gap for webhook/Slack targets (pin + block redirects entirely); feed
  URLs legitimately need to follow redirects (http→https, CDN), so blocking
  them outright wasn't the right fix here. Fixed by following redirects
  manually, one hop at a time, re-running `validate_external_url` against
  every `Location` before it's followed, capped at 5 hops. Regression tests in
  `test_connector_resilience.py` lock in: a safe same-host/CDN-style redirect
  is still followed; a redirect to cloud metadata, loopback, or an RFC1918
  address is rejected before the internal target is ever contacted; and a
  long/looping redirect chain raises rather than hanging.

### 2026-07-08 — Simple/Power mode: don't silently override the pre-existing UI default
- **Fixed a real regression E2E caught before it shipped**: `useExperienceMode`
  (an existing Normal/Power toggle that already drives real page UI - e.g. the
  SIEM alert queue's card density / inline triage actions - defaulting to
  'normal') was made to sync with the new backend org mode, treating every
  `GET /config/mode` response as authoritative. The backend's un-set fallback
  is `power`, so an org that had never explicitly chosen a mode (every
  existing install, every fresh demo/E2E boot) got silently flipped from its
  working 'normal' default to 'power' the moment the page synced - breaking
  the SIEM page's default triage UI. Root cause: two genuinely different
  "modes" (a client-side page-density preference vs. a new org-level
  feature-visibility setting) got conflated under one shared value with
  incompatible defaults. Fix: `GET`/`PUT /config/mode` now return an
  `explicit` flag (`modes.has_explicit_mode`) - true only when the org has
  actually persisted a choice - and the frontend only lets the backend
  override its local default when `explicit` is true; the feature list (nav
  curation) still always syncs, since its own fail-open default is equivalent.
  Caught by the `E2E (Playwright)` job before merge, not a live incident.

### 2026-07-08 — Test hygiene: two tests left standing auto-trigger playbooks enabled
- **Fixed real test pollution CI caught**: `test_playbook_auto_trigger` and
  `test_playbook_crud_validation` (`test_api.py`) each create a custom
  `trigger_type=auto` playbook (one matching any T1110/high alert, the other
  any critical alert at all) to exercise the create/update paths, but never
  disabled them afterward - leaving two standing, broad-match auto-trigger
  candidates enabled for the rest of the suite. Combined with the correlation
  fix below (which made `auto_trigger_playbooks` scan every alert in the
  window instead of stopping at 100), this let their broad matches compete
  with other tests' alerts for the same-second tie-break in `ORDER BY ts DESC`,
  making the correlation fix's own new tests fail intermittently deep in the
  full suite. Both tests now `PATCH … {"enabled": false}` once done. Also
  hardened the two `test_playbook_engine.py` auto-trigger tests to bump their
  alert's `ts` a few seconds into the future (the same idiom already used for
  the correlation-engine volume test) so they're unambiguously the most recent
  match regardless of any other same-second alert elsewhere in the shared
  suite DB - not just a fix for this one pollution source, but for the whole
  class of same-second tie-break flakiness.

### 2026-07-08 — CI catch: auto-trigger playbooks had the same volume-dependent miss as the correlation engine
- **Fixed a real production bug CI caught**: `auto_trigger_playbooks` scanned
  candidate alerts with `ORDER BY ts DESC LIMIT 100`. Once more than 100
  unresolved critical/high alerts existed within the 15-minute window — a busy
  SOC, or precisely an active incident, which is exactly when automated
  response matters most — a genuinely-matching fresh alert could be excluded
  by the row cap (same-second timestamp ties don't guarantee inclusion in the
  top 100) and its playbook would silently never auto-fire. This is the exact
  same class of bug already fixed once this session in the correlation engine
  (`_maybe_escalate_case`'s window-based grouping) — missed here because
  `playbook_engine.py` wasn't in scope of that earlier pass. Fixed the same
  way: the scan is now bounded purely by the 15-minute recency window, not an
  arbitrary row count. Added `test_auto_trigger_survives_high_open_alert_volume`
  (buries a real matching alert behind 150 noise alerts, asserts it still
  auto-triggers) — confirmed it reproduces the miss against the pre-fix code.

### 2026-07-08 — S3 log pull: one bad object can't corrupt the checkpoint
- **Fixed a real duplicate-ingestion / stuck-poller bug in the agentless S3
  log-pull path** (`dashboard_api/s3_pull.py`). `poll()` looped over the
  listed objects with no per-object isolation: if ANY object's `GET` failed
  (a network blip, transient S3 throttling/5xx, a malformed body), the
  exception propagated out of the whole batch **before the checkpoint had
  advanced**, so every object already ingested earlier in that same poll got
  **re-ingested (duplicate alerts) on every subsequent retry** — and if the
  failing object kept failing, the poller could get **permanently stuck**,
  never progressing past it. Each object's fetch+ingest is now isolated: a
  failure stops the batch (so ordering is preserved) but the checkpoint
  advances up to the last **successfully processed** key first, so retries
  never reprocess already-ingested objects and a transient failure clears on
  its own once the underlying condition does. Regression test: object 2 of 3
  fails, the checkpoint stops at object 1 (not re-listed/re-ingested on
  retry), and once the failure clears the poll resumes and finishes cleanly
  with no duplicate events. The other four files audited in this sweep
  (`routers/darkweb.py`, `leader.py`, `routers/stream.py`,
  `threat_api/retention.py`) were already correctly hardened — no changes.

### 2026-07-08 — Simple vs Power mode now curates the sidebar (frontend)
- **Wired the existing Normal/Power toggle (`TopBar`) to the backend org mode**
  (`GET`/`PUT /config/mode`, added in the entry below). The toggle previously
  only changed a localStorage flag with no effect on navigation; it now
  persists to the org (synced across devices/sessions) and the **Sidebar
  actually hides Power-only sections in Normal mode** — rule authoring,
  ATT&CK/UEBA, hunts, playbook building, dark-web, vuln/network scanning,
  custom connectors — while keeping the essentials (overview, SOC console,
  alert queue, log sources, cases, core CTI, feeds, asset inventory, config)
  visible in both. Fails open: until the backend responds (or if it's
  unreachable), the full nav shows — a UI preference never hides
  functionality it isn't certain about. New `useOrgFeatures()` hook shares one
  fetch across `TopBar`/`Sidebar` (mirrors the existing `usePermissions`
  cache pattern).
- **Fixed a fabricated data point found along the way**: the sidebar's
  "Active Alerts" badge was a hardcoded `7`, regardless of the real alert
  count. It now shows the real open (new + investigating) alert total, and
  the badge doesn't render at all until that's loaded (no placeholder number,
  no "0" flash).
- Verified: `tsc --noEmit`, `check:routes` (46 routes / 227 links, no dead
  links), and `npm run build` all clean.

### 2026-07-08 — Simple vs Power organization mode (backend)
- **Added an organization "mode" (`simple` | `power`)** so one deployment fits
  both a two-person shop and a mature SOC. `power` (default — zero behaviour
  change) surfaces the full feature set; `simple` curates an essentials-only
  subset (overview, SOC console, SIEM alert queue + sources, cases, core CTI +
  feeds, asset inventory, reports, config) and hides analyst-grade depth (rule
  authoring, ATT&CK/UEBA, hunts, playbook building, dark-web, vuln scanning,
  custom connectors, compliance). New `dashboard_api/modes.py` + `GET/PUT
  /config/mode` (GET any user, PUT gated by `config.manage`), persisted via the
  standard `settings` upsert (per-workspace under multi-tenancy, else global).
  **This is a UI-surfacing layer, not a security boundary** — every endpoint
  keeps enforcing its real capability via `permissions.py`; the mode only tells
  the frontend what to show. Unset/garbled values fail open to `power`.
- Added test coverage for `webhooks.py` (HMAC sign/verify, subscriber filtering,
  retry/SSRF-block behaviour) and the SOAR `playbook_engine.py` (dry-run vs live
  persistence, case creation, approval pause→resume/reject, and idempotent
  auto-trigger on a matching alert).

### 2026-07-05 — CI (Supply chain): fix `three` peer-dep conflict breaking SBOM
- **Fixed the `Supply chain` CI job (SBOM generation).** A frontend
  dependency-group bump had set `three: ^0.185.1` in package.json, but
  `postprocessing` (via `@react-three/postprocessing`) pins a peer
  `three: >=0.168.0 <0.185.0`, so the resolver kept `three@0.184.0` and the
  declared `^0.185.1` became unsatisfiable. `npm ci` and the build tolerate the
  peer conflict, but the SBOM step's `npm ls --json --long --all` fails hard on
  it (`ELSPROBLEMS … three@0.184.0 … invalid`). Pinned `three`/`@types/three`
  back to `^0.184.0` (the version already installed and shipped, so no runtime
  change) and regenerated the lock (also clearing an extraneous `@emnapi/runtime`).
  Verified: `npm ls --all` clean (exit 0), `tsc --noEmit`, `check:routes`, and
  `npm run build` all green.

### 2026-07-05 — CI (Postgres backend): fix ON CONFLICT translation + test isolation
- **Fixed the `backend-postgres` CI job (7 failures).** Two independent causes,
  both invisible to the local SQLite runs:
  - **sqlglot `ON CONFLICT` regression.** sqlglot 30.x (allowed by the wide
    `sqlglot>=25,<31` pin) parses SQLite `ON CONFLICT(col)` conflict targets as
    *ordered* expressions and the Postgres generator renders them as
    `col NULLS FIRST`, which Postgres rejects ("NULLS FIRST/LAST is not allowed
    in ON CONFLICT clause"). This broke every upsert on Postgres
    (`cve_catalogue`, `audit_sink_cursor`, `user_org_roles`). The translator
    (`db_backend._pg_transform`) now strips the ordering wrapper from conflict
    keys at the AST level, so the target renders as a bare column list —
    robust to further sqlglot rendering changes.
  - **`test_live_honesty` subprocess isolation.** The live-boot honesty tests
    spawn a subprocess against a throwaway SQLite DB but inherited
    `DASHBOARD_DB_BACKEND=postgres`/`DATABASE_URL` from the CI env, so they
    connected to the shared, already-populated Postgres and saw other tests'
    rows (19 users / 5470 alerts instead of a clean boot). The subprocess now
    forces the SQLite backend for genuine isolation.
  - Verified by running the full dashboard suite against a real local Postgres
    16 (mirroring the CI service): **459 passed, 2 skipped** (was 7 failed).
  - **Added a unit-level regression fence** (`test_pg_translation.py`): asserts
    `to_postgres` never emits `NULLS FIRST/LAST` in `ON CONFLICT` and preserves
    the conflict keys, for the app's real upsert shapes. It runs on both the
    sqlglot path (Postgres CI) and the regex fallback (SQLite CI), so a future
    transpiler bump that reintroduces the ordering wrapper fails fast at the unit
    level instead of only in the live-Postgres job.

### 2026-07-05 — vuln scan: zero-pad version compare (fix boundary miss)
- **Fixed a false-negative (and false-positive) in CVE version matching.** The
  version comparator built dotted-numeric tuples and compared them directly, so
  `2.0` and `2.0.0` compared as *unequal* (`(2,0) < (2,0,0)`). At a patch
  boundary that meant an asset on `2.0.0` was **missed** when an affected range
  topped out at `2.0` (a real vulnerable-host miss), and an asset on `2.0` was
  **falsely flagged** when the fix was `2.0.0`. Comparisons now zero-pad to
  equal length (`_ver_cmp`), so `2.0 == 2.0.0`; numeric (non-lexical) ordering
  (`1.10 > 1.9`) and inclusive/exclusive bounds are preserved. Test covers the
  boundary FP/FN and the padded equality across differing component counts.

### 2026-07-05 — dark-web: public email domains no longer poison leak matching
- **Fixed a false-positive flood in workforce credential-leak matching.**
  `watched_identities` derived the org's "owned" domains from *every* email in
  the user directory, so a single personal/SSO account on a public provider
  (e.g. `someone@gmail.com`) turned `gmail.com` into an owned domain — and
  `match_credential_leaks` then flagged **every unrelated leaked gmail/outlook/
  yahoo address** in a feed as a *"workforce credential leaked — force a reset"*
  **critical** notification. Public/free providers are now excluded from the
  domain-wide match (list extensible via `DASHBOARD_PUBLIC_EMAIL_DOMAINS`);
  corporate-domain matches and exact-email matches for those users still work.
  Regression test covers the unrelated-public / corporate-domain / exact-email
  cases. (First test coverage for `darkweb_logic`.)

### 2026-07-05 — self-review follow-up: `_to_confidence` overflow guard
- **Fixed a gap in the connector confidence-coercion hardening** found reviewing
  the session's own diff. `_to_confidence` caught `ValueError`/`TypeError` but
  not `OverflowError`, so a feed sending `confidence: "inf"` / `"Infinity"` /
  `"1e999"` still raised `int(float("inf"))` → `OverflowError` and aborted the
  whole import — the exact failure the coercion was meant to prevent. Now
  rejects non-finite values (NaN / ±inf / overflow) and falls back to the
  default. Extended the coercion test matrix with the non-finite cases.

### 2026-07-05 — NVD sync: one malformed CVE can't abort the catalogue
- **Fixed a whole-sync abort in the NVD → CVE-catalogue parser.**
  `nvd_to_catalogue` looped over the feed's CVE records with `float(baseScore
  or 0)` and nested CPE parsing but no per-record isolation, so a single record
  with a non-numeric `baseScore` (an NVD mirror/proxy quirk) or a non-dict entry
  would raise and **discard every other CVE in the sync**. Each record is now
  parsed in isolation (a bad one is skipped and logged), and `baseScore` coerces
  defensively to `0.0` instead of raising. Regression test mixes a good CVE with
  a bad-score record and junk entries and asserts the good ones still land.

### 2026-07-05 — RSS fetcher: ReDoS + OOM guards on hostile feed bodies
- **Fixed a ReDoS in the RSS/Atom IOC extractor.** The domain-matching regex
  `\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b` backtracks catastrophically on a crafted
  text blob (a long `a.a.a.…` run): `re.findall` took **8.5 s at 20k chars and
  >20 s at 40k** to conclude *no match*. RSS/Atom bodies are third-party and
  attacker-influenceable, so a compromised or hostile feed could stall the OSINT
  refresh thread. Fixed with a bounded extraction input (`_MAX_EXTRACT_CHARS`,
  20k — generous for a real item, hard-bounds the pathological case) plus a
  **possessive** outer quantifier (`(?:…)++`, Python 3.11+) that removes the
  backtracking path while matching real domains identically (<0.2 s worst case).
- **Capped the RSS feed body we buffer/parse** (`_get_capped`, 32 MB streamed):
  a multi-GB feed body can no longer be loaded whole into memory by
  `resp.text` / `ET.fromstring` (OOM). Mirrors the dashboard connector feed cap.
  3 tests: real-indicator extraction, sub-2 s on adversarial input, input cap.

### 2026-07-05 — OSINT refresh: a malformed feed value can't abort the batch
- **Fixed a whole-refresh abort in the CTI normalization stage.** `normalize_iocs`
  had no per-IOC isolation, and `_normalize_url`/`_normalize_domain` call
  `urlparse`, which raises `ValueError` on certain malformed inputs (e.g. an
  unclosed IPv6 bracket like `http://[`). A single such value from any OSINT
  source (abuse.ch / RSS / OTX / dark-web) would abort normalization for the
  **entire refresh — discarding every IOC from every source**. Now each IOC is
  normalized in isolation (a bad one is skipped/kept-raw, never fatal), and both
  URL/domain normalizers catch the `urlparse` `ValueError` and fall back to the
  raw value. Regression test mixes malformed values with good ones and asserts
  the good IOCs still come through.

### 2026-07-04 — ingest: one crafted line can't drop the whole batch
- **Fixed a batch-abort DoS on the log-ingest path** (the most attacker-adjacent
  surface — every forwarded line is untrusted). `ingest_lines` looped over the
  POSTed lines with no per-line isolation, and `_parse_json` caught only
  `ValueError`/`TypeError`. A single deeply-nested JSON line
  (`{"a":{"a":{…}}}`, small enough to pass the body cap) raised an unhandled
  `RecursionError` from the JSON decoder, which propagated out of the loop and
  **dropped every other line in the same POST while 500-ing the endpoint**. Now:
  (1) each line's parse is wrapped so any failure skips just that line (counted
  in a new `skipped` field), the rest ingest; (2) `_parse_json` also catches
  `RecursionError` (a deep line degrades to a generic log event); (3) `_flatten`
  has a depth cap (`_MAX_FLATTEN_DEPTH=64`) so ECS flattening can't recurse
  without bound; (4) the `/ingest/raw` whole-body JSON path returns 400 instead
  of 500 on a deep document. 3 tests: deep-line-doesn't-crash, bounded flatten,
  and one-bad-line-doesn't-drop-the-batch end-to-end.

### 2026-07-04 — detection engine: a broken rule can't blind the SIEM
- **Fixed a whole-SIEM denial-of-detection from one malformed rule.**
  `rule_engine.evaluate` did `int(agg["threshold"])` / `int(agg["windowMinutes"])`
  with no guard, so a detection rule stored with a non-numeric aggregation
  (`threshold: "high"`, `windowMinutes: "5m"` — an analyst typo or a malformed
  imported rule) raised `ValueError` *inside the per-batch detection loop*. That
  exception propagated out of `run_detection`, so **every other rule and event in
  that tick was skipped** — the SIEM silently stopped detecting until the rule
  was removed. Two-layer fix: (1) `evaluate` now coerces the aggregation numerics
  defensively (a broken threshold → the rule fires nothing, never raises); (2)
  `run_detection` wraps each rule's evaluation in try/except so *any* latent
  per-rule error is isolated and logged, and the rest of the batch still runs.
  Added authoring-time validation (`invalid_aggregation_in`) so create/update/
  backtest reject a broken aggregation with a clear 400, mirroring the existing
  ReDoS guard. 5 tests: coercion tolerance, the detector, API rejection, and a
  crashing-rule-doesn't-blind-the-batch end-to-end.

### 2026-07-04 — correlation engine: window-based grouping (no silent misses)
- **Fixed a real detection miss in the SOAR auto-escalation.**
  `_maybe_escalate_case` correlated only the **200 most-recent** unresolved
  critical/high alerts (`ORDER BY ts DESC LIMIT 200`) and bucketed them in
  Python. In a busy SOC — exactly what real feeds produce — once more than 200
  critical/high alerts are open, three genuinely-correlated alerts on one host
  could fall outside that window and **never escalate into a case**: a silent,
  volume-dependent incident miss. Correlation now groups **in SQL over a recency
  window** (`DASHBOARD_CORRELATION_WINDOW_HOURS`, default 48) with
  `GROUP BY <pivot> HAVING COUNT(*) >= 3`, so every in-window pivot is
  considered regardless of total open-alert volume, and the scan is bounded by
  time rather than an arbitrary row count. New regression test buries a real
  3-alert pivot behind 250 newer noise alerts and asserts the case still opens
  (this also fixes an intermittent full-suite test flake from the same cause).

### 2026-07-04 — connector parser robustness (messy real feeds)
- **A single malformed record no longer discards a whole feed import.** Every
  fetcher coerced feed-supplied confidence via `int(<value> or <default>)`, so a
  record with a non-numeric confidence (`"high"`, `"75%"`, `null`, `"n/a"`) —
  routine in real feeds — raised inside the per-record loop and aborted the
  entire import, silently dropping every good indicator in the batch. Added
  `_to_confidence`, which safely coerces ints/floats/numeric-strings/percent,
  clamps to `[0,100]`, and falls back to the default on junk; wired it into all
  fetchers (`threatorbit`, `json`/`csv`/`darkweb` field-map, `stix`) and the
  importer. Also guarded every per-record loop (`threatorbit`, `otx`, `nvd`,
  `stix`) with `isinstance` checks so a non-dict element in a feed array is
  skipped, not crashed, and non-object top-level responses raise a clear error.
  16 tests cover the coercion matrix and the "one bad row doesn't lose the feed"
  guarantee.

### 2026-07-04 — connector feed DoS guard (outbound OSINT fetch)
- **Fixed a memory-exhaustion DoS on the threat-intel connectors** — the
  scheduled outbound path that fetches attacker-adjacent, third-party feed URLs
  (NVD, OTX, custom JSON/CSV/STIX, dark-web). `_http_get`/`_http_post` called
  `httpx.get`/`.post`, which read the entire response body into memory before
  `.json()`/`.text`, so a compromised, hostile, or simply buggy feed returning a
  multi-GB body would OOM the dashboard — and the per-request `limit` params we
  send are advisory (a hostile server ignores them). Both fetchers now stream via
  a size-capped reader (`_read_capped`) that rejects any body past
  `_MAX_FEED_BYTES` (64 MB, env `DASHBOARD_MAX_FEED_BYTES`) with a `ValueError`;
  `run_connector` already records that as `last_error` with `status='error'`, so
  a flooding feed degrades one connector gracefully instead of taking down the
  service. SSRF re-validation at send time and per-connector error isolation were
  already in place; this closes the remaining unbounded-read gap. 4 tests cover
  the cap (boundary, under, over, end-to-end graceful degradation).

### 2026-07-03 — hunt console honesty + credential-page polish
- **SIEM hunt console:** a failed query no longer fabricates beacon results —
  it shows an honest "query couldn't run" error state instead. The header
  metric cards (previously hardcoded "47 queries today", "3 IOCs confirmed",
  …) are now derived from the real saved-hunt store (saved count, summed
  findings, distinct ATT&CK techniques, last-run hits). Removed the dead
  fabricated beacon-result constant.

### 2026-07-05 — correlation follow-up: collision-proof case ids
- **Hardened auto-escalation case-id generation.** Now that a single
  `_maybe_escalate_case` call can open several cases (it scans the whole
  correlation window, not a capped row set), the old `CASE-<4-digit-random>`
  id with a single retry could collide under load and throw an unhandled
  `IntegrityError` mid-loop, aborting the escalation. Ids are now allocated by
  retrying until free, with a wide `uuid`-suffixed fallback — so a busy tick
  that opens many cases never crashes on an id clash. Regression test forces
  every 4-digit draw to collide and asserts distinct cases still open.
- **Config → API keys/webhooks:** start empty instead of flashing fabricated
  key/webhook metadata before the API responds (a credentials page should
  never show fake keys, even for a moment); the demo set is an offline-only
  fallback.

### 2026-07-03 — syslog-listener DoS guard (network-exposed ingestion)
- **Fixed a memory-exhaustion DoS on the syslog TLS listener** — the primary
  network log path a deployment exposes (GOING_LIVE §3b). `deframe_syslog`
  read a leading octet-count and buffered until that many bytes arrived, so a
  client sending an over-long declared length (`999999999 …`) or an
  unterminated multi-MB line made the per-connection buffer grow without bound.
  It now rejects any frame past `MAX_SYSLOG_MSG` (64 KB) with a `ValueError`,
  and the TLS handler drops that connection instead of buffering. Also capped
  the file-watcher's per-poll read (`MAX_FILE_READ`, 8 MB) so a huge appended
  file drains over several polls rather than all into memory. UDP is already
  bounded by the 64 KB datagram size. (The stdlib collector agent was already
  well-covered by its own CI suite — 7 tests — and is unaffected.)

### 2026-07-03 — load/perf validation + detection-worker guardrail
- **Validated the published EPS limits** by running `bench.py` on 4 vCPU:
  ingest+detect ~8–13k EPS and detection-drain ~10k (1 worker) — meeting or
  exceeding `docs/LOAD_LIMITS.md`'s conservative baseline, so the README's
  "~10k ingest / ~7k detection" claim holds. Confirmed (and consistent with the
  docs) that the detection pool is *slower* at 4 workers than 1 on SQLite.
- **Startup guardrail:** the app now logs a warning if
  `DASHBOARD_DETECTION_WORKERS > 1` on the SQLite backend — that config has no
  throughput benefit and regresses under lock contention (it only helps on
  Postgres). Prevents a silent throughput footgun. Tests cover the warn/no-warn
  matrix and keep `bench.py` runnable.

### 2026-07-03 — deep fabrication sweep: hardcoded stats wired to real data
- **Overview "Security Posture" gauge** showed a hardcoded 74/100 "Good" with a
  fabricated "1 integration degraded". Now derived from the live org-risk score
  (health = 100 − risk), with a real band, matching the Normal dashboard.
- **Overview "System Status"** listed six services with invented health
  ("MISP Feed: Degraded", "ML Engine: Healthy", …). Replaced with the real
  reachability from `/services/status` — Dashboard API (up by definition), Threat
  API, Log Ingestion — Healthy / Unreachable / Checking, no fake rows.
- **SOAR Metrics KPI strip** fell back to hardcoded values (MTTD "4.2 min",
  Alert Volume "1,284", Automation "73%", …) when the store was empty; the values
  are wired to the live metrics but an empty real deployment showed the fake
  fallback. Now shows a neutral "—" placeholder; removed the dead fabricated
  fields (value/trend/trendLabel).
- **CTI actors** page init aligned to the honest pattern (empty until the API
  answers; the curated library is offline-only fallback).

### 2026-07-03 — closed the MSSP cross-org read gap (multi-tenancy)
- **Sub-resource GETs now enforce tenant isolation.** Several id-addressed reads
  took no caller and so couldn't run `cross_org`, leaking another workspace's
  linked data under multi-tenancy (worsened by guessable `CASE-####` ids):
  `soar/cases/{id}/related`, `assets/{id}/vulns`, `assets/{id}/activity`,
  `cti/attribution/case/{id}`, `cti/iocs/{id}/enrichment`. Each now 404s across
  workspaces.
- **Intel reports were missed from the tenancy pass entirely** — `intel_reports`
  had no `org_id`, so every workspace could read/edit/delete every other's
  reports. Added the column (schema v4 migration, default keeps single-tenant
  unchanged) and to `TENANT_TABLES`; scoped create (stamps org), list (filters),
  and read/MISP-export/patch/delete (404 cross-org). Guarded by
  `test_tenant_e2e.py`. All inert while `DASHBOARD_MULTI_TENANT` is off (the
  single-tenant default) — this closes the tracked pre-condition for enabling
  multi-tenancy on an MSSP build.

### 2026-07-03 — ingress body-size cap (DoS) + XSS verified clean
- **Fixed an ingest memory-exhaustion DoS.** `/siem/ingest` and `/siem/ingest/raw`
  read/parse the whole request body into memory *before* the 5000-line cap runs,
  so a multi-GB POST (or one enormous line) could exhaust memory. Added a
  pure-ASGI `BodySizeLimitMiddleware` that rejects an over-large body with 413 at
  the edge — a fast reject on a declared `content-length`, plus a streaming byte
  counter that bounds memory even for chunked/lying clients (`DASHBOARD_MAX_BODY_BYTES`,
  25 MB default).
- **Verified stored-XSS is closed** (no fix needed): a SIEM renders
  attacker-controlled log data to analysts, so this was checked end to end — the
  React UI has no `dangerouslySetInnerHTML` (auto-escaped), and both HTML report
  renderers (`dashboard_api/report_render.py`, `log_api/reporter/report.py`)
  escape every user-derived field.

### 2026-07-03 — ReDoS guard on detection rules + core-pipeline test
- **Fixed a detection-rule ReDoS (DoS).** `regex` conditions are analyst-authored
  and Python's `re` has no match timeout, so a catastrophic-backtracking pattern
  (e.g. `(a+)+$`) run against a crafted field hangs the detection thread —
  freezing the engine tick and, on the ingest path, the HTTP request (verified:
  `(a+)+$` on 35 chars runs >3s). Rules run per-event over every batch, so one
  bad pattern is a whole-deployment DoS. Added a conservative guard
  (`rule_engine.is_safe_regex`): unsafe patterns are rejected at authoring
  (create/update/backtest → 400 with clear feedback) and skipped at evaluation,
  and regex input is length-capped as defence in depth.
- **Core-pipeline end-to-end test** (`test_pipeline_e2e.py`): forwarded logs →
  detection rule fires → alert carries the right rule + MITRE (T1110 / Credential
  Access) → correlated critical alerts on one pivot auto-escalate into a SOAR
  case with the standard IR task list. Guards the product's central promise.

### 2026-07-03 — RBAC gap on write endpoints (security)
- **Fixed under-privileged write access.** Thirteen mutating endpoints were
  gated only by `current_user` (any authenticated principal) instead of the
  capability the catalogue documents, so a **read-scoped API key or a viewer
  user could write to shared SOC data** — inject forged events/alerts via
  `/siem/ingest[/raw]`, and most dangerously **edit/disable detection rules**
  (`PATCH /siem/rules/{id}`) to blind the SIEM. Also affected: SIEM sources &
  hunts, CTI hunts, asset create + fleet risk recompute, feed create/toggle,
  and the SOAR integration-test trigger. Each now enforces the right capability
  (`siem.write` / `cti.write` / `assets.write` / `connectors.manage` /
  `soar.write`); the write-scoped collector key (analyst role) is unaffected.
  Regression-tested: a viewer now gets 403 on all of them (and specifically
  cannot disable a rule), while an analyst still succeeds.

### 2026-07-02 — real-feeds hardening (sub-page sweep + prod-boot verification)
- **Fabrication sweep, round 2 (sub-pages).** Extended the empty-store honesty
  fix to the remaining surfaces: SOAR **integrations** (NOT seeded in live mode,
  so a real deployment showed fake Splunk/CrowdStrike connectors that
  misrepresented what SOAR could act on), the SIEM **hunt** console (no more
  pre-populated fake beacon results, and saved hunts start empty), and the CTI
  **hunt** campaigns (page + overview panel). Each shows the API's real response
  even when empty, with honest empty states, and falls back to the demo set only
  when the API is unreachable.
- **Production posture verified by boot test.** Confirmed `REQUIRE_SECRETS=true`
  aborts (exit 1) on a default admin password or a missing JWT secret, and that a
  clean live+engine-off boot with real secrets closes registration (403), pauses
  the engine (zero synthetic alerts), and returns empty stores — including zero
  integrations, proving the fabrication fix holds server-side.

### 2026-07-02 — real-feeds hardening + landing 3D fixes
- **No fabricated data on a real deployment.** Swept the dashboard for widgets
  that showed demo constants when their API store was empty — the exact state a
  fresh real-feeds install is in — and made each honest: the SIEM alert queue &
  MITRE distribution, SOAR cases & playbooks, the CTI feeds board (+ its
  `Math.random()` "incoming threat" simulator), CTI IOC-type counts, the assets
  inventory & fleet vulnerabilities all now start empty and render the API's
  real response (even when empty), falling back to the demo set ONLY when the
  API is unreachable (offline preview), never on an empty live store. The
  per-user admin drawer's fabricated "sessions" panel is removed and its
  activity log is wired to the real audit trail filtered by that user.
- **Production overlay — real feeds only, one command:**
  `docker-compose.prod.yml` pins live mode + `DASHBOARD_ENGINE=off` +
  `DASHBOARD_REQUIRE_SECRETS=true` + closed registration and makes a missing
  secret abort `up` rather than boot insecure. Documented in GOING_LIVE.
- **Landing 3D scenes fixed** — the IOC-network cluster and orbital scene (and
  the threat globe) no longer tear down their WebGL context on scroll (they
  latch mounted once seen, pausing the render loop off-screen instead), so they
  stop vanishing and re-appearing; both now preload their chunk so they render
  promptly instead of after several seconds; and the mobile device-pixel-ratio
  cap was raised (1.25–1.5 → 1.75–2, smooth AdaptiveDpr) to fix the pixelation
  on phones.

### 2026-07-02 — real-data readiness (go-live pass)
- **`DASHBOARD_ENGINE=off` — the real-data switch.** Live mode can now run with
  the synthetic-telemetry engine fully disabled: no first-boot priming, boots
  paused on every start (operator env wins; the UI toggle can still resume it
  deliberately). Wired through compose, Helm (`config.engine`) and
  `.env.example`.
- **`docs/GOING_LIVE.md`** — the production runbook: secrets/hardening gate,
  real-data mode, OSINT keys, and log forwarding from Windows/**Active
  Directory** (NXLog → `/siem/ingest/raw`, audit-policy prerequisites),
  **AWS/CloudTrail** (S3 puller), Linux (collector agent), and syslog senders —
  plus verification and day-2 operations. README points at it.
- **Honest empty states on Overview** — the Intel Brief no longer shows
  fabricated headlines badged "Live", the hourly timeline no longer renders a
  fake volume shape, and the MITRE heatmap no longer falls back to invented
  counts when the store is empty (fresh real-data installs start empty and now
  say so).
- **`windows-test.bat`** now installs the `-dev` requirement files — without
  them the FastAPI suites fail loudly on the missing `httpx2` (the pytest.ini
  deprecation gate). `windows-start.bat` re-verified end to end (launcher
  serving path smoke-tested).
- Live bootstrap no longer marks the admin as MFA-enrolled before a TOTP
  secret exists (the flag now honestly reflects enrolment state).

### 2026-07-02 — plan.md audit-fix pass
- **SP-signed SAML AuthnRequest (B9 residual)** — with `SAML_SP_PRIVATE_KEY` set
  the SP signs its AuthnRequest per the HTTP‑Redirect binding (detached
  SigAlg/Signature over the transmitted query octets, RSA‑ or ECDSA‑SHA256) for
  IdPs that require signed requests. Unset = unsigned, as before.
- **Audit sink: persisted cursor + replay** — delivery is now an outbox drain
  over the committed `audit_log` with a persisted cursor (`audit_sink_cursor`,
  schema v3): at‑least‑once across restarts and sink outages, in order, with
  backoff and a single drainer elected via the DB lease. Rolled‑back actions are
  no longer mirrored; consumers can dedupe on the shipped event `id`.
- **Multi‑tenancy end‑to‑end validation** (`tests/test_tenant_e2e.py`) — the
  full tenant journey through the real API; it caught and fixed five isolation
  gaps (manual‑alert workspace stamping; cross‑org guards on alert get/patch,
  asset get, case patch; per‑workspace IOC‑import dedup, removing a cross‑tenant
  existence oracle). Flipping `DASHBOARD_MULTI_TENANT` on is now purely a
  deployment decision.
- **Packaged scheduled-backup job** — opt‑in compose service
  (`--profile backup`, interval + retention pruning via `scripts/backup_loop.sh`)
  and a Helm CronJob (`backup.enabled`, dedicated PVC), both wrapping the same
  consistent tar.gz snapshot of all three databases.
- **PII handling & redaction** — `docs/PII_HANDLING.md` (what is stored where,
  retention/erasure reach, operator checklist) plus opt‑in
  `DASHBOARD_LOG_REDACT` redaction (email/secret/cc/ssn) applied to raw log text
  at the single ingest seam before persistence; detection pivots retained.
- **Theme tokens everywhere** — completed the `lib/colors.ts` migration across
  every dashboard page and shared panel (per‑page severity/status maps, SVG
  chart gradients, network‑topology hues, world‑map choropleth as an
  accent‑opacity ramp). Zero hardcoded theme hex remains in the dashboard;
  report print HTML and marketing 3D scenes stay fixed by design.
- Fixed a date‑rotted enrichment test (WHOIS "<30d = suspicious" fixture now
  computed relative to run time).

### Security & hardening
- **SSRF defence at send time** — outbound calls to user‑supplied URLs (webhooks,
  per‑user Slack routing, scheduled‑report delivery) re‑validate, pin the
  connection to a validated IP (defeating DNS rebinding / TOCTOU) and never follow
  redirects, while TLS still verifies against the real hostname.
- **SSE stream tickets** — the live event stream is opened with a short‑lived,
  single‑use ticket instead of the long‑lived JWT, so the session token is never
  placed in a URL/query string.
- **OIDC PKCE (S256)** and **mandatory SAML AudienceRestriction**; OIDC JWKS `kid`
  pinning (no first‑key fallback).
- **Content‑Security‑Policy + HSTS** on all delivery paths (nginx and both Vercel
  configs).
- Real **MFA (TOTP)** with recovery codes and per‑user TOTP‑counter replay
  protection; **secrets encryption at rest**; honest auth‑method selector.
- **Per‑install JWT secret**, PBKDF2‑HMAC‑SHA256 (600k) with self‑describing cost,
  constant‑time secret comparison, fail‑closed RBAC with audited denials.

### Responsive & cross‑device UX
- **Fluid page width** — content tracks the viewport (no fixed‑width gutters on
  wide / ultrawide displays), via a single `site-container` (`clamp` max‑width +
  scaling padding).
- **Touch‑friendly navigation** — hover‑to‑reveal sidebars switch to explicit
  tap‑to‑toggle on coarse pointers; mouse/trackpad keep the smooth hover.
- **Fluid dashboards too** — the Normal‑mode Overview fills wide screens with a
  12‑column layout instead of a narrow centred column (no empty side gutters).
- **Compact, persistent controls** — the assistant launcher and the Settings Save
  collapse to icons that expand on hover; Save floats top‑right so it's reachable
  from any scroll position. Network‑map zoom no longer wobbles on a held pinch.

### Platform & UX
- Real‑time push (in‑process pub/sub broker → SSE), notifications centre.
- Global search + command palette, deep‑linking, saved views / filters.
- Scheduled & emailed reports; onboarding wizard; 11 runtime themes; mobile‑responsive.
- **Multi‑format, multi‑audience reports** — every domain report exports as
  JSON / CSV / Markdown / printable HTML (PDF via browser print) and reshapes for
  the reader: Executive (compact), Technical (full depth), or Compliance (adds an
  ISO 27001 / SOC 2 control‑mapping section). All HTML output is escaped.
- **SOC Metrics fully live** — the alert‑volume trend and disposition split are
  now backed by real data (`/overview/alert-analytics`); no remaining "sample" charts.

### SIEM
- Detection rule editor; real log‑source ingestion (syslog/CEF/LEEF + vendor
  envelopes); field normalisation to ECS; UEBA per‑entity risk scoring.
- Alert tuning / false‑positive workflow; full ATT&CK navigator (coverage matrix);
  search/hunt language; threat‑intel matching.

### SOAR
- Visual playbook builder; credentialled real action integrations; automation
  triggers; case‑management depth (SLA, linkage); response approvals; post‑incident
  reporting.

### CTI
- Full STIX 2.1 / TAXII 2.1 server; relationship graph; enrichment pipeline
  (VirusTotal/GreyNoise/Shodan/WHOIS); IOC lifecycle; campaign & report management;
  attribution scoring.
- OSINT ingestion: OTX + abuse.ch + a pluggable RSS layer (curated leak/abuse and
  community feeds; dark‑web/social are RSS slots, not live collection).

### Assets & vulnerabilities
- Real vulnerability scanning; attack‑surface discovery; asset ↔ alert ↔ case
  linkage; dark‑web exposure surfacing.

### Enterprise
- SSO (OIDC + SAML 2.0 with XML‑signature‑wrapping defence and cert pinning) + SCIM;
  multi‑tenancy / workspaces with scale‑grade per‑workspace RBAC; billing/licensing;
  audit & compliance pack.

### Data, scale & ops
- Opt‑in Postgres backend (validated against a live server in CI); retention
  tiering with S3 archival; collector ecosystem + API‑stability contract;
  background‑service HA story; performance work (row virtualisation, indexing).
- Backup / restore / upgrade path with a schema‑version gate; deployment hardening
  (digest‑pinned non‑root images, healthchecks); observability baseline.

### Testing & quality
- Dashboard suite plus unit tests for the `threat_api` transform pipeline
  (normalise/correlate/trust/STIX) and the `log_api` parsers and pattern /
  statistical / temporal / ML detectors; Playwright E2E in CI; `pip-audit` across
  all three services.
- **TestClient on `httpx2`** — migrated the FastAPI/Starlette `TestClient` to its
  sanctioned successor (`httpx2`) as a *test‑only* dependency; production keeps the
  stable `httpx` (SSRF guard etc. unchanged). Each service's `pytest.ini` errors on
  `StarletteDeprecationWarning`, so a missing httpx2 fails CI loudly rather than
  silently regressing to the deprecated shim.

[Unreleased]: https://github.com/Sami9211/ThreatOrbit-V2/commits/main
