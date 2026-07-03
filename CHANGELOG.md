# Changelog

All notable changes to ThreatOrbit‑V2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project tracks the
roadmap in [`plan.md`](plan.md) (completed roadmap items land here).

> Status framing lives in the README's **"Project status — read this first"**
> and **§15 Limitations & honest caveats** — read those before pitching this.

## [Unreleased]

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
