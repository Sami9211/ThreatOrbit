# Changelog

All notable changes to ThreatOrbit‑V2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project tracks the
roadmap in [`plan.md`](plan.md) (completed roadmap items land here).

> Status framing lives in the README's **"Project status — read this first"**
> and **§15 Limitations & honest caveats** — read those before pitching this.

## [Unreleased]

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

### Platform & UX
- Real‑time push (in‑process pub/sub broker → SSE), notifications centre.
- Global search + command palette, deep‑linking, saved views / filters.
- Scheduled & emailed reports; onboarding wizard; 11 runtime themes; mobile‑responsive.

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
