# Security policy

## Reporting a vulnerability

Email **security@threatorbit.space** (or open a GitHub *private* security
advisory on this repository). Include reproduction steps, affected
version/commit, and impact as you understand it. Please do **not** open a
public issue for an unpatched vulnerability.

What you can expect:

| Stage | Target |
|---|---|
| Acknowledgement | 2 business days |
| Triage + severity assessment | 7 days |
| Fix or documented mitigation for High/Critical | 30 days |
| Coordinated disclosure | after a fix ships, credited if you want |

## Supported versions

The `main` branch is the supported line; fixes land there first. Deployments
should track tagged releases and apply security releases promptly (the
upgrade contract is additive-only migrations — see `docs/OPERATIONS.md`).

## What's already in place

- Dependency audits **and automated updates** in CI: `.github/workflows/
  security.yml` runs `pip-audit` + an npm-audit gate with an **expiring
  allowlist** (every triaged advisory carries a reason + expiry; the build goes
  red on a new high/critical or an expired triage), and **`dependabot.yml`**
  opens grouped weekly update PRs across all four services + the CI actions
  (security PRs immediately) while **`dependabot-auto-merge.yml`** merges safe
  patch/minor bumps once the test gates pass. Honest status (2026-06-14): the
  Next.js 14 advisories were **cleared by upgrading to next@16** (production
  audit has no high/critical; React stays on 18), and `threat_api`'s vulnerable
  `flask-cors` 4.0.1 was fixed (>=6.0.1).
- **Supply-chain evidence + scanning** (`.github/workflows/supply-chain.yml`):
  CycloneDX **SBOMs** (backend + frontend) published as artifacts on every run,
  **Trivy** scanning for vulnerable deps + committed secrets (fails on a fixable
  CRITICAL) and Docker/IaC misconfigurations, and Dependabot tracking the
  container **base images**. A separate `docker-build.yml` **build-validates all
  four service images** (build-only, no push) so a base-image or dependency bump
  can't merge green and break only at deploy.
- **Digest-pinned base images + signed releases.** All four Dockerfiles pin
  their base image by immutable `@sha256:` digest, so a build can't silently
  inherit a re-pushed tag (Dependabot keeps the digests current). The
  tag-triggered `release.yml` workflow ships each release with **cosign keyless
  signatures** (Sigstore Fulcio + Rekor transparency log — no long-lived key)
  over the SBOMs, source archive, and checksums, plus **SLSA3 build provenance**
  (in-toto) from the official generator. Verification commands are in the
  workflow header. Remaining (tracked in `plan.md`): signing published container
  images once a registry-push pipeline exists. (The react@19 + react-three-fiber
  v9 upgrade landed 2026-06-14, leaving the frontend on current majors.)
- Secrets encrypted at rest (Fernet, `DASHBOARD_ENCRYPTION_KEY`), TOTP MFA,
  capability-based RBAC with audited denials, login throttling, security
  headers on every API response, signed evidence bundles.
- **Identity lifecycle**: optional OIDC SSO (ID-token RS256 verification) and
  **SCIM 2.0 provisioning** (bearer-token `/scim/v2`) so an IdP can
  automatically *deactivate* departed users — closing the "ex-employee keeps
  access" gap. Both degrade to off when unconfigured; email+password is
  unaffected.
- **SSRF guard** (`net_guard.py`) on every user-supplied outbound URL
  (webhooks, custom connectors, personal Slack routing): http/https only, and
  the local host plus private / link-local / reserved ranges (incl. the cloud
  metadata endpoint) are rejected. Override for local dev with
  `DASHBOARD_ALLOW_PRIVATE_URLS=true`.
- **No shared default secrets.** When `DASHBOARD_JWT_SECRET` is unset the API
  generates and persists a per-install random secret rather than using a known
  default. `DASHBOARD_REQUIRE_SECRETS=true` (or `DASHBOARD_ENV=production`)
  makes explicit secrets and a non-default admin password mandatory, and a
  wildcard `DASHBOARD_CORS_ORIGINS` is refused because credentials are enabled.
- **Password hashing** PBKDF2-HMAC-SHA256 at 600k iterations (OWASP/NIST
  2023+), with self-describing hashes so the cost can rise without breaking
  existing logins. **Constant-time** API-key comparison on the Threat API.
  Tenant detail reads (`/cti/actors|iocs/{id}`, `/soar/cases/{id}`) are
  org-scoped under multi-tenancy. HTML reports escape user-controlled fields.
- Hardening + operations runbooks: `docs/DEPLOYMENT.md`,
  `docs/OPERATIONS.md`.

## Known triaged advisories

| Advisory | Component | Why accepted | Until |
|---|---|---|---|
| 2× moderate postcss (CSS-stringify XSS) | build tooling | Reached only during the build (processing our own CSS), not at runtime; below the gate's high/critical threshold | next minor bump |
| PYSEC-2026-161 | starlette | Host-header validation; fix needs starlette ≥1.0.1, unsupported by any FastAPI yet. Reference proxy configs pin Host; the API builds no absolute URLs from it | FastAPI ceiling moves |

_Resolved: the 14 Next.js 14 server advisories were **fixed** by upgrading to next@16 (2026-06-14), not just triaged._

A third-party penetration test is a pre-sale requirement (plan.md Tier 1)
and has **not** been performed yet — this file does not claim otherwise.
