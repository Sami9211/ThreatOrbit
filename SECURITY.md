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

- Dependency audits in CI (`.github/workflows/security.yml`): `pip-audit`
  on the backend and an npm-audit gate with an **expiring allowlist** on the
  frontend — every triaged advisory carries a reason and an expiry date, and
  the build goes red when either a new high/critical advisory appears or a
  triage decision expires.
- Secrets encrypted at rest (Fernet, `DASHBOARD_ENCRYPTION_KEY`), TOTP MFA,
  capability-based RBAC with audited denials, login throttling, security
  headers on every API response, signed evidence bundles.
- Hardening + operations runbooks: `docs/DEPLOYMENT.md`,
  `docs/OPERATIONS.md`.

## Known triaged advisories

| Advisory | Component | Why accepted | Until |
|---|---|---|---|
| 14× Next.js server CVEs (see `frontend/.audit-allowlist.json`) | next 14.x | production deploys the **static export** — no Next server runs; real fix is the next@16 major upgrade (tracked in plan.md) | 2026-09-30 |
| PYSEC-2026-161 | starlette | Host-header validation; fix needs starlette ≥1.0.1, unsupported by any FastAPI yet. Reference proxy configs pin Host; the API builds no absolute URLs from it | FastAPI ceiling moves |

A third-party penetration test is a pre-sale requirement (plan.md Tier 1)
and has **not** been performed yet — this file does not claim otherwise.
