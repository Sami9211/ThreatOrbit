# Security control mapping (SOC 2 / ISO 27001)

> **This is a self-assessment, not a certification.** It maps the security
> controls ThreatOrbit *actually implements* to SOC 2 Trust Services Criteria
> and ISO/IEC 27001:2022 Annex A, with evidence in this repository, to speed a
> buyer's security review. A SOC 2 report or ISO certification requires an
> **independent auditor** — items below marked *planned* (including a
> third-party penetration test and a formal audit) are **not yet in place** and
> are listed honestly rather than omitted.

The machine-readable source of truth is `dashboard_api/compliance.py`, also
served at `GET /compliance/controls` for an in-product view / questionnaire
auto-fill.

## Implemented

| Control | SOC 2 | ISO 27001 | Evidence |
|---|---|---|---|
| MFA (TOTP) | CC6.1, CC6.6 | A.8.5 | `mfa.py` |
| RBAC, least privilege | CC6.1, CC6.3 | A.5.15, A.8.2 | `permissions.py` (audited denials) |
| SSO — OIDC + SAML 2.0 | CC6.1 | A.8.5 | `oidc.py`, `saml.py` (signature-verified) |
| Provisioning + **deprovisioning** (SCIM) | CC6.2, CC6.3 | A.5.16, A.5.18 | `scim.py` |
| Password storage + throttling | CC6.1 | A.8.5 | `auth.py` (PBKDF2 600k) |
| Secrets encrypted at rest | CC6.7 | A.8.24 | `secretstore.py` (Fernet) |
| Audit logging | CC7.2, CC7.3 | A.8.15 | `db.audit()` |
| Security monitoring/metrics | CC7.1 | A.8.16 | `observability.py` |
| SSRF guard | CC6.6 | A.8.20, A.8.21 | `net_guard.py` |
| HTTP security headers | CC6.6 | A.8.23 | `observability.py` |
| Tamper-evident evidence bundles | CC7.3 | A.5.28 | `evidence.py` (HMAC-signed) |
| Data-subject rights (GDPR export + erasure) | P5.1, P4.2 | A.5.34 | `privacy.py` (`/privacy` export + anonymising erase) |
| Secure SDLC / supply chain | CC8.1 | A.8.28, A.8.30 | `supply-chain.yml`, `release.yml` (SBOM, signed + SLSA) |
| Vulnerability/dependency mgmt | CC7.1 | A.8.8 | `security.yml`, `dependabot.yml` |
| Backup + tested restore | A1.2 | A.8.13 | `backup.py`, `docs/BACKUP_RESTORE.md` (CI restore drill) |

## Partial

| Control | Why partial |
|---|---|
| TLS in transit (CC6.7 / A.8.24) | Terminated at the deployment's reverse proxy — see `docs/DEPLOYMENT.md` |
| Capacity / backpressure (A1.1 / A.8.6) | Bounded ingest (429) + lag metrics shipped; still single-node |

## Planned (honest gaps)

| Control | Status |
|---|---|
| High availability / failover (A1.2 / A.8.14) | Single-instance background services today; multi-AZ guidance pending |
| Independent penetration test (CC4.1 / A.8.29) | Pre-sale requirement; **not yet performed** (`SECURITY.md`) |
| Independent SOC 2 / ISO audit (CC4.1 / A.5.35) | This matrix is a self-assessment, not a certification |

Keep this file and `dashboard_api/compliance.py` in sync; `test_compliance.py`
guards the data's shape and honesty (every control cites evidence; gaps stay
visible).
