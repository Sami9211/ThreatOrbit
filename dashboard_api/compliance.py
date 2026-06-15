"""Security control mapping (SOC 2 Trust Services Criteria + ISO/IEC 27001:2022).

A procurement-facing matrix of the controls ThreatOrbit *actually* implements,
each pointing at real evidence in this codebase, with honest `status`
(implemented / partial / planned). This is a **self-assessment** to speed
security review - NOT a SOC 2 report or an ISO certification, which require an
independent auditor. Gaps (e.g. a third-party penetration test, a formal audit)
are listed as `planned`, not hidden.

Single source of truth for `GET /compliance/controls` and docs/COMPLIANCE.md.
"""

DISCLAIMER = (
    "Self-assessment of implemented security controls mapped to SOC 2 (TSC) and "
    "ISO/IEC 27001:2022 Annex A, with evidence in-repo. This is NOT a SOC 2 "
    "report or an ISO certification (those require an independent auditor). "
    "Items marked 'planned' are not yet in place."
)

# status ∈ implemented | partial | planned
CONTROLS = [
    {"id": "AC-MFA", "title": "Multi-factor authentication (TOTP)",
     "soc2": ["CC6.1", "CC6.6"], "iso27001": ["A.8.5"], "status": "implemented",
     "evidence": ["dashboard_api/mfa.py", "TOTP enrolment + verification, secret encrypted at rest"]},
    {"id": "AC-RBAC", "title": "Role-based access control (capability-based, least privilege)",
     "soc2": ["CC6.1", "CC6.3"], "iso27001": ["A.5.15", "A.8.2"], "status": "implemented",
     "evidence": ["dashboard_api/permissions.py", "require_perm() on privileged routes; denials audited"]},
    {"id": "AC-SSO", "title": "Single sign-on (OIDC + SAML 2.0)",
     "soc2": ["CC6.1"], "iso27001": ["A.8.5"], "status": "implemented",
     "evidence": ["dashboard_api/oidc.py", "dashboard_api/saml.py",
                  "signature-verified assertions, JIT provisioning"]},
    {"id": "AC-LIFECYCLE", "title": "Automated user provisioning + deprovisioning (SCIM 2.0)",
     "soc2": ["CC6.2", "CC6.3"], "iso27001": ["A.5.16", "A.5.18"], "status": "implemented",
     "evidence": ["dashboard_api/scim.py", "IdP-driven deactivation of departed users"]},
    {"id": "AC-PWD", "title": "Password storage + brute-force resistance",
     "soc2": ["CC6.1"], "iso27001": ["A.8.5"], "status": "implemented",
     "evidence": ["dashboard_api/auth.py", "PBKDF2-HMAC-SHA256 600k iters; login throttling"]},
    {"id": "CR-REST", "title": "Encryption of secrets at rest",
     "soc2": ["CC6.7"], "iso27001": ["A.8.24"], "status": "implemented",
     "evidence": ["dashboard_api/secretstore.py", "Fernet (AES-128-CBC + HMAC); DASHBOARD_ENCRYPTION_KEY"]},
    {"id": "CR-TRANSIT", "title": "Encryption in transit (TLS)",
     "soc2": ["CC6.7"], "iso27001": ["A.8.24"], "status": "partial",
     "evidence": ["docs/DEPLOYMENT.md", "terminated at the reverse proxy (deployment-provided)"]},
    {"id": "LOG-AUDIT", "title": "Audit logging of security-relevant actions",
     "soc2": ["CC7.2", "CC7.3"], "iso27001": ["A.8.15"], "status": "implemented",
     "evidence": ["dashboard_api/db.py audit()", "auth, rule, content, SCIM, config events"]},
    {"id": "LOG-MON", "title": "Security monitoring + metrics",
     "soc2": ["CC7.1"], "iso27001": ["A.8.16"], "status": "implemented",
     "evidence": ["dashboard_api/observability.py", "Prometheus metrics incl. pipeline backpressure"]},
    {"id": "NET-SSRF", "title": "Outbound request hardening (SSRF guard)",
     "soc2": ["CC6.6"], "iso27001": ["A.8.20", "A.8.21"], "status": "implemented",
     "evidence": ["dashboard_api/net_guard.py", "blocks private/link-local/metadata targets"]},
    {"id": "NET-HDRS", "title": "HTTP security headers",
     "soc2": ["CC6.6"], "iso27001": ["A.8.23"], "status": "implemented",
     "evidence": ["dashboard_api/observability.py SecurityHeadersMiddleware"]},
    {"id": "INT-EVID", "title": "Tamper-evident records (signed evidence bundles)",
     "soc2": ["CC7.3"], "iso27001": ["A.5.28"], "status": "implemented",
     "evidence": ["dashboard_api/evidence.py", "HMAC-signed case evidence exports"]},
    {"id": "CM-SUPPLY", "title": "Secure SDLC + supply-chain integrity",
     "soc2": ["CC8.1"], "iso27001": ["A.8.28", "A.8.30"], "status": "implemented",
     "evidence": [".github/workflows/supply-chain.yml", ".github/workflows/release.yml",
                  "SBOM, digest-pinned images, cosign-signed + SLSA-provenance releases"]},
    {"id": "VM-DEPS", "title": "Vulnerability + dependency management",
     "soc2": ["CC7.1"], "iso27001": ["A.8.8"], "status": "implemented",
     "evidence": [".github/workflows/security.yml", ".github/dependabot.yml",
                  "pip-audit + npm audit gate, Trivy, automated updates"]},
    {"id": "AV-BACKUP", "title": "Backup + tested restore (availability)",
     "soc2": ["A1.2"], "iso27001": ["A.8.13"], "status": "implemented",
     "evidence": ["dashboard_api/backup.py", "docs/BACKUP_RESTORE.md",
                  "consistent snapshots + automated restore drill in CI"]},
    {"id": "AV-BACKPRESSURE", "title": "Capacity / backpressure handling",
     "soc2": ["A1.1"], "iso27001": ["A.8.6"], "status": "partial",
     "evidence": ["dashboard_api/event_queue.py", "bounded ingest (429) + lag metrics; single-node today"]},
    {"id": "AV-HA", "title": "High availability / failover",
     "soc2": ["A1.2"], "iso27001": ["A.8.14"], "status": "planned",
     "evidence": ["single-instance background services today; multi-AZ guidance pending"]},
    {"id": "RM-PENTEST", "title": "Independent penetration test",
     "soc2": ["CC4.1"], "iso27001": ["A.8.29"], "status": "planned",
     "evidence": ["SECURITY.md", "pre-sale requirement; not yet performed"]},
    {"id": "RM-AUDIT", "title": "Independent SOC 2 / ISO 27001 audit",
     "soc2": ["CC4.1"], "iso27001": ["A.5.35"], "status": "planned",
     "evidence": ["this matrix is a self-assessment, not a certification"]},
]

_STATUSES = {"implemented", "partial", "planned"}


def summary() -> dict:
    counts = {s: 0 for s in _STATUSES}
    for c in CONTROLS:
        counts[c["status"]] += 1
    return {"total": len(CONTROLS), **counts}


def as_dict() -> dict:
    return {"disclaimer": DISCLAIMER, "frameworks": ["SOC 2 (TSC)", "ISO/IEC 27001:2022"],
            "summary": summary(), "controls": CONTROLS}
