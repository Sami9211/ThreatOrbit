# Data Processing Agreement (DPA) — template

> **This is a template, not legal advice.** It is provided to speed an
> enterprise procurement / privacy review. Have it reviewed by qualified counsel
> and adapted to your jurisdiction and the specific deployment before signing.
> Bracketed `[…]` fields must be completed. Where this template and a signed
> master agreement conflict, the signed agreement governs.

This DPA forms part of the agreement (the **"Principal Agreement"**) between:

- **[Customer legal name]** (the **"Controller"** / "Customer"), and
- **[Vendor legal name]** operating **ThreatOrbit** (the **"Processor"**),

each a "party" and together the "parties", and reflects the parties' agreement on
the processing of Personal Data in connection with the ThreatOrbit platform (the
**"Service"**) under the EU General Data Protection Regulation (Regulation (EU)
2016/679, **"GDPR"**) and, where applicable, the UK GDPR and other Data
Protection Laws.

## 0. Deployment model — read first

ThreatOrbit can run in two ways, and the processing roles differ:

- **Self-hosted / customer-operated.** The Customer runs the Service on
  infrastructure it controls (see `docs/DEPLOYMENT.md`, `deploy/helm/`). The
  Processor has **no access** to Personal Data processed in that deployment and
  is **not a processor** of it. The Processor acts as a processor only for any
  diagnostic, support, or telemetry data the Customer chooses to share (e.g. when
  raising a support request). Sections 4–9 then apply only to that shared data.
- **Managed / SaaS (Processor-operated).** The Processor hosts the Service for
  the Customer and processes Customer Personal Data on the Customer's behalf.
  The full DPA applies.

Select the applicable model in **Annex I**.

## 1. Definitions

Terms not defined here have the meaning in the GDPR. "**Personal Data**",
"**Processing**", "**Controller**", "**Processor**", "**Sub-processor**",
"**Data Subject**", "**Supervisory Authority**", and "**Personal Data Breach**"
have the meanings in Art. 4 GDPR. "**Data Protection Laws**" means all laws
applicable to the Processing of Personal Data under the Principal Agreement,
including the GDPR and UK GDPR. "**Customer Personal Data**" means Personal Data
that the Processor Processes on behalf of the Customer under the Service.

## 2. Roles and scope

2.1 As between the parties, the **Customer is the Controller** (or processor
acting for a third-party controller) and **ThreatOrbit is the Processor** of
Customer Personal Data. The Customer's instructions are described in this DPA and
the Principal Agreement.

2.2 The subject-matter, duration, nature and purpose of the Processing, the types
of Personal Data, and the categories of Data Subjects are set out in **Annex I**.

2.3 The Customer is responsible for the lawfulness of the Personal Data it (and
its users) submit to the Service and for having an appropriate legal basis.

## 3. Processor obligations (Art. 28(3))

The Processor shall:

3.1 **Documented instructions.** Process Customer Personal Data only on the
Customer's documented instructions (including this DPA and Customer's use/
configuration of the Service), unless required by EU/Member-State law, in which
case it informs the Customer first unless that law prohibits it.

3.2 **Confidentiality.** Ensure persons authorised to Process Customer Personal
Data are bound by confidentiality.

3.3 **Security.** Implement the technical and organisational measures in
**Annex II** (Art. 32). The Customer acknowledges those measures may evolve; the
Processor will not materially reduce the overall level of security during the
term.

3.4 **Sub-processors.** Engage Sub-processors only under Section 5.

3.5 **Data-subject requests.** Assist the Customer, by appropriate technical and
organisational measures and insofar as possible, to respond to Data-Subject
requests (Section 6).

3.6 **Assistance.** Assist the Customer in ensuring compliance with Art. 32–36
(security, breach notification, DPIAs and prior consultation), taking into
account the nature of Processing and the information available to the Processor.

3.7 **Deletion or return.** At the Customer's choice, delete or return all
Customer Personal Data at the end of the provision of the Service (Section 7).

3.8 **Audit.** Make available information necessary to demonstrate compliance
with Art. 28 and allow for and contribute to audits (Section 8).

3.9 **Instruction conflicts.** Immediately inform the Customer if, in its
opinion, an instruction infringes Data Protection Laws.

## 4. Security of Processing (Art. 32)

The Processor maintains the technical and organisational measures described in
**Annex II**, designed to ensure a level of security appropriate to the risk,
including pseudonymisation/encryption where appropriate, confidentiality,
integrity, availability and resilience, and regular testing of effectiveness.

## 5. Sub-processors (Art. 28(2) & (4))

5.1 The Customer provides **general authorisation** for the Processor to engage
the Sub-processors listed in **Annex III**.

5.2 **Changes.** The Processor will give the Customer at least **[30] days'**
prior notice (e.g. by email or an updated Annex III) of any intended addition or
replacement of a Sub-processor, giving the Customer the opportunity to **object**
on reasonable data-protection grounds. If the parties cannot resolve a
good-faith objection, the Customer may terminate the affected part of the Service
as its exclusive remedy.

5.3 **Flow-down.** The Processor imposes data-protection obligations on each
Sub-processor that are no less protective than those in this DPA and remains
liable for the Sub-processor's performance.

5.4 In a **self-hosted** deployment, the Customer selects its own infrastructure
and any optional integrations (Annex III), and is responsible for engaging those
as Sub-processors under its own DPAs.

## 6. Data-subject rights

The Service provides tooling so the Customer can fulfil Data-Subject rights
without bespoke engineering (see Annex II):

- **Access / portability** — self-service export (`GET /privacy/me`) and an
  admin export of a subject's data (`GET /privacy/export/{user_id}`), returned as
  structured JSON.
- **Erasure (right to be forgotten)** — `POST /privacy/erase/{user_id}`
  **anonymises** the subject's PII and disables the account (operational and
  audit integrity are preserved by replacing rather than hard-deleting linked
  records), satisfying Art. 17 by rendering data no longer attributable.
- **Rectification / restriction** — user-management endpoints let the Customer
  correct or disable accounts.

If the Processor receives a Data-Subject request directly, it will (unless legally
required to act) refer the Data Subject to the Customer and notify the Customer.

## 7. Personal Data Breach (Art. 33–34)

7.1 The Processor will notify the Customer **without undue delay, and in any
event within [48] hours**, after becoming aware of a Personal Data Breach
affecting Customer Personal Data.

7.2 The notification will, to the extent known, describe the nature of the
breach, likely consequences, measures taken/proposed, and a contact point, and
will be supplemented as more information becomes available. The Processor
maintains an audit trail (Annex II) to support investigation and notification.

7.3 The Processor does not assess whether the Customer must notify a Supervisory
Authority or Data Subjects; that determination rests with the Customer as
Controller.

## 8. Audits (Art. 28(3)(h))

8.1 The Processor makes available its security control self-assessment
(`docs/COMPLIANCE.md` / `GET /compliance/controls`, mapping implemented controls
to SOC 2 TSC and ISO 27001 Annex A with in-repo evidence) and, where available,
third-party audit reports and penetration-test summaries.

8.2 Where that information is insufficient, the Customer may request an audit no
more than **once per 12 months** (or after a Personal Data Breach), on
**[30] days'** notice, during business hours, subject to confidentiality and
without unreasonably disrupting the Processor's operations. The parties bear
their own costs unless the audit reveals a material breach by the Processor.

> **Honest note:** as of the date of this template, ThreatOrbit has **not** yet
> completed an independent SOC 2 Type II or ISO 27001 audit or a third-party
> penetration test (see `SECURITY.md`, `docs/COMPLIANCE.md`). Those are tracked
> as pre-GA items; do not represent them as completed.

## 9. Deletion or return (Art. 28(3)(g))

On termination or expiry of the Service, and at the Customer's choice, the
Processor will return and/or delete Customer Personal Data within **[30] days**,
and delete existing copies unless EU/Member-State law requires storage. The
Service provides export (Section 6) and **retention enforcement** with optional
**cold-storage archival before purge** (Annex II) to support this. In a
self-hosted deployment, deletion/return is performed by the Customer.

## 10. International transfers

10.1 The Processor will not transfer Customer Personal Data outside the EEA/UK
except in compliance with Chapter V GDPR (e.g. an adequacy decision or the EU
**Standard Contractual Clauses**, which are incorporated by reference where
relevant and completed in **Annex IV**).

10.2 In a self-hosted deployment, the Customer controls where the Service runs
and therefore controls **data residency** directly.

## 11. General

11.1 **Liability** is subject to the limitations in the Principal Agreement.
11.2 **Order of precedence:** this DPA prevails over the Principal Agreement on
the subject of Personal Data processing; the SCCs (Annex IV) prevail over this
DPA on the subject of restricted transfers.
11.3 **Governing law:** [governing law / jurisdiction], consistent with the
Principal Agreement.
11.4 **Term:** this DPA runs for as long as the Processor Processes Customer
Personal Data under the Principal Agreement.

---

## Annex I — Details of Processing

| Item | Detail |
|---|---|
| **Deployment model** | ☐ Self-hosted (Customer-operated) ☐ Managed / SaaS (Processor-operated) |
| **Subject matter** | Provision of the ThreatOrbit SIEM/SOAR/CTI/Asset/Dark-Web security platform |
| **Duration** | The term of the Principal Agreement |
| **Nature & purpose** | Collection, storage, organisation, analysis, alerting and reporting of security telemetry and platform-user account data to deliver security monitoring and response |
| **Categories of Data Subjects** | The Customer's platform **users/operators** (analysts, admins); **individuals appearing in ingested security telemetry** (e.g. usernames, source IPs in logs/events); individuals named in threat-intelligence or dark-web findings the Customer ingests |
| **Categories of Personal Data** | Account data (name, email, role, hashed credentials, MFA secrets — encrypted, audit/login metadata); telemetry-derived identifiers (usernames, IP addresses, hostnames, device/process names) within ingested events/alerts; any Personal Data the Customer chooses to ingest |
| **Special categories (Art. 9)** | None intended. The Customer must not ingest special-category data unless it has a lawful basis and has configured appropriate safeguards |
| **Frequency** | Continuous, for the term |

## Annex II — Technical & Organisational Measures (Art. 32)

Grounded in controls the Service **actually implements** (evidence in the
repository; see `docs/COMPLIANCE.md` for the full SOC 2 / ISO 27001 mapping):

| Measure | Implementation |
|---|---|
| **Access control** | Role-based access control with least privilege and audited denials (`permissions.py`); enforced on every endpoint |
| **Authentication** | Passwords hashed with PBKDF2-HMAC-SHA256 (600k iterations) + login throttling (`auth.py`); **TOTP MFA** with one-time recovery codes (`mfa.py`); password screening against common/breached passwords |
| **Enterprise identity** | SSO via OIDC and signature-verified SAML 2.0; SCIM provisioning **and deprovisioning** (`sso.py`, `saml.py`, `scim.py`) |
| **Session security** | Revocable sessions (per-user token epoch), per-device session list + individual revoke, idle timeout |
| **Encryption at rest** | Application secrets (TOTP secrets, integration tokens, webhook URLs) encrypted with Fernet (`secretstore.py`); database/disk encryption is provided by the deployment environment |
| **Encryption in transit** | TLS terminated at the deployment's reverse proxy/ingress (`docs/DEPLOYMENT.md`, `deploy/helm/`) |
| **Network protection** | SSRF guard on all outbound/user-supplied URLs (`net_guard.py`); HTTP security headers (`observability.py`) |
| **Audit & monitoring** | Tamper-evident audit logging of state changes (`db.audit()`), optionally **streamed to an external/immutable sink** for tamper-evidence; platform metrics (`observability.py`); HMAC-signed evidence bundles (`evidence.py`) |
| **Data-subject tooling** | GDPR export + anonymising erasure (`privacy.py`, `/privacy/*`) |
| **Data lifecycle** | Configurable retention enforcement with optional compressed cold-storage archival **before** purge |
| **Multi-tenancy isolation** | Per-org data scoping on list endpoints, global search and the live SSE stream (when multi-tenant mode is enabled) |
| **Resilience / backup** | Full-stack backup with a CI-tested restore drill (`backup.py`, `docs/BACKUP_RESTORE.md`); ingest backpressure (429) under load |
| **Secure SDLC / supply chain** | Automated dependency scanning, SBOM, signed releases / SLSA provenance (`security.yml`, `supply-chain.yml`, `release.yml`) |
| **Integrity of outbound integrations** | Webhook deliveries HMAC-signed with rotatable per-endpoint secrets + idempotency keys + retries |

The Customer is responsible for measures within its control: TLS termination,
network/firewall configuration, OS/disk encryption, infrastructure hardening,
and (self-hosted) backups and patching.

## Annex III — Sub-processors

For a **managed/SaaS** deployment, the mandatory Sub-processor is the hosting
provider; the integrations below are engaged **only if the Customer enables
them**. For a **self-hosted** deployment there are no mandatory Sub-processors —
the Customer chooses all of these.

| Sub-processor | Purpose | Engaged when |
|---|---|---|
| **[Hosting / cloud provider]** | Compute, storage, networking for the managed Service | Managed deployment (mandatory) |
| **[Managed Postgres provider]** | Database backend (optional Postgres mode) | If Postgres backend is used |
| AlienVault OTX | Threat-intelligence enrichment | If `OTX_API_KEY` is configured |
| VirusTotal | Indicator enrichment | If `VIRUSTOTAL_API_KEY` is configured |
| OpenCTI instance | CTI federation | If OpenCTI integration is enabled |
| Stripe | Subscription billing | If self-serve billing is enabled |
| Slack | Notification routing | If a Slack webhook is configured |
| Email/SMTP provider | Scheduled reports / critical notifications | If SMTP is configured |
| Customer's IdP (OIDC/SAML) | Authentication | If SSO is enabled |

> Note: most "integrations" send only the minimum necessary data (e.g. an
> indicator value to enrich), not bulk Personal Data. The Customer controls which
> are enabled.

## Annex IV — Standard Contractual Clauses (if applicable)

Where restricted international transfers occur, the EU SCCs (Commission
Implementing Decision (EU) 2021/914) Module **[Two: Controller→Processor]** apply
and are completed as follows: data exporter = **[Customer]**; data importer =
**[Vendor]**; the description of transfer = Annex I; technical/organisational
measures = Annex II; governing law and forum per the SCCs. For UK transfers, the
UK International Data Transfer Addendum applies.

---

*Signatures, effective date, and contact points (including the parties' data
protection contacts / DPO where applicable) to be completed on execution.*
