# Data residency

ThreatOrbit is **self-hosted**: you run the services and own the data store
(WAL-SQLite or your Postgres), so your operational data lives wherever you
deploy - there is no vendor-side copy. Residency is therefore primarily a
function of *where you deploy* plus *which optional external integrations you
turn on*. This page enumerates every point at which data could leave your
deployment's region/network, and how to pin or disable each, so you can run a
strict in-region (or fully air-gapped) installation.

By default the platform makes **no outbound calls** beyond what you explicitly
enable: every integration below is opt-in. Outbound URLs entered for connectors
and webhooks are also SSRF-guarded (`dashboard_api/net_guard.py`).

## Egress points

| What | When it leaves | What leaves | Keep it in-region / off |
| --- | --- | --- | --- |
| **Primary store** (SQLite/Postgres) | never (self-hosted) | - | deploy in your region; that is your residency boundary |
| **Threat-intel connectors / OSINT** (abuse.ch, NVD, OTX, RSS, custom) | on sync | *outbound only* - fetches indicators; your data is not sent (custom connectors send only the API key you set) | leave connectors disabled, or point custom ones at in-region mirrors |
| **IOC enrichment** (VirusTotal, GreyNoise, Shodan, WHOIS) | per lookup, only if a key is set | the indicator value being enriched (IP/domain/hash) | leave the keys unset (built-in offline enrichers still run) |
| **AI assistant** | per query, only if `ANTHROPIC_API_KEY` set | the prompt + read-only tool output | leave the key unset (deterministic router runs offline), or point at an in-region / self-hosted OpenAI-compatible endpoint (see README §16) |
| **Billing** (Stripe) | on checkout/portal, only if configured | billing metadata (no security data) | leave `STRIPE_*` unset (license keys still work) |
| **Audit sink** (`DASHBOARD_AUDIT_SINK_URL`) | per audit event, if set | audit-trail events | set it to an **in-region** endpoint (your SIEM / object-lock store), or leave unset |
| **Retention cold-storage** (`DASHBOARD_ARCHIVE_S3_*`) | on purge, if set | purged rows (NDJSON) | use an in-region bucket or self-hosted MinIO via `_ENDPOINT`; or use a local `DASHBOARD_ARCHIVE_DIR` |
| **Outbound webhooks / Slack** | per notification, per configured hook | notification payloads | point hooks at in-region/internal URLs (or none) |
| **SMTP email** | on report/notification delivery, if configured | report contents / notifications | use an in-region mail relay (or leave unset) |
| **SSO IdP** (OIDC/SAML) | per sign-in, if configured | auth assertions (identity only) | use your own in-region IdP |
| **TAXII push / OpenCTI** (threat_api) | on push, if configured | STIX bundles you choose to publish | point at your in-region OpenCTI (or don't push) |
| **Companion services** (threat_api, log_api) | internal to your deployment | - | run them in the same network/region |

## Strict in-region / air-gapped checklist

1. Deploy all services + the database in your chosen region (your residency
   boundary). Put TLS in front (`docs/DEPLOYMENT.md`).
2. Leave external **enrichment** and **assistant** keys unset - both degrade to
   offline behaviour - or point the assistant at a self-hosted model.
3. Leave **Stripe** unset (use signed license keys directly).
4. If you use the **audit sink** or **cold-storage archive**, point them at
   in-region endpoints (an in-region object store, or self-hosted MinIO/Ceph via
   the S3 `_ENDPOINT`).
5. Point **webhooks**, **SMTP**, **SSO IdP**, and **OpenCTI/TAXII** at
   in-region/internal systems, or leave them off.
6. For intel without internet egress, mirror OSINT feeds in-region and register
   them as **custom connectors** by URL, or run fully offline (the engine and all
   detection/correlation work without any connector).

With the above, the only data that ever leaves your region is what you have
explicitly routed to an in-region destination you control. Multi-tenant
deployments add per-workspace isolation on top (`DASHBOARD_MULTI_TENANT`); a
single deployment serves one residency region - run separate deployments for
separate regions.
