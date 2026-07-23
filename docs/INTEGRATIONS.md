# Enrichment Integrations (IntelScope)

IntelScope enriches an indicator by fanning out to a set of **enrichment
providers** and showing each provider's real answer side-by-side. Providers
fall into three groups:

| Group | Providers | Key required |
|-------|-----------|--------------|
| Built-in | ThreatOrbit intel store, heuristic indicator analysis | No |
| Public   | RDAP (registry/WHOIS), DNS | No |
| External | **VirusTotal**, GreyNoise, Shodan | Yes (per provider) |

External providers are **off until you add an API key** and report
`available: false` honestly until then — IntelScope never invents a verdict for
a provider that isn't configured.

Configure keys in **Configuration → Integrations → Enrichment providers**
(stored encrypted in the settings store) or via environment variables
(`VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`). A key set in the
UI takes precedence over the environment variable.

---

## VirusTotal

### Can VirusTotal be connected to IntelScope?

**Yes.** VirusTotal is a first-class enrichment provider. Once a key is
configured, every IntelScope scan of a supported indicator automatically
includes a VirusTotal result.

### How the integration works

1. In IntelScope you scan a value (URL, domain, IP, or file hash) — typed, or
   pivoted to from an alert/IOC.
2. The frontend calls `POST /cti/scan/enrich`, which runs the enrichment
   pipeline over that value.
3. If a VirusTotal key is present, the pipeline queries the **VirusTotal API
   v3** (`https://www.virustotal.com/api/v3/…`, header `x-apikey`) for the
   indicator and reads its `last_analysis_stats`.
4. The result renders in the scan's **Details** tab as a *VirusTotal
   Detections* card: the multi-engine ratio (malicious / suspicious / harmless /
   undetected) with a detection-ratio bar. If VirusTotal has never seen the
   indicator it shows an honest "not seen by VirusTotal" rather than a verdict.

Results are cached with a TTL and recorded in the enrichment history, so a
re-scan doesn't re-hit the API unnecessarily (use the refresh action to force a
fresh lookup).

### Which API tier is supported?

**The public (free) API tier is fully supported.** The integration uses only
GET object lookups (`/ip_addresses/{ip}`, `/domains/{domain}`, `/files/{hash}`,
`/urls/{id}`) and reads `last_analysis_stats`, all of which the free v3 API
provides.

Practical notes on the free tier:
- Rate limits apply (VirusTotal's free tier is ~4 lookups/minute, ~500/day).
  The pipeline's caching keeps you well under this for normal analyst use.
- A **premium/enterprise** key works identically and simply raises those rate
  limits (and would unlock richer endpoints — behaviour, relationships,
  live-hunt — that this integration does not yet consume).

### What data can be retrieved

| Indicator type | VirusTotal object | Data surfaced |
|----------------|-------------------|---------------|
| IP address     | `/ip_addresses/{ip}`   | detection stats (reputation across engines) |
| Domain         | `/domains/{domain}`    | detection stats |
| File hash (MD5/SHA-1/SHA-256) | `/files/{hash}` | detection stats |
| URL            | `/urls/{base64(url)}`  | detection stats |

Surfaced today: the **detection ratio and per-verdict breakdown**
(malicious / suspicious / harmless / undetected) and the derived verdict.
Not covered: CVE and email indicator types (VirusTotal has no object for them —
IntelScope reports "VirusTotal does not cover type" honestly). Richer
VirusTotal data (WHOIS blob, passive DNS, sample behaviour, related files) is
available on the API but is not yet mapped into the UI — it's a documented
future enhancement, not a hidden feature.

### Configuration required beyond the API key

**None.** Supplying the key is the entire setup. The endpoint URL, request
format, auth header, and type routing are all handled internally — an
administrator only pastes the key (or sets `VIRUSTOTAL_API_KEY`) and saves.
Provider availability is shown live in the Integrations panel.

---

## Other external providers (for reference)

- **GreyNoise** (`GREYNOISE_API_KEY`) — for IP indicators: internet-scanner
  classification (benign / malicious / unknown), RIOT common-service flag,
  actor tag, last-seen. Rendered as a *GreyNoise · Internet Scanner* card.
- **Shodan** (`SHODAN_API_KEY`) — for IP indicators: open ports, hosting org,
  and known CVEs (each pivotable back into IntelScope). Rendered as a
  *Shodan · Exposure* card.
- **RDAP / WHOIS** (no key) — registrar, registration/expiry dates, domain age,
  nameservers, and IP allocation data, from the registries' own public data.

Every provider is honest about availability and never substitutes fabricated
data when a lookup can't run.
