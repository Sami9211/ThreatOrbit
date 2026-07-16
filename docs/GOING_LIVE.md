# Going live - running ThreatOrbit on real data

This is the runbook for turning ThreatOrbit from an evaluation install into a
deployment where **every number on screen comes from your environment**: your
logs, real OSINT, zero synthesized telemetry. It covers three deployment
shapes - a **Windows host** (including an Active Directory network), **AWS**,
and any **Docker/Kubernetes** host - because the steps are 90% identical and
the differences are called out where they occur.

> **The two switches that matter** (everything else is additive):
>
> ```
> DASHBOARD_DATA_MODE=live    # start empty - no demo data, ever
> DASHBOARD_ENGINE=off        # REAL DATA ONLY - no synthetic telemetry, ever
> ```
>
> `live` alone keeps a background engine generating *representative* telemetry
> so the console feels alive before log forwarding exists (nice for a pilot,
> wrong for production). `DASHBOARD_ENGINE=off` disables that engine
> completely: no first-boot priming, and it boots paused on every start. From
> then on the only data you will ever see is what you feed it.

Data enters ThreatOrbit through exactly three doors, and this runbook wires
each one:

| Door | What flows through it | Where it lands |
| --- | --- | --- |
| **1. Your logs** | collector agent, syslog UDP/TLS, file watcher, HTTP ingest, S3 pull, uploads | SIEM events → detection rules → alerts → correlation → SOAR |
| **2. External intel** | abuse.ch, AlienVault OTX, NVD CVEs, RSS, TAXII, VirusTotal enrichment | CTI indicators, actor attribution, vuln findings |
| **3. Analyst work** | cases, playbooks, imports, scans | SOAR/CTI/assets |

---

## Step 0 - Secrets and hardening (do this first)

Set these before the first production boot. With `DASHBOARD_REQUIRE_SECRETS=true`
the service **refuses to start** on any insecure default - turn it on so a
missed secret is a loud failure, not a silent hole.

```bash
DASHBOARD_REQUIRE_SECRETS=true
DASHBOARD_JWT_SECRET=<64 random hex chars>        # python3 -c "import secrets;print(secrets.token_hex(32))"
DASHBOARD_ADMIN_EMAIL=soc-admin@your-domain.com
DASHBOARD_ADMIN_PASSWORD=<strong bootstrap password>
DASHBOARD_ENCRYPTION_KEY=<Fernet key>              # python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
DASHBOARD_CORS_ORIGINS=https://soc.your-domain.com # the exact origin(s) serving the frontend
DASHBOARD_ALLOW_REGISTRATION=false                 # closed deployment: admins create accounts
APP_API_KEY=<random>                               # threat_api + log_api user key
ADMIN_API_KEY=<different random>                   # their admin key (distinct in prod)
SERVICES_API_KEY=$APP_API_KEY                      # dashboard → services bridge
SERVICES_ADMIN_KEY=$ADMIN_API_KEY
```

Then:

1. **TLS in front of everything.** Never expose :8000-8002/:3000 directly -
   put nginx or Caddy in front (ready-made configs, security headers and the
   full topology are in [`DEPLOYMENT.md`](DEPLOYMENT.md)).
2. **First login:** change the bootstrap password, then enrol **TOTP MFA**
   (Config → Security → Two-factor) for every admin.
3. Optional but recommended: `DASHBOARD_LOG_REDACT=email,secret` so credential
   material and email local-parts in raw logs are masked before persistence
   ([`PII_HANDLING.md`](PII_HANDLING.md)).

## Step 1 - Real-data mode

```bash
DASHBOARD_DATA_MODE=live
DASHBOARD_ENGINE=off
```

- **docker compose (recommended):** use the production overlay, which pins
  these plus the hardening gate in one command - no per-var wiring:
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d`.
  (Or set both in `.env` and use the base file for an evaluation run.)
- **Helm:** `--set config.dataMode=live --set config.engine=off`.
- **Windows launcher:** nothing to set - double-clicking `windows-start.bat`
  already boots `live` with the engine **off** (real data only, same default
  as `linux-start.sh`). `windows-start.bat synthetic` turns the evaluation
  telemetry engine back on.

Boot and verify: `Config → General → Live Processing Engine` shows **paused**,
and the log prints `Real-data mode (DASHBOARD_ENGINE=off)`. Every store starts
at zero. That's correct - you're about to fill them.

## Step 2 - External threat intelligence (works within minutes)

Free keys, in ascending order of value:

| Source | Key needed | What you get |
| --- | --- | --- |
| abuse.ch Feodo | none | thousands of live C2/botnet IPs |
| abuse.ch URLHaus | free Auth-Key (abuse.ch account) | live malware-distribution URLs |
| AlienVault OTX | free API key (otx.alienvault.com) | community pulses, IOCs |
| NVD | none | CVE catalogue for the vuln rollup |
| VirusTotal | free API key | enrichment verdicts on indicators |

```bash
OTX_API_KEY=…            # threat_api
ABUSECH_AUTH_KEY=…       # threat_api (URLHaus)
VIRUSTOTAL_API_KEY=…     # threat_api enrichment
ENABLE_SCHEDULER=true    # threat_api: periodic ingestion without clicking
```

Then in the dashboard: **Feeds → Sources → Sync now** on the ThreatOrbit OSINT
and NVD connectors. CTI fills with real indicators; every one traces to its
source. TAXII 2.1 push/pull and OpenCTI integration are documented in
[`opencti_integration.md`](opencti_integration.md).

## Step 3 - Forward your logs (the part that makes it *your* SOC)

Pick per source system; all paths meet the same pipeline (parse → normalise →
detect → correlate → escalate) and all are org-stamped and backpressure-aware.

Mint a **write-scoped API key** first: Config → API Keys → create, scope
*Read + Write*. Machine clients authenticate with `X-API-Key: to_sk_live_…`
(or the same value as a `Bearer` token).

### 3a. Linux / any file-based logs - the collector agent

A stdlib-only Python agent (no pip installs) that tails files, checkpoints
offsets (at-least-once across restarts), handles rotation, honours 429
backpressure, and ships over TLS/mTLS:

```bash
# on each source host
sudo install -m744 collector/threatorbit_collector.py /usr/local/bin/threatorbit-collector
sudo install -m640 collector/collector.env /etc/threatorbit/collector.env   # from collector.env.example
sudo cp collector/threatorbit-collector.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now threatorbit-collector
```

`collector.env`: `THREATORBIT_URL=https://soc.your-domain.com`,
`THREATORBIT_API_KEY=to_sk_live_…`,
`THREATORBIT_PATHS=/var/log/auth.log,/var/log/nginx/*.log`.

### 3b. Syslog senders (network gear, firewalls, appliances)

Open the built-in listeners on the dashboard API host:

```bash
DASHBOARD_SYSLOG_PORT=5514           # UDP (LAN only)
DASHBOARD_SYSLOG_TLS_PORT=6514       # TCP+TLS (use this across networks)
DASHBOARD_SYSLOG_TLS_CERT=/etc/threatorbit/syslog.crt
DASHBOARD_SYSLOG_TLS_KEY=/etc/threatorbit/syslog.key
DASHBOARD_SYSLOG_TLS_CA=/etc/threatorbit/ca.pem     # set to require client certs (mTLS)
```

CEF and LEEF envelopes are parsed natively, so firewall/SIEM-forwarder output
works as-is. A drop directory watcher also exists:
`DASHBOARD_LOG_WATCH_DIR=/var/threatorbit/drop`.

### 3c. Windows / **Active Directory** - Security events and Sysmon

ThreatOrbit natively normalises **Windows Security** events (4624/4625 logons,
4688 process creation, 4728/4732 group changes, 1102 log cleared, 7045 service
install) and **Sysmon** (1, 3, 11, 12/13, 22) onto its detection vocabulary
with MITRE mapping - see [`SUPPORTED_SOURCES.md`](SUPPORTED_SOURCES.md). Ship
them as JSON with **NXLog CE** (or winlogbeat) from each DC / member server:

```
# C:\Program Files\nxlog\conf\nxlog.conf  (minimal, JSON over TLS)
<Extension json>
    Module  xm_json
</Extension>
<Input eventlog>
    Module  im_msvistalog
    Query   <QueryList><Query Id="0">\
              <Select Path="Security">*</Select>\
              <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>\
            </QueryList>
</Input>
<Output threatorbit>
    Module  om_http
    URL     https://soc.your-domain.com/siem/ingest/raw?format=auto&source=%HOSTNAME%
    AddHeader X-API-Key: to_sk_live_...
    ContentType application/x-ndjson
    Exec    to_json();
</Output>
<Route r>
    Path    eventlog => threatorbit
</Route>
```

(`POST /siem/ingest/raw` accepts newline-delimited JSON - no envelope needed -
and is exactly the endpoint certified for Fluent Bit / Vector / Filebeat too.)

**Make the DCs emit the right events first** (Group Policy → Advanced Audit
Policy): *Logon/Logoff: Logon* (4624/4625), *Detailed Tracking: Process
Creation* (4688, plus "Include command line in process creation events"),
*Account Management* (4728/4732). Installing **Sysmon** with a community
config (e.g. SwiftOnSecurity) raises fidelity substantially - process, network
and DNS telemetry per host.

The built-in rules that light up immediately on AD telemetry: brute-force
(T1110), password spraying (T1110.003), Kerberoasting (T1558.003), privilege
escalation via group change (T1078/T1098), impossible travel, malicious
process execution.

### 3d. AWS - CloudTrail and anything in S3

CloudTrail (and native AWS log shapes) are normalised too (`CreateAccessKey`,
console logons, …). Point the built-in S3 puller at the bucket; it uses the
standard AWS credential envs (an instance role via env, or an IAM user):

```bash
DASHBOARD_S3_PULL_BUCKET=my-cloudtrail-bucket
DASHBOARD_S3_PULL_PREFIX=AWSLogs/…/CloudTrail/     # optional narrowing
DASHBOARD_S3_PULL_REGION=eu-west-1
DASHBOARD_S3_PULL_SECONDS=60
AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…        # or session credentials
```

New objects are ingested once, checkpointed, and flow through the same
detection pipeline (T1098.001 cloud-key creation etc.).

### 3e. Ad-hoc - file upload

**SIEM → Sources → upload a log** runs the Log API's four detector engines
(pattern / statistical / ML ranking / temporal) on Apache, syslog, Windows,
or generic files - useful for incident triage of a file someone hands you.

## Step 4 - Verify the deployment is honestly live

Work down this list; each line has a place to look:

1. `GET /health` on :8000/:8001/:8002 → `ok` (or container healthchecks green).
2. **Feeds → Sources**: last-sync timestamps moving; CTI indicator count > 0.
3. **SIEM → Sources**: your collector/syslog/S3 sources listed with event
   counts. Sources are **auto-discovered on first ingest** - the name your
   collector passes in `?source=` (the built-in listeners use `syslog-udp`,
   `syslog-tls`, and `file-watch`) appears as a source row tagged
   `auto-discovered`, no manual registration needed. The per-source
   *Events (24h)* figure is computed live from events carrying that source
   name; a wired-up source that goes quiet shows a truthful 0. You can still
   pre-register a source (SIEM → Sources → Add) under the collector's name to
   set its type/host metadata ahead of time.
4. **Config → General → Live Processing Engine**: *paused*, alertsProduced 0 -
   any alert you see is a real detection on your data.
5. **Overview**: KPIs non-zero only where you actually fed data; empty panels
   say "no data yet" (they never fabricate).
6. Raise a test detection: `ssh wrong-password` a machine 10× or run the
   sample: `curl -X POST https://…/siem/ingest/raw?format=auto -H "X-API-Key: …" --data-binary @sample_logs/sample_apache.log`.
7. **Config → Security → Audit Trail**: your logins and syncs are recorded.

## Step 5 - Day-2 operations

* **Backups on a schedule** - compose: `docker compose --profile backup up -d`;
  Helm: `--set backup.enabled=true`. Retention/offbox guidance in
  [`OPERATIONS.md`](OPERATIONS.md).
* **Retention & archives** - size windows per obligation; per-tenant overrides
  exist. Optional S3/object-lock archival before purge.
* **Tamper-evident audit mirror** - `AUDIT_SINK_URL` (+ `AUDIT_SINK_SECRET`)
  streams every audit event off-box with replay across outages.
* **Monitoring** - Prometheus at `/metrics` on every service; alert on
  `engine_tick_failures`, ingest shedding, and healthchecks.
* **Scale** - measured limits in [`LOAD_LIMITS.md`](LOAD_LIMITS.md) (~10k EPS
  ingest on 4 vCPU, SQLite). Sustained higher load or >1 API replica → the
  Postgres backend ([`POSTGRES_HA.md`](POSTGRES_HA.md)).

## Deployment-shape quick reference

### Windows host (pilot / small team, incl. the AD case above)
1. Install Python 3.11+ (tick *Add to PATH*) and Node.js LTS.
2. Set the Step-0/1 variables as **system environment variables**
   (`DASHBOARD_DATA_MODE=live`, `DASHBOARD_ENGINE=off`, secrets…).
3. Double-click **`windows-start.bat`** - it installs, builds the production
   frontend, starts all four services, and opens the browser.
   (`windows-test.bat` runs every suite and prints `ALL TESTS PASSED`.)
4. Wire the DC/member servers per **3c**. For anything internet-facing, put
   IIS/nginx TLS in front or move to the Docker shape.

### AWS (EC2 + docker compose - the simplest production shape)
1. EC2 `t3.large`+ (4 vCPU/8 GB to track LOAD_LIMITS), Docker + compose plugin.
2. Security group: 443 in, nothing else public; the containers publish only to
   localhost behind nginx/ALB TLS.
3. `cp .env.example .env` → fill the Step-0 secrets → bring it up with the
   **production overlay** (real feeds only, one command):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
   # add scheduled backups:  … -f docker-compose.prod.yml --profile backup up -d
   ```
   The overlay pins `DASHBOARD_DATA_MODE=live`, `DASHBOARD_ENGINE=off`,
   `DASHBOARD_REQUIRE_SECRETS=true` and closed registration, and makes a missing
   secret abort the command instead of booting insecure - so you can't
   accidentally ship demo mode. (Plain `docker compose up` without the overlay
   stays in demo mode for evaluation.)
4. CloudTrail via **3d**; EC2/EKS workload logs via the collector (**3a**);
   VPC appliances via syslog-TLS (**3b**).

### Kubernetes (Helm)
```bash
helm install threatorbit deploy/helm/threatorbit \
  --set config.dataMode=live --set config.engine=off \
  --set secrets.jwtSecret=… --set secrets.adminPassword=… \
  --set secrets.appApiKey=… --set backup.enabled=true \
  --set ingress.enabled=true --set ingress.host=soc.your-domain.com
```
Multi-replica needs the Postgres backend (`postgres.enabled`); see
[`POSTGRES_HA.md`](POSTGRES_HA.md).

---

**Honest scope, restated:** single-node SQLite by default with measured
limits; the ML layer ranks outliers for triage rather than asserting attacks;
no third-party pentest yet ([`../SECURITY.md`](../SECURITY.md), README §15).
Everything above is real, inspectable code paths - nothing in this runbook
depends on generated data.
