# ThreatOrbit Collector Ecosystem

Enterprise log shipping for ThreatOrbit - a lightweight first-party agent plus
**certified configs** for Fluent Bit, Vector, and the Elastic Beats stack. All
of them authenticate with a scoped API key and ship to the SIEM's ingest
endpoints, which parse the lines into events and run detections + threat-intel
matching on them.

## Ingest endpoints

| Endpoint | Body | Used by |
| --- | --- | --- |
| `POST /siem/ingest` | `{"lines": ["…"], "format": "auto", "source": "…"}` | the first-party agent |
| `POST /siem/ingest/raw?format=&source=` | raw text, NDJSON, or a JSON array | certified vendor configs |

Both require an **API key** and enforce the same validation, **backpressure**
(HTTP 429 + `Retry-After` when the detection backlog is full), and audit trail.

The `source` name you send is how the platform attributes flow: on first
ingest an unknown source **auto-registers** under SIEM → Sources (tagged
`auto-discovered`) and shows a live *Events (24h)* count from that point on -
no manual registration step. Give each collector a distinct, stable name.

## 1. First-party agent (`threatorbit_collector.py`)

A single stdlib-only file (Python 3.8+, no `pip`). It tails files, **checkpoints
read offsets** so a restart never re-ships or drops a line (at-least-once),
handles **log rotation/truncation**, batches, and honours backpressure.

```bash
# one-shot (cron-friendly)
THREATORBIT_URL=https://soc.example.com:8002 \
THREATORBIT_API_KEY=to_sk_live_xxxx \
python3 threatorbit_collector.py --once --paths /var/log/auth.log,/var/log/nginx/*.log

# daemon (or use the systemd unit)
python3 threatorbit_collector.py --paths /var/log/*.log

# preview without shipping
python3 threatorbit_collector.py --once --dry-run --paths /var/log/syslog
```

Run it under systemd with `threatorbit-collector.service` +
`collector.env.example`. See the file headers for the env vars.

## 2. Certified vendor configs (`configs/`)

Drop-in, no record shaping required - each posts to `/siem/ingest/raw`.

- **`fluent-bit.conf`** - `tail` input → `http` output (JSON). Built-in DB file
  checkpoints offsets.
- **`vector.toml`** - `file` source → `http` sink (JSON array). `data_dir`
  checkpoints offsets; retries on 429.
- **`filebeat-logstash.conf`** - Beats have no native HTTP output, so the
  certified path is **Filebeat → Logstash → HTTP**. Contains the Logstash
  pipeline (`json_batch`) and the matching `filebeat.yml`.

Set `THREATORBIT_API_KEY` in the agent's environment before starting.

## 3. Credentials & enrolment

Mint a key under **Settings → API** (or `POST /config/api-keys`). Scopes map to
roles:

| Scope | Prefix | Role | Use |
| --- | --- | --- | --- |
| `write` | `to_sk_live_` | analyst | **collectors** - ingest logs |
| `read`  | `to_rk_live_` | viewer | read-only automation |
| `admin` | `to_ak_live_` | admin  | administration |

Give each collector its **own** write-scoped key so it can be revoked
individually (Settings → API → Revoke) without touching the others - keys are
verified server-side on every request and a revoked key is rejected immediately.
Present the key as either `Authorization: Bearer <key>` or `X-API-Key: <key>`.

### Transport security / mTLS

TLS terminates at your ingress (nginx/Helm chart). For **mutual-TLS enrolment**,
issue a per-collector client certificate from your PKI and configure the ingress
to require it; each agent then presents its cert in addition to the API key
(defence in depth - transport identity *and* an application credential):

- **agent**: `THREATORBIT_CLIENT_CERT` / `THREATORBIT_CLIENT_KEY` (+ `THREATORBIT_CA`)
- **Fluent Bit**: `tls.crt_file` / `tls.key_file` / `tls.ca_file`
- **Vector**: `[sinks.threatorbit.tls]` `crt_file` / `key_file` / `ca_file`
- **Logstash**: `client_cert` / `client_key` / `cacert`

This pairs a revocable application credential (the API key) with a revocable
transport identity (the client cert) - "POST your logs here" with enrolment, not
an open door.
