# Prometheus monitoring for ThreatOrbit

The dashboard API exposes Prometheus metrics at `GET /metrics` (text exposition
format - see [`docs/OPERATIONS.md`](../../docs/OPERATIONS.md) → *Observability*).
This directory ships ready-to-use **alert rules for the platform's own health**,
so a team already running Prometheus/Alertmanager gets paged on the same
conditions the in-app **Settings → System Health** card shows.

## Metrics exposed

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `threatorbit_uptime_seconds` | gauge | - | seconds since the API process started |
| `threatorbit_requests_total` | counter | `method`, `path`, `status` | HTTP requests by route template |
| `threatorbit_request_seconds_sum` | counter | `method`, `path`, `status` | cumulative request latency |
| `threatorbit_domain_total` | counter | `counter` | domain events - `errors`, `engine_ticks`, `engine_tick_failures`, `engine_events`, `engine_alerts`, `ingested_events`, `ingest_alerts` |
| `threatorbit_table_rows` | gauge | `table` | core-table row counts (storage growth) |
| `threatorbit_event_queue_depth` | gauge | - | pending (unprocessed) events - detection backlog |
| `threatorbit_event_queue_lag_seconds` | gauge | - | age of the oldest pending event - detection lag |

## Scrape config

`/metrics` is open on private networks by default; set `DASHBOARD_METRICS_TOKEN`
to require a bearer token. Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: threatorbit          # the alert rules select job="threatorbit"
    metrics_path: /metrics
    static_configs:
      - targets: ["dashboard-api:8002"]
    # Only if DASHBOARD_METRICS_TOKEN is set:
    # authorization:
    #   type: Bearer
    #   credentials_file: /etc/prometheus/threatorbit-metrics-token

rule_files:
  - /etc/prometheus/threatorbit/alerts.yml
```

## Alert rules

[`alerts.yml`](alerts.yml) groups the rules by concern:

- **platform-health** - target down, `/ready` returning 503 (DB unreachable),
  unhandled-error rate, engine-tick failures.
- **detection-backpressure** - queue depth and lag past the self-health
  thresholds (`DASHBOARD_HEALTH_QUEUE_DEPTH` / `DASHBOARD_HEALTH_LAG_SECONDS`).
- **latency** - mean API request latency.

Thresholds match the in-app self-health defaults on purpose - tune both together.

### prometheus-operator (PrometheusRule CRD)

If you run the prometheus-operator, wrap the groups from `alerts.yml` in a CRD:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: threatorbit
  labels: { release: prometheus }   # match your operator's ruleSelector
spec:
  groups:                            # paste the `groups:` list from alerts.yml here
    - name: threatorbit-platform-health
      rules: [ ... ]
```

A `ServiceMonitor` selecting the dashboard-api Service (port `http`, path
`/metrics`) wires the scrape the operator way.
