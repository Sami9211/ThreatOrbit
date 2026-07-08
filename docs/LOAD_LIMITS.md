# Load limits — measured baseline

Real, reproducible throughput numbers for the ingest → detection pipeline, so
capacity planning is grounded in measurement rather than guesses. Reproduce with:

```bash
python -m dashboard_api.bench            # full
python -m dashboard_api.bench --quick    # small smoke run
```

The benchmark (`dashboard_api/bench.py`) spins up an **isolated temp database**,
seeds the detection rules + the curated pack, and times two stages with a
realistic event mix (failed logins, large egress, process starts, beacons):

- **ingest+detect** — raw JSON log lines parsed → events inserted → detection run
  inline (the end-to-end `/siem/ingest` path);
- **drain xN** — a pre-seeded backlog processed by the detection worker pool at
  N workers.

## Captured baseline

> Point-in-time, on the hardware below. **Re-run on your reference hardware** —
> numbers vary run-to-run by ~10–20%.

**Environment:** Linux x86_64 · 4 vCPU · Python 3.11 · SQLite WAL (single node)

| Stage | Events | Alerts | Seconds | Events/sec |
|---|---:|---:|---:|---:|
| ingest + detect (inline) | 5,000 | 244 | 0.46 | **~10,800** |
| detect drain — 1 worker | 10,000 | 10,000 | 1.36 | **~7,400** |
| detect drain — 4 workers | 10,000 | 10,000 | 1.87 | **~5,400** |

**Environment:** same host · Postgres 16 (local, loopback TCP) ·
`DASHBOARD_DB_BACKEND=postgres` — the previously "remaining" Tier-2 baseline
(`plan.md`), now measured rather than assumed:

| Stage | Events | Alerts | Seconds | Events/sec |
|---|---:|---:|---:|---:|
| ingest + detect (inline) | 5,000 | 242 | 7.42 | **~670** |
| detect drain — 1 worker | 10,000 | 10,000 | 22.41 | **~450** |
| detect drain — 4 workers | 10,000 | 10,000 | 23.25 | **~430** |

## What this means (read before scaling)

1. **A single SQLite node sustains roughly 8–11k EPS** of ingest+detect and
   ~7k EPS of pure detection on modest (4 vCPU) hardware — comfortably enough for
   a small/mid team. The bounded-ingest backpressure (HTTP 429 once the backlog
   passes `DASHBOARD_INGEST_MAX_BACKLOG`) protects the node above that.

2. **The detection worker pool does NOT increase throughput on SQLite — it is
   slightly slower** (4 workers < 1 worker above). This is expected and honest:
   SQLite has a **single writer**, so more workers add lock contention without
   write parallelism. The pool exists for **correctness** (a concurrency-safe,
   restart-resilient claim contract) and to **scale on Postgres** (real
   row-level locking + concurrent writers), *not* to speed up SQLite. Run the
   pool at 1 worker on SQLite — the app **logs a startup warning** if
   `DASHBOARD_DETECTION_WORKERS > 1` on the SQLite backend, so this misconfig is
   hard to hit silently.

3. **Measured today, Postgres is markedly slower than SQLite for this same
   pipeline, and 4 workers don't beat 1 — correcting an earlier assumption in
   this doc that simply switching to Postgres would go "materially higher."**
   The reason isn't Postgres itself: `ingest_lines` and the detection worker
   both issue **one round-trip statement per row** (a Python loop of
   `conn.execute(...)`, no `executemany`/batch/`COPY`). Over SQLite that's an
   in-process file write with no network hop; over Postgres — even loopback —
   every row pays a real client↔server round trip, which dominates at this row
   count and swamps whatever row-level-locking parallelism 4 workers could
   otherwise exploit. This is an honest, reproducible measurement
   (`DASHBOARD_DB_BACKEND=postgres DATABASE_URL=... python -m dashboard_api.bench`
   against a disposable database), not a Postgres capacity ceiling — a real
   deployment adds further network latency on top of this, so treat these
   numbers as a floor, not a target.
4. **To go materially higher on Postgres**: batch the per-row ingest/detection
   writes (`executemany` or a multi-row `INSERT` / `COPY`) instead of one
   statement per event — untouched by this measurement pass, tracked as a new,
   concretely-scoped item in `plan.md`'s open roadmap. For very high sustained
   EPS beyond that, externalise the event store to a columnar/search engine
   (ClickHouse/OpenSearch) behind the same hunt API — the remaining P0 pipeline
   item already tracked there.

## Caveats

- SQLite WAL, single node — no network/disk-latency component a managed DB adds.
- The event mix favours rules that match (so detection does real work); a quieter
  stream will measure higher EPS.
- These are pipeline numbers, not an end-to-end SLA — front the API with TLS, a
  reverse proxy, and the resource limits in `deploy/helm/`.

## API dataset ceilings (UI safety)

Every list endpoint caps its `limit` query parameter server-side, so a client
(or a buggy UI) can't request an unbounded result set and exhaust memory. An
over-cap value is rejected with HTTP 422; the cap is the hard ceiling:

| Endpoint family | Per-request cap |
| --- | --- |
| SIEM alerts, assets, dark-web, hunts | 500 |
| CTI IOCs / TAXII objects / fleet vulns | 1000 |
| MISP export | 5000 · STIX bundle | 10000 |
| Audit-log read | 2000 · audit CSV export | 50000 |
| Overview rollups (recent/top/geo/feed) | 100–500 |
| SOAR run history / action trails | 500 |
| Notifications | 100 · global search | 25 |

On the client side, the SIEM queue **windows** rows above 150 (a dependency-free
`useWindowedRows` hook) so even a full 500-row page renders only the visible
slice. For datasets larger than a single page, use the server-side
pagination (`offset`/`limit`) and filters the list endpoints expose rather than
raising the cap.
