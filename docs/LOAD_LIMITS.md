# Load limits - measured baseline

Real, reproducible throughput numbers for the ingest → detection pipeline, so
capacity planning is grounded in measurement rather than guesses. Reproduce with:

```bash
python -m dashboard_api.bench            # full
python -m dashboard_api.bench --quick    # small smoke run
```

The benchmark (`dashboard_api/bench.py`) spins up an **isolated temp database**,
seeds the detection rules + the curated pack, and times two stages with a
realistic event mix (failed logins, large egress, process starts, beacons):

- **ingest+detect** - raw JSON log lines parsed → events inserted → detection run
  inline (the end-to-end `/siem/ingest` path);
- **drain xN** - a pre-seeded backlog processed by the detection worker pool at
  N workers.

## Captured baseline

> Point-in-time, on the hardware below. **Re-run on your reference hardware** -
> numbers vary run-to-run by ~10-20%.

**Environment:** Linux x86_64 · 4 vCPU · Python 3.11 · SQLite WAL (single node)

| Stage | Events | Alerts | Seconds | Events/sec |
|---|---:|---:|---:|---:|
| ingest + detect (inline) | 5,000 | 244 | 0.46 | **~10,800** |
| detect drain - 1 worker | 10,000 | 10,000 | 1.36 | **~7,400** |
| detect drain - 4 workers | 10,000 | 10,000 | 1.87 | **~5,400** |

**Environment:** same host · Postgres 16 (local, loopback TCP) ·
`DASHBOARD_DB_BACKEND=postgres` - the previously "remaining" Tier-2 baseline
(`plan.md`), now measured rather than assumed. `ingest+detect` reflects the
batched-write fix below (§4); the `drain` stages are unchanged from the first
measurement (the detection worker's claim/complete path was already
batched - see §4):

| Stage | Events | Alerts | Seconds | Events/sec |
|---|---:|---:|---:|---:|
| ingest + detect (inline) | 5,000 | 242 | 1.32 | **~3,800** |
| detect drain - 1 worker | 10,000 | 10,000 | 24.82 | **~400** |
| detect drain - 4 workers | 10,000 | 10,000 | 26.04 | **~380** |

## What this means (read before scaling)

1. **A single SQLite node sustains roughly 8-11k EPS** of ingest+detect and
   ~7k EPS of pure detection on modest (4 vCPU) hardware - comfortably enough for
   a small/mid team. The bounded-ingest backpressure (HTTP 429 once the backlog
   passes `DASHBOARD_INGEST_MAX_BACKLOG`) protects the node above that.

2. **The detection worker pool does NOT increase throughput on SQLite - it is
   slightly slower** (4 workers < 1 worker above). This is expected and honest:
   SQLite has a **single writer**, so more workers add lock contention without
   write parallelism. The pool exists for **correctness** (a concurrency-safe,
   restart-resilient claim contract) and to **scale on Postgres** (real
   row-level locking + concurrent writers), *not* to speed up SQLite. Run the
   pool at 1 worker on SQLite - the app **logs a startup warning** if
   `DASHBOARD_DETECTION_WORKERS > 1` on the SQLite backend, so this misconfig is
   hard to hit silently.

3. **Postgres is still slower than SQLite for this pipeline, but ingest+detect
   is now ~5.7x faster than the first measurement** (~670 → ~3,800 EPS) after
   batching the ingest write path - correcting an earlier assumption in this
   doc that simply switching to Postgres would go "materially higher" *and*
   the follow-up measurement that first quantified the gap. Root cause of the
   original number, confirmed by reading the code: `ingest_lines` issued **one
   round-trip statement per row** (a Python loop of `conn.execute(...)`). Fixed
   by collecting the batch's rows and issuing one `conn.executemany(...)` call
   instead - verified empirically first (a standalone benchmark against this
   same local Postgres instance measured `executemany` at ~6x a row-by-row
   loop, matching a hand-built multi-row `VALUES` INSERT's throughput with far
   less code), then confirmed on the real pipeline via this bench. No
   correctness change: parse-time error isolation (one bad line can't drop the
   batch) happens before rows are collected, unaffected by how the INSERT is
   issued.
4. **The `drain` stages didn't move, and didn't need to**: `event_queue.claim`
   (one `UPDATE … WHERE id IN (…)`) and `.complete` (already `executemany`)
   were already batched - the "detection-claim path" named in the original
   roadmap item turned out not to be the bottleneck once actually read; only
   the ingest INSERT loop was. `detect drain` stays network-round-trip-bound
   on the *processing* side (rule evaluation + `_insert_alert` per match, and
   here every event matches), not the claim/complete plumbing.
5. **What's still not batched**: `_insert_alert` (one write per firing match)
   and the built-in engine's own inline path - lower priority, since matches
   are a small fraction of raw events in a typical mix (244 alerts for 5,000
   events above) unlike `drain`'s pathological all-match test data. For very
   high sustained EPS beyond what batching buys, externalise the event store
   to a columnar/search engine (ClickHouse/OpenSearch) behind the same hunt
   API - the remaining P0 pipeline item already tracked in `plan.md`.

## Caveats

- SQLite WAL, single node - no network/disk-latency component a managed DB adds.
- The event mix favours rules that match (so detection does real work); a quieter
  stream will measure higher EPS.
- These are pipeline numbers, not an end-to-end SLA - front the API with TLS, a
  reverse proxy, and the resource limits in `deploy/helm/`.

## CTI IOC import throughput (feed ingestion)

Separate from the SIEM event pipeline above: how fast the platform ingests
**threat-intel indicators** from a connector feed (AlienVault OTX, ThreatFox,
NVD, custom JSON/CSV/STIX). The reference point is OpenCTI's OTX connector, which
sustains roughly **1,000–10,000 indicators/second** including dedup/filtering.

The `ioc import` stage in `python -m dashboard_api.bench` times the real engine
(`connectors.import_indicators`): normalise → type-filter → intra-batch dedup →
chunked `value IN (...)` existence probe → single `executemany` bulk INSERT, in
bounded sub-batches. Same host as above (4 vCPU · SQLite WAL):

| Stage | Indicators | Seconds | Indicators/sec |
|---|---:|---:|---:|
| ioc import (all new, empty table) | 50,000 | 1.27 | **~39,000** |

Held under a growing table (loading 50k-at-a-time to 1,000,000 rows, every
indicator normalised + dedup-checked + inserted):

| IOC table size | Indicators/sec (all-new) | Indicators/sec (all-duplicate) |
|---|---:|---:|
| ~50k rows   | ~39,000 | — |
| ~500k rows  | ~30,000 | — |
| ~1,000,000 rows | ~23,000 | ~86,000 |

**What this means:**

1. **The engine already clears the OpenCTI/OTX reference band (1k–10k/s) by
   2–23×, on plain SQLite, with every indicator filtered** — and stays above it
   even at a million-row store (degradation is gentle B-tree index maintenance,
   not a cliff). This is the payoff of the batch redesign: the previous per-row
   `SELECT`+`INSERT` loop was O(N) database round trips (hundreds of
   indicators/second, and worse as the table grew). **No framework switch is
   required to hit the target** — measured, not assumed. The Postgres backend
   remains an opt-in (`DASHBOARD_DB_BACKEND=postgres`) for deployments that need
   concurrent writers, not for single-node import speed.

2. **Bounded memory + lock hold at any feed size.** `import_indicators` slices a
   pull into `DASHBOARD_IMPORT_BATCH` (default 10,000) sub-batches, so a
   hundred-thousand-indicator sync ingests with flat memory and short
   transactions instead of one giant in-memory list / multi-second write-lock
   hold. Dedup remains correct across sub-batches, and the per-run critical-alert
   cap is shared across them (a big pull can't flood the SIEM alert queue).

3. **Amount imported per OTX sync now scales like a real feed.** The OTX fetcher
   walks the paginated subscribed-pulses API (up to `DASHBOARD_OTX_MAX_PAGES` ×
   `DASHBOARD_OTX_PAGE_LIMIT` pulses, capped at `DASHBOARD_OTX_MAX_INDICATORS`),
   not a single 30-pulse page — so a sync pulls the whole subscribed feed
   (tens of thousands of indicators) rather than a handful. The engine numbers
   above are what absorbs that volume.

4. **The real-world ceiling is usually the source, not the engine.** OTX (and
   most public feeds) rate-limit the fetch; at 39k/s of local insert, a sync is
   network/API-bound long before it is database-bound.

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
| Overview rollups (recent/top/geo/feed) | 100-500 |
| SOAR run history / action trails | 500 |
| Notifications | 100 · global search | 25 |
| SIEM FP-triage (`/siem/alerts/fp-triage`) | 200 per page, 300-alert working set |

On the client side, the SIEM queue **windows** rows above 150 (a dependency-free
`useWindowedRows` hook) so even a full 500-row page renders only the visible
slice. For datasets larger than a single page, use the server-side
pagination (`offset`/`limit`) and filters the list endpoints expose rather than
raising the cap.

The FP-triage working set is capped lower than a plain list, because each row
costs several `fp_scoring` queries (not one) - it scores the most recent 300
open alerts, filters/sorts by likelihood band, then paginates the *scored*
result. On a deployment with more than 300 concurrently open alerts, older
ones fall outside this pass; this is an honest bound on a bulk-triage
convenience view, not the authoritative alert queue (`/siem/alerts` has no
such ceiling on what's queryable, only on page size).

## Polled rollups at high alert volume

`GET /siem/kpis` is polled every 30 s by the SIEM page (plus on every live
tick). It originally fetched **every alert row** into Python to count
severities/dispositions - a full-table transfer per poll that dominated at
scale. It now aggregates with a single `GROUP BY` (result ≤ |severities| ×
|statuses| × |dispositions| rows). Measured on Postgres 16 with **210k
alerts** (this container, median of 5):

| Query shape | Median |
| --- | --- |
| old: fetch-all rows into Python | 1650 ms |
| new: SQL `GROUP BY` aggregate | **27 ms** |

The latency AVGs in the same endpoint were already SQL-side. The per-day
trends endpoint (`/siem/analytics/trends`) cuts by `ts >= date` and rides
`idx_alerts_ts`, so its cost scales with the window's rows, not the table.
