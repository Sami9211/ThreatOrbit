"""Repeatable load benchmark for the ingest → detection pipeline.

So "load limits" are backed by **real, reproducible numbers measured on the host
you run this on**, not guesses. It spins up an isolated temp database, seeds the
detection rules, and times two stages:

  * ingest  — raw log lines parsed → events inserted → detection run inline
              (the end-to-end `/siem/ingest` path), and
  * drain   — a pre-seeded backlog processed by the detection worker pool,
              at 1 and N workers.

Run:  python -m dashboard_api.bench           # full
      python -m dashboard_api.bench --quick   # small, for a smoke check

Numbers are point-in-time for this hardware + SQLite WAL on a single node;
publish them with the environment line this prints, and re-run on your own
reference hardware. See docs/LOAD_LIMITS.md for a captured baseline.
"""
import os
import platform
import sys
import tempfile
import time
import uuid

# Isolate from any real database BEFORE importing the app config/db.
os.environ.setdefault("DASHBOARD_DB_PATH",
                      tempfile.NamedTemporaryFile(suffix="-bench.db", delete=False).name)
os.environ.setdefault("DASHBOARD_JWT_SECRET", "bench-secret")
os.environ.setdefault("DASHBOARD_ADMIN_PASSWORD", "BenchPassw0rd!")

from dashboard_api.db import get_conn, init_db  # noqa: E402


def _setup():
    init_db()
    from dashboard_api.engine import seed_builtin_rules
    seed_builtin_rules()
    # Load the curated pack so realistic rules are firing during the run.
    try:
        from dashboard_api.detection_pack import load_pack
        with get_conn() as conn:
            load_pack(conn, "bench@local", "org-default")
            conn.commit()
    except Exception:
        pass


# A realistic mix that exercises several rules (brute force, egress, process, C2).
def _synthetic_lines(n: int) -> list:
    import json
    lines = []
    for i in range(n):
        bucket = i % 5
        if bucket == 0:
            ev = {"event_type": "failed_login", "src_ip": f"10.0.{i % 8}.5",
                  "username": f"user{i % 50}", "raw": f"failed login attempt {i}"}
        elif bucket == 1:
            ev = {"event_type": "large_egress", "src_ip": f"10.1.{i % 64}.{i % 200 + 1}",
                  "bytes_out": 60_000_000, "raw": f"egress {i}"}
        elif bucket == 2:
            ev = {"event_type": "process_start", "hostname": f"host{i % 30}",
                  "process_name": "powershell.exe", "raw": f"proc {i}"}
        elif bucket == 3:
            ev = {"event_type": "beacon", "src_ip": f"10.2.{i % 32}.9",
                  "dest_ip": "203.0.113.50", "raw": f"beacon {i}"}
        else:
            ev = {"event_type": "log", "src_ip": f"10.3.{i % 16}.7", "raw": f"misc {i}"}
        lines.append(json.dumps(ev))
    return lines


def bench_ingest(n: int) -> dict:
    from dashboard_api.ingest import ingest_lines
    lines = _synthetic_lines(n)
    t0 = time.perf_counter()
    res = ingest_lines(lines, "json", "bench")
    dt = time.perf_counter() - t0
    return {"stage": "ingest+detect", "events": res["parsed"], "alerts": res["alerts"],
            "seconds": round(dt, 3), "eps": round(res["parsed"] / dt) if dt else 0}


def bench_drain(n: int, workers: int) -> dict:
    marker = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO events (id,ts,category,event_type,src_ip,bytes_out,raw,processed) "
                "VALUES (?,?,?,?,?,?,?,0)",
                (f"b-{marker}-{i}", "2026-06-01T00:00:00+00:00", "network", "large_egress",
                 f"10.{i % 250}.{i // 250 % 250}.{i % 250}", 60_000_000, f"bench-{marker}"))
        conn.commit()
    from dashboard_api.detection_pool import run_pool
    t0 = time.perf_counter()
    res = run_pool(workers=workers, batch=200)
    dt = time.perf_counter() - t0
    return {"stage": f"drain x{workers}", "events": res["events"], "alerts": res["alerts"],
            "seconds": round(dt, 3), "eps": round(res["events"] / dt) if dt else 0}


def run(quick: bool = False) -> dict:
    _setup()
    n_ing = 500 if quick else 5000
    n_drn = 1000 if quick else 10000
    ingest = bench_ingest(n_ing)
    # Clear whatever the ingest stage left pending so the timed drains below each
    # measure exactly their own seeded backlog.
    from dashboard_api.detection_pool import run_pool
    run_pool(workers=1, batch=500)
    rows = [ingest,
            bench_drain(n_drn, 1),
            bench_drain(n_drn, 4)]
    return {"env": _env(), "results": rows}


def _env() -> str:
    return (f"{platform.system()} {platform.machine()} · "
            f"{os.cpu_count()} vCPU · Python {platform.python_version()} · SQLite WAL (single node)")


def main():
    quick = "--quick" in sys.argv
    out = run(quick=quick)
    print(f"\nThreatOrbit load benchmark — {out['env']}\n")
    print(f"{'stage':<16}{'events':>9}{'alerts':>9}{'seconds':>10}{'events/sec':>12}")
    print("-" * 56)
    for r in out["results"]:
        print(f"{r['stage']:<16}{r['events']:>9}{r['alerts']:>9}{r['seconds']:>10}{r['eps']:>12}")
    print()


if __name__ == "__main__":
    main()
