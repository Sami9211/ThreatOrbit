# Postgres high availability (multi-AZ)

The default store is single-node WAL-SQLite. For a **multi-replica dashboard**
(rolling upgrades, no single point of failure) run the opt-in Postgres backend
behind a highly-available, multi-AZ Postgres and point every API replica at the
**HA endpoint** (not a single instance). This page is the deployment guidance;
`docs/BACKUP_RESTORE.md` covers backups/DR and `docs/OPERATIONS.md` the upgrade
contract.

## Turn on the Postgres backend

```
DASHBOARD_DB_BACKEND=postgres
DATABASE_URL=postgresql://user:pass@<ha-endpoint>:5432/threatorbit
```

Install `psycopg` in the API image. `DATABASE_URL` must resolve to the HA
**endpoint** that always points at the current primary (see below), so a failover
is transparent to the app. The backend is validated against live Postgres 16 in
CI (see the CHANGELOG); SQLite stays the default and is untouched.

## Why failover is clean here

- **Stateless API replicas.** All state is in Postgres; run N dashboard replicas
  behind a load balancer (the Helm chart in `deploy/helm/` does multi-replica +
  rolling updates when Postgres is configured). Any replica can serve any
  request.
- **Per-request connections.** The data layer opens a fresh connection per
  operation (`db.get_conn()`) and closes it — there is **no long-lived pool to
  go stale**. During a failover, in-flight requests may error once; the very next
  request opens a new connection through the HA endpoint and lands on the new
  primary. Recovery is automatic, no app restart.
- **The leader lease lives in the DB.** Background singletons (engine tick,
  connector/report scheduler, file-watcher) are gated by a DB-backed lease
  (`leader.py`, `leader_lease` table). It survives failover with the data: after
  the standby is promoted, the lease either is still held (renewed by the same
  node) or expires and a follower takes it within one TTL
  (`DASHBOARD_LEASE_TTL`, default 60s). Two replicas never double-run the
  singletons across a failover.

## Choose an HA topology

**Managed (recommended).** Use a cloud provider's synchronous multi-AZ Postgres
— it gives you a single stable endpoint, a synchronous standby in another AZ,
and automatic failover with no app changes:

| Provider | Offering | Notes |
| --- | --- | --- |
| AWS | **RDS / Aurora PostgreSQL Multi-AZ** | RDS Multi-AZ (or Multi-AZ DB cluster) — point `DATABASE_URL` at the cluster/instance endpoint |
| GCP | **Cloud SQL for PostgreSQL (HA)** | regional (multi-zone) instance; use the instance IP / Auth Proxy |
| Azure | **Azure Database for PostgreSQL – Flexible Server, zone-redundant HA** | zone-redundant high availability |

Pick **synchronous** replication so a committed transaction is never lost on
failover (RPO ≈ 0).

**Self-managed.** If you run your own Postgres, put a cluster manager in front
that does leader election + automatic failover and exposes one endpoint:

- **Patroni** (+ etcd/Consul) with **HAProxy** or **PgBouncer** routing to the
  current primary, or
- **repmgr** with a virtual IP.

Keep the standby in a different AZ/rack and replicate synchronously for RPO ≈ 0.

## Connection pooling (PgBouncer)

The app uses plain per-request connections, so a pooler is optional. If you add
**PgBouncer**, prefer **session** or **transaction** pooling and point
`DATABASE_URL` at PgBouncer's address; PgBouncer following the primary makes
failover transparent. (The app issues no session-level features that break
transaction pooling.)

## RPO / RTO with multi-AZ

- **RPO ≈ 0** with a synchronous standby (no acknowledged-commit loss on
  failover). Asynchronous replication trades RPO for latency — know which you've
  configured.
- **RTO** = the managed service's failover time (typically ~60–120s) + the few
  seconds for API replicas to reconnect. No app restart is needed.
- Multi-AZ protects against an instance/AZ failure; it is **not** a substitute
  for backups. Keep the off-box snapshots (`docs/BACKUP_RESTORE.md`) for
  region loss, accidental deletes, and point-in-time recovery (enable PITR on the
  managed instance).

## Upgrades against an HA Postgres

Schema migrations are additive and gated (`docs/OPERATIONS.md`): on boot the code
**refuses to run against a DB newer than it understands**. For a rolling upgrade,
let the first new replica apply migrations (additive columns are tolerated by the
older replicas still running), then roll the rest. Check before/after with
`python -m dashboard_api.ops schema-version`.

## Checklist

1. Provision multi-AZ Postgres with a **synchronous** standby + a stable endpoint.
2. Enable automated backups / PITR on the instance (DR beyond the AZ pair).
3. `DASHBOARD_DB_BACKEND=postgres`, `DATABASE_URL=<ha-endpoint>`, `psycopg`
   installed, on **all** API replicas.
4. Run ≥2 dashboard replicas behind a load balancer (Helm chart).
5. Leave leader election on (default) so the background singletons stay single-run
   across failover.
6. Test a failover in staging and confirm: requests recover automatically, a
   leader is re-elected within one TTL, and `GET /ready` goes healthy again.
