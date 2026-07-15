# API versioning & deprecation policy

The Dashboard API (`:8002`) exposes a stable, versioned surface so integrators
can build against a contract that won't break under them.

## The `/v1` contract

Every API path is served **both** unversioned and under `/v1`:

```
GET /siem/alerts        ==  GET /v1/siem/alerts
POST /auth/login        ==  POST /v1/auth/login
```

`/v1/...` is an exact alias of the canonical handler - same request, same
response - implemented as a pure-ASGI path rewrite
([`dashboard_api/api_versioning.py`](../dashboard_api/api_versioning.py)), so
there is a single route table and no duplicated OpenAPI operations. Responses to
`/v1` requests carry an **`X-API-Version: v1`** header.

**Recommendation:** new integrations should pin to `/v1`. The unversioned paths
remain a permanent backward-compatible alias of the current version (the bundled
frontend uses them), so existing clients keep working unchanged.

## What "stable" means

Within a major version (`v1`) we guarantee, for every documented path in
[`docs/api/v1-paths.json`](api/v1-paths.json):

- the path will not be **removed** or renamed;
- existing request fields keep their meaning; responses are **additive only**
  (new fields may appear - clients must tolerate unknown fields);
- authentication and status-code semantics for a route don't change
  incompatibly.

A change that violates any of these is a **breaking change** and ships only
under a new version prefix (`/v2`), never silently inside `/v1`.

This is enforced in CI: `test_api_contract.py::test_no_documented_path_removed`
fails if a documented path disappears, so a removal can't merge without a
deliberate version decision.

## Deprecation process

When a route or field must be retired:

1. **Announce** in the CHANGELOG (`plan.md`) and mark it deprecated in the
   OpenAPI description.
2. **Signal at runtime** - the retiring handler calls
   `api_versioning.mark_deprecated(response, sunset=…)`, so its responses carry
   `Deprecation: true` and, where a removal date is set, a `Sunset: <HTTP-date>`
   header (RFC 8594).
3. **Grace period** - at least **6 months** (or two minor releases, whichever is
   longer) between announcement and removal.
4. **Remove** only in a new major version; the previous version keeps serving
   the old behaviour until its own sunset.

## OpenAPI

FastAPI serves the live schema and interactive docs:

- `GET /openapi.json` - machine-readable schema
- `GET /docs` - Swagger UI · `GET /redoc` - ReDoc

Per-release snapshots are produced by
[`scripts/openapi_snapshot.py`](../scripts/openapi_snapshot.py):

```bash
python scripts/openapi_snapshot.py          # refresh docs/api/v1-paths.json (the contract surface)
python scripts/openapi_snapshot.py --full   # + write docs/api/openapi.json (release artifact)
```

Run it whenever routes change so the committed contract surface tracks reality.
