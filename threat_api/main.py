import json
import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import wraps
from typing import Dict

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from threat_api.config import (
    API_HOST, API_PORT, APP_API_KEY, BUNDLE_PATH, CORS_ORIGINS, FLASK_DEBUG,
    ENABLE_ABUSECH, ENABLE_DARKWEB_OSINT, ENABLE_OTX, ENABLE_RSS, ENABLE_SCHEDULER,
    ENABLE_SOCIAL_OSINT, OPENCTI_API_KEY, OPENCTI_ENABLED, OPENCTI_URL,
    PIPELINE_MAX_ENRICH, PIPELINE_MAX_IOCS_PER_SOURCE, PIPELINE_MAX_TOTAL_IOCS,
    RATE_LIMIT_PER_MINUTE, SCHEDULE_FETCH_CRON_MINUTES,
)
from threat_api.db import init_db, load_iocs_from_db, upsert_iocs
from threat_api.enrichment.virustotal import enrich_iocs
from threat_api.fetchers.abusech import fetch_abusech_iocs
from threat_api.fetchers.darkweb_osint import fetch_darkweb_osint_iocs, get_configured_darkweb_sources
from threat_api.fetchers.otx import fetch_otx_iocs
from threat_api.fetchers.rss import fetch_rss_iocs, get_configured_rss_feeds
from threat_api.fetchers.social_osint import fetch_social_osint_iocs, get_configured_social_sources
from threat_api.metrics import ThreatMetrics
from threat_api.models import EnrichedIOC
from threat_api.normalization import boost_confidence_by_correlation, normalize_iocs
from threat_api.opencti_push import push_stix_to_opencti
from threat_api.rate_limit import SimpleRateLimiter
from threat_api.retention import cleanup_old_iocs
from threat_api.scheduler import IntervalScheduler
from threat_api.source_health import build_source_health
from threat_api.stix_converter.converter import convert_to_stix_bundle, save_bundle_to_file
from threat_api.trust_scoring import apply_trust_scoring, load_trust_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}})

limiter = SimpleRateLimiter(RATE_LIMIT_PER_MINUTE)
metrics = ThreatMetrics()
scheduler = None

# In-memory IOC store — restored from DB on startup, updated after each pipeline run
_store: list = []
_store_lock = threading.Lock()
_last_fetch: datetime | None = None
_last_source_health: dict = {}

# Single-flight lock prevents concurrent pipeline runs
_fetch_lock = threading.Lock()

# Job tracking (ephemeral, in-memory)
_jobs: Dict[str, dict] = {}
_jobs_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    logging.exception("Unhandled exception")
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ---------------------------------------------------------------------------
# Auth / rate limiting
# ---------------------------------------------------------------------------

def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key or key != APP_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        client = request.remote_addr or "unknown"
        if not limiter.allow(client):
            return jsonify({"error": "Rate limit exceeded"}), 429
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Job helpers
# ---------------------------------------------------------------------------

def _update_job(job_id: str, status: str, **kwargs):
    now = datetime.now(timezone.utc).isoformat()
    with _jobs_lock:
        existing = _jobs.get(job_id, {"created_at": now})
        _jobs[job_id] = {
            "job_id": job_id,
            "status": status,
            "created_at": existing.get("created_at", now),
            "updated_at": now,
            **kwargs,
        }


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "threat_api"})


@app.get("/ready")
def ready():
    return jsonify({"ready": True})


@app.get("/metrics")
def get_metrics():
    return jsonify(metrics.to_dict())


@app.get("/")
def root():
    with _store_lock:
        ioc_count = len(_store)
    return jsonify({
        "service": "Threat API",
        "status": "running",
        "iocs_in_memory": ioc_count,
        "last_fetch": _last_fetch.isoformat() if _last_fetch else None,
        "feeds": {
            "rss": len(get_configured_rss_feeds()),
            "darkweb_osint": len(get_configured_darkweb_sources()),
            "social_osint": len(get_configured_social_sources()),
        },
    })


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------

@app.get("/source-health")
@require_api_key
def source_health():
    return jsonify(_last_source_health or {"message": "No fetch has run yet"})


@app.get("/source-stats")
@require_api_key
def source_stats():
    with _store_lock:
        store = _store[:]
    counts: dict = {}
    for i in store:
        counts[i.source] = counts.get(i.source, 0) + 1
    return jsonify({"total_iocs": len(store), "by_source": counts})


@app.get("/trust/config")
@require_api_key
def get_trust_config():
    return jsonify(load_trust_config())


@app.post("/fetch")
@require_api_key
def fetch():
    enrich_raw = request.args.get("enrich", "true").lower()
    if enrich_raw not in ("true", "false"):
        return jsonify({"error": "enrich must be true|false"}), 400
    enrich = enrich_raw == "true"

    try:
        max_enrich = int(request.args.get("max_enrich", min(50, PIPELINE_MAX_ENRICH)))
    except ValueError:
        return jsonify({"error": "max_enrich must be an integer"}), 400
    if not (0 <= max_enrich <= PIPELINE_MAX_ENRICH):
        return jsonify({"error": f"max_enrich must be 0–{PIPELINE_MAX_ENRICH}"}), 400

    # ?wait=true keeps the old blocking behaviour (useful for CLI / scripts)
    wait = request.args.get("wait", "false").lower() == "true"

    if not _fetch_lock.acquire(blocking=False):
        with _jobs_lock:
            running = [j for j in _jobs.values() if j["status"] in ("queued", "running")]
        payload = {"error": "A fetch is already in progress"}
        if running:
            payload["job_id"] = running[0]["job_id"]
        return jsonify(payload), 409

    job_id = str(uuid.uuid4())
    _update_job(job_id, "queued")

    if wait:
        try:
            _run_pipeline(enrich, max_enrich, job_id)
            with _store_lock:
                total = len(_store)
            return jsonify({"job_id": job_id, "status": "completed", "total_iocs": total})
        except Exception as e:
            logging.exception("Fetch pipeline failed")
            metrics.mark_failure()
            _update_job(job_id, "failed", error=str(e))
            return jsonify({"job_id": job_id, "status": "failed", "error": str(e)}), 500
        finally:
            _fetch_lock.release()
    else:
        def _bg():
            try:
                _run_pipeline(enrich, max_enrich, job_id)
            except Exception as e:
                logging.exception("Background fetch failed")
                metrics.mark_failure()
                _update_job(job_id, "failed", error=str(e))
            finally:
                _fetch_lock.release()

        threading.Thread(target=_bg, daemon=True, name=f"fetch-{job_id[:8]}").start()
        return jsonify({"job_id": job_id, "status": "queued"})


@app.get("/jobs")
@require_api_key
def list_jobs():
    with _jobs_lock:
        jobs = sorted(_jobs.values(), key=lambda j: j.get("created_at", ""), reverse=True)[:50]
    return jsonify(jobs)


@app.get("/jobs/<job_id>")
@require_api_key
def get_job(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.get("/iocs")
@require_api_key
def iocs():
    ioc_type = request.args.get("ioc_type")
    source = request.args.get("source")
    threat_type = request.args.get("threat_type")
    malicious_only = request.args.get("malicious_only", "false").lower() == "true"

    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400

    valid_types = {"ip", "domain", "url", "hash"}
    if ioc_type and ioc_type not in valid_types:
        return jsonify({"error": f"ioc_type must be one of {sorted(valid_types)}"}), 400

    with _store_lock:
        results = _store[:]

    if ioc_type:
        results = [i for i in results if i.ioc_type == ioc_type]
    if source:
        results = [i for i in results if source.lower() in i.source.lower()]
    if threat_type:
        results = [i for i in results if i.threat_type == threat_type]
    if malicious_only:
        results = [i for i in results if (i.vt_malicious_count or 0) > 0]

    return jsonify([i.model_dump(mode="json") for i in results[offset: offset + limit]])


@app.post("/stix/export")
@require_api_key
def export_stix():
    with _store_lock:
        store_copy = _store[:]
    if not store_copy:
        return jsonify({"error": "No IOCs available. Run /fetch first."}), 404
    bundle = convert_to_stix_bundle(store_copy)
    save_bundle_to_file(bundle, BUNDLE_PATH)
    resp = jsonify(bundle)
    resp.headers["Content-Type"] = "application/stix+json"
    return resp


@app.post("/opencti/push")
@require_api_key
def opencti_push():
    if not OPENCTI_ENABLED:
        return jsonify({"ok": False, "error": "OpenCTI push disabled (OPENCTI_ENABLED=false)"}), 400
    if not os.path.exists(BUNDLE_PATH):
        return jsonify({"error": "No STIX bundle found. Run /stix/export first."}), 404
    with open(BUNDLE_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    result = push_stix_to_opencti(OPENCTI_URL, OPENCTI_API_KEY, bundle)
    return jsonify(result), (200 if result.get("ok") else 400)


# ---------------------------------------------------------------------------
# OpenCTI read endpoints (for frontend dashboard)
# ---------------------------------------------------------------------------

@app.get("/opencti/status")
@require_api_key
def opencti_status():
    if not OPENCTI_ENABLED:
        return jsonify({"connected": False, "reason": "OPENCTI_ENABLED=false"})
    try:
        data = _gql("{ me { id name entity_type } }")
        me = data.get("data", {}).get("me", {})
        if me:
            return jsonify({"connected": True, "user": me.get("name"), "url": OPENCTI_URL})
        return jsonify({"connected": False, "reason": "Unexpected OpenCTI response"})
    except requests.exceptions.ConnectionError:
        return jsonify({"connected": False, "reason": f"Cannot reach {OPENCTI_URL}"})
    except Exception as e:
        return jsonify({"connected": False, "reason": str(e)})


@app.get("/opencti/stats")
@require_api_key
def opencti_stats():
    if not OPENCTI_ENABLED:
        return jsonify({"error": "OpenCTI not enabled"}), 400
    query = """
    {
      indicators(first: 1)      { pageInfo { totalCount } }
      reports(first: 1)         { pageInfo { totalCount } }
      malwares(first: 1)        { pageInfo { totalCount } }
      attackPatterns(first: 1)  { pageInfo { totalCount } }
      stixDomainObjects(first: 1) { pageInfo { totalCount } }
    }
    """
    try:
        data = _gql(query).get("data", {})
        return jsonify({
            "indicators":     _count(data, "indicators"),
            "reports":        _count(data, "reports"),
            "malwares":       _count(data, "malwares"),
            "attack_patterns": _count(data, "attackPatterns"),
            "total_objects":  _count(data, "stixDomainObjects"),
        })
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach OpenCTI at {OPENCTI_URL}"}), 503
    except Exception as e:
        logging.exception("OpenCTI stats failed")
        return jsonify({"error": str(e)}), 500


@app.get("/opencti/indicators")
@require_api_key
def opencti_indicators():
    if not OPENCTI_ENABLED:
        return jsonify({"error": "OpenCTI not enabled"}), 400
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 500))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    after = request.args.get("after")

    query = """
    query GetIndicators($first: Int, $after: String) {
      indicators(first: $first, after: $after, orderBy: created, orderMode: desc) {
        pageInfo { hasNextPage endCursor totalCount }
        edges {
          node {
            id name description
            pattern pattern_type indicator_types
            valid_from valid_until
            x_opencti_score x_opencti_main_observable_type
            created modified
          }
        }
      }
    }
    """
    variables: dict = {"first": limit}
    if after:
        variables["after"] = after

    try:
        raw = _gql(query, variables).get("data", {}).get("indicators", {})
        return jsonify({
            "page_info": raw.get("pageInfo", {}),
            "indicators": [e["node"] for e in raw.get("edges", [])],
        })
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach OpenCTI at {OPENCTI_URL}"}), 503
    except Exception as e:
        logging.exception("OpenCTI indicators fetch failed")
        return jsonify({"error": str(e)}), 500


@app.get("/opencti/search")
@require_api_key
def opencti_search():
    if not OPENCTI_ENABLED:
        return jsonify({"error": "OpenCTI not enabled"}), 400
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "q parameter is required"}), 400

    query = """
    query Search($search: String) {
      indicators(first: 25, search: $search) {
        edges {
          node {
            id name description pattern indicator_types
            valid_from valid_until x_opencti_score created
          }
        }
      }
      stixDomainObjects(first: 25, search: $search) {
        edges {
          node { id entity_type ... on Malware { name description }
                          ... on ThreatActor { name description }
                          ... on AttackPattern { name description } }
        }
      }
    }
    """
    try:
        data = _gql(query, {"search": q}).get("data", {})
        return jsonify({
            "indicators": [e["node"] for e in data.get("indicators", {}).get("edges", [])],
            "objects":    [e["node"] for e in data.get("stixDomainObjects", {}).get("edges", [])],
        })
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach OpenCTI at {OPENCTI_URL}"}), 503
    except Exception as e:
        logging.exception("OpenCTI search failed")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _gql(query: str, variables: dict = None) -> dict:
    url = f"{OPENCTI_URL.rstrip('/')}/graphql"
    headers = {"Authorization": f"Bearer {OPENCTI_API_KEY}", "Content-Type": "application/json"}
    payload: dict = {"query": query}
    if variables:
        payload["variables"] = variables
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()


def _count(data: dict, key: str) -> int:
    return data.get(key, {}).get("pageInfo", {}).get("totalCount", 0)


def _cap(items, n):
    return items[:max(0, n)]


def _empty_result(name: str):
    from threat_api.models import FetchResult
    return FetchResult(source=name, ioc_count=0, iocs=[], fetched_at=datetime.now(timezone.utc), errors=[])


def _run_pipeline(enrich: bool, max_enrich: int, job_id: str = None):
    global _store, _last_fetch, _last_source_health

    def _stage(label, **kw):
        if job_id:
            _update_job(job_id, "running", stage=label, **kw)
        logging.info("[pipeline] %s", label)

    # ── 1. Parallel source fetching ──────────────────────────────────────
    _stage("fetching sources")
    fetcher_map = {}
    if ENABLE_OTX:           fetcher_map["otx"] = fetch_otx_iocs
    if ENABLE_ABUSECH:       fetcher_map["abusech"] = fetch_abusech_iocs
    if ENABLE_RSS:           fetcher_map["rss"] = fetch_rss_iocs
    if ENABLE_DARKWEB_OSINT: fetcher_map["darkweb_osint"] = fetch_darkweb_osint_iocs
    if ENABLE_SOCIAL_OSINT:  fetcher_map["social_osint"] = fetch_social_osint_iocs

    fetch_results = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        future_to_name = {pool.submit(fn): name for name, fn in fetcher_map.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                fetch_results[name] = future.result()
            except Exception as e:
                logging.error("Fetcher %s failed: %s", name, e)
                fetch_results[name] = _empty_result(name)

    for name in ("otx", "abusech", "rss", "darkweb_osint", "social_osint"):
        fetch_results.setdefault(name, _empty_result(name))

    # ── 2. Aggregate & normalise ─────────────────────────────────────────
    _stage("normalizing and deduplicating")
    all_iocs = []
    for name in ("otx", "abusech", "rss", "darkweb_osint", "social_osint"):
        all_iocs.extend(_cap(fetch_results[name].iocs, PIPELINE_MAX_IOCS_PER_SOURCE))
    all_iocs = _cap(all_iocs, PIPELINE_MAX_TOTAL_IOCS)

    normalized = normalize_iocs(all_iocs)
    trusted = apply_trust_scoring(normalized, load_trust_config())

    seen: set = set()
    dedup = []
    for i in trusted:
        k = (i.ioc_type, i.value, i.source)
        if k not in seen:
            seen.add(k)
            dedup.append(i)

    correlated = boost_confidence_by_correlation(dedup)
    for i in correlated:
        i.extra = i.extra or {}
        i.extra["confidence_explain"] = {
            "final_confidence": i.confidence,
            "tags": (i.tags or [])[:8],
        }

    # ── 3. Enrichment ────────────────────────────────────────────────────
    if enrich:
        _stage("enriching with VirusTotal", total=len(correlated), max_enrich=max_enrich)
        enriched = enrich_iocs(correlated, max_enrichments=max_enrich)
    else:
        enriched = [
            EnrichedIOC(**i.model_dump(), enrichment_status="skipped",
                        enrichment_error="enrichment disabled")
            for i in correlated
        ]

    # ── 4. Persist & publish ─────────────────────────────────────────────
    _stage("persisting to database")
    with _store_lock:
        _store = enriched
    _last_fetch = datetime.now(timezone.utc)
    upsert_iocs(enriched)
    cleanup_old_iocs(days=30)

    _last_source_health = build_source_health({
        name: {"count": r.ioc_count, "errors": r.errors}
        for name, r in fetch_results.items()
    })
    metrics.mark_success(len(enriched))

    if job_id:
        _update_job(job_id, "completed",
                    total_iocs=len(enriched),
                    source_health=_last_source_health)


def _scheduled_fetch():
    if _fetch_lock.acquire(blocking=False):
        try:
            _run_pipeline(enrich=True, max_enrich=min(25, PIPELINE_MAX_ENRICH))
        except Exception:
            logging.exception("Scheduled fetch failed")
            metrics.mark_failure()
        finally:
            _fetch_lock.release()


if __name__ == "__main__":
    init_db()
    restored = load_iocs_from_db()
    if restored:
        _store = restored
        logging.info("Restored %d IOCs from database", len(restored))

    if ENABLE_SCHEDULER and not FLASK_DEBUG:
        scheduler = IntervalScheduler(SCHEDULE_FETCH_CRON_MINUTES * 60, _scheduled_fetch)
        scheduler.start()

    app.run(host=API_HOST, port=API_PORT, debug=FLASK_DEBUG)
