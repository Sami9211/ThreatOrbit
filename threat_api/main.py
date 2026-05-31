from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime, timezone
import uuid
import json
import os
import logging

from threat_api.config import (
    API_HOST, API_PORT, APP_API_KEY, FLASK_DEBUG,
    RATE_LIMIT_PER_MINUTE, ENABLE_SCHEDULER, SCHEDULE_FETCH_CRON_MINUTES,
    OPENCTI_URL, OPENCTI_API_KEY, OPENCTI_ENABLED,
    ENABLE_OTX, ENABLE_ABUSECH, ENABLE_RSS, ENABLE_DARKWEB_OSINT, ENABLE_SOCIAL_OSINT,
    PIPELINE_MAX_IOCS_PER_SOURCE, PIPELINE_MAX_TOTAL_IOCS, PIPELINE_MAX_ENRICH, BUNDLE_PATH
)
from threat_api.models import EnrichedIOC
from threat_api.fetchers.otx import fetch_otx_iocs
from threat_api.fetchers.abusech import fetch_abusech_iocs
from threat_api.fetchers.rss import fetch_rss_iocs, get_configured_rss_feeds
from threat_api.fetchers.darkweb_osint import fetch_darkweb_osint_iocs, get_configured_darkweb_sources
from threat_api.fetchers.social_osint import fetch_social_osint_iocs, get_configured_social_sources
from threat_api.normalization import normalize_iocs, boost_confidence_by_correlation
from threat_api.trust_scoring import load_trust_config, apply_trust_scoring
from threat_api.enrichment.virustotal import enrich_iocs
from threat_api.stix_converter.converter import convert_to_stix_bundle, save_bundle_to_file
from threat_api.rate_limit import SimpleRateLimiter
from threat_api.source_health import build_source_health
from threat_api.opencti_push import push_stix_to_opencti
from threat_api.retention import cleanup_old_iocs
from threat_api.metrics import ThreatMetrics
from threat_api.scheduler import IntervalScheduler
from threat_api.db import init_db, upsert_iocs

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

limiter = SimpleRateLimiter(RATE_LIMIT_PER_MINUTE)
metrics = ThreatMetrics()
scheduler = None

_store = []
_last_fetch = None
_last_source_health = {}
_fetch_in_progress = False


@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    logging.exception("Unhandled exception")
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


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
    return jsonify({
        "service": "Threat API",
        "status": "running",
        "iocs_in_memory": len(_store),
        "last_fetch": _last_fetch.isoformat() if _last_fetch else None,
        "feeds": {
            "rss": len(get_configured_rss_feeds()),
            "darkweb_osint": len(get_configured_darkweb_sources()),
            "social_osint": len(get_configured_social_sources()),
        }
    })


@app.get("/source-health")
@require_api_key
def source_health():
    return jsonify(_last_source_health or {"message": "No fetch has run yet"})


@app.get("/source-stats")
@require_api_key
def source_stats():
    counts = {}
    for i in _store:
        counts[i.source] = counts.get(i.source, 0) + 1
    return jsonify({"total_iocs": len(_store), "by_source": counts})


@app.get("/trust/config")
@require_api_key
def get_trust_config():
    return jsonify(load_trust_config())


@app.post("/fetch")
@require_api_key
def fetch():
    global _fetch_in_progress
    if _fetch_in_progress:
        return jsonify({"error": "A fetch is already in progress"}), 409

    enrich_raw = request.args.get("enrich", "true").lower()
    if enrich_raw not in ("true", "false"):
        return jsonify({"error": "enrich must be true|false"}), 400
    enrich = enrich_raw == "true"

    try:
        max_enrich = int(request.args.get("max_enrich", min(50, PIPELINE_MAX_ENRICH)))
    except ValueError:
        return jsonify({"error": "max_enrich must be an integer"}), 400

    if max_enrich < 0 or max_enrich > PIPELINE_MAX_ENRICH:
        return jsonify({"error": f"max_enrich must be between 0 and {PIPELINE_MAX_ENRICH}"}), 400

    job_id = str(uuid.uuid4())
    try:
        _run_pipeline(enrich, max_enrich)
        metrics.mark_success(len(_store))
        cleanup_old_iocs(days=30)
        return jsonify({"job_id": job_id, "status": "completed", "total_iocs": len(_store)})
    except Exception as e:
        logging.exception("Fetch failed")
        metrics.mark_failure()
        return jsonify({"job_id": job_id, "status": "failed", "error": str(e)}), 500


@app.get("/iocs")
@require_api_key
def iocs():
    ioc_type = request.args.get("ioc_type")
    source = request.args.get("source")
    threat_type = request.args.get("threat_type")
    malicious_only = request.args.get("malicious_only", "false").lower() == "true"
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    results = _store
    if ioc_type:
        results = [i for i in results if i.ioc_type == ioc_type]
    if source:
        results = [i for i in results if source.lower() in i.source.lower()]
    if threat_type:
        results = [i for i in results if i.threat_type == threat_type]
    if malicious_only:
        results = [i for i in results if (i.vt_malicious_count or 0) > 0]

    sliced = results[offset: offset + max(1, min(limit, 1000))]
    return jsonify([i.model_dump(mode="json") for i in sliced])


@app.post("/stix/export")
@require_api_key
def export_stix():
    if not _store:
        return jsonify({"error": "No IOCs available. Run /fetch first."}), 404

    bundle = convert_to_stix_bundle(_store)
    save_bundle_to_file(bundle, BUNDLE_PATH)
    return jsonify(bundle)


@app.post("/opencti/push")
@require_api_key
def opencti_push():
    if not OPENCTI_ENABLED:
        return jsonify({"ok": False, "error": "OpenCTI push disabled by config (OPENCTI_ENABLED=false)"}), 400

    if not os.path.exists(BUNDLE_PATH):
        return jsonify({"error": "No STIX bundle found. Run /stix/export first."}), 404

    with open(BUNDLE_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    result = push_stix_to_opencti(OPENCTI_URL, OPENCTI_API_KEY, bundle)
    return jsonify(result), (200 if result.get("ok") else 400)


def _cap(items, n):
    return items[:max(0, n)]


def _run_pipeline(enrich: bool, max_enrich: int):
    global _store, _last_fetch, _last_source_health, _fetch_in_progress
    _fetch_in_progress = True
    try:
        res_otx = fetch_otx_iocs() if ENABLE_OTX else _empty_result("otx")
        res_abuse = fetch_abusech_iocs() if ENABLE_ABUSECH else _empty_result("abusech")
        res_rss = fetch_rss_iocs() if ENABLE_RSS else _empty_result("rss")
        res_dark = fetch_darkweb_osint_iocs() if ENABLE_DARKWEB_OSINT else _empty_result("darkweb_osint")
        res_social = fetch_social_osint_iocs() if ENABLE_SOCIAL_OSINT else _empty_result("social_osint")

        all_iocs = (
            _cap(res_otx.iocs, PIPELINE_MAX_IOCS_PER_SOURCE)
            + _cap(res_abuse.iocs, PIPELINE_MAX_IOCS_PER_SOURCE)
            + _cap(res_rss.iocs, PIPELINE_MAX_IOCS_PER_SOURCE)
            + _cap(res_dark.iocs, PIPELINE_MAX_IOCS_PER_SOURCE)
            + _cap(res_social.iocs, PIPELINE_MAX_IOCS_PER_SOURCE)
        )
        all_iocs = _cap(all_iocs, PIPELINE_MAX_TOTAL_IOCS)

        normalized = normalize_iocs(all_iocs)
        trusted = apply_trust_scoring(normalized, load_trust_config())

        seen = set()
        dedup = []
        for i in trusted:
            k = (i.ioc_type, i.value, i.source)
            if k in seen:
                continue
            seen.add(k)
            dedup.append(i)

        correlated = boost_confidence_by_correlation(dedup)

        for i in correlated:
            i.extra = i.extra or {}
            i.extra["confidence_explain"] = {
                "final_confidence": i.confidence,
                "tags": (i.tags or [])[:8]
            }

        if enrich:
            enriched = enrich_iocs(correlated, max_enrichments=max_enrich)
        else:
            enriched = [
                EnrichedIOC(
                    **i.model_dump(),
                    enrichment_status="skipped",
                    enrichment_error="enrichment disabled"
                )
                for i in correlated
            ]

        _store = enriched
        upsert_iocs(enriched)
        _last_fetch = datetime.now(timezone.utc)

        _last_source_health = build_source_health({
            "otx": {"count": len(res_otx.iocs), "errors": res_otx.errors},
            "abusech": {"count": len(res_abuse.iocs), "errors": res_abuse.errors},
            "rss": {"count": len(res_rss.iocs), "errors": res_rss.errors},
            "darkweb_osint": {"count": len(res_dark.iocs), "errors": res_dark.errors},
            "social_osint": {"count": len(res_social.iocs), "errors": res_social.errors},
        })
    finally:
        _fetch_in_progress = False


def _scheduled_fetch():
    if _fetch_in_progress:
        return
    try:
        _run_pipeline(enrich=True, max_enrich=min(25, PIPELINE_MAX_ENRICH))
        metrics.mark_success(len(_store))
        cleanup_old_iocs(days=30)
    except Exception:
        logging.exception("Scheduled fetch failed")
        metrics.mark_failure()


def _empty_result(source_name: str):
    from threat_api.models import FetchResult
    return FetchResult(source=source_name, ioc_count=0, iocs=[], fetched_at=datetime.now(timezone.utc), errors=[])


if __name__ == "__main__":
    init_db()
    if ENABLE_SCHEDULER and not FLASK_DEBUG:
        scheduler = IntervalScheduler(SCHEDULE_FETCH_CRON_MINUTES * 60, _scheduled_fetch)
        scheduler.start()
    app.run(host=API_HOST, port=API_PORT, debug=FLASK_DEBUG)
