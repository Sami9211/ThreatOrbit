"""Agentless log pull: tail an S3 (or S3-compatible) bucket prefix and ingest
new objects, so logs already landing in object storage flow into the SIEM with
no agent or forwarder.

Enabled by `DASHBOARD_S3_PULL_BUCKET` (+ `_PREFIX`/`_REGION`/`_ENDPOINT`/`_ORG`).
On each tick the poller lists objects after a stored checkpoint key
(`ListObjectsV2` with `start-after`), GETs the new ones, splits them into lines,
and feeds them through `ingest_lines` (stamped with `_ORG` for per-tenant pull).
The checkpoint advances to the last key processed, so a restart never re-ingests
or skips. Stdlib-only AWS SigV4 (reusing `archive._signing_key`), GET signing
adds the canonical query string; works against AWS and S3-compatible stores
(MinIO/R2/B2 via `_ENDPOINT`). Credentials come from the standard AWS env.

The poller is driven by the connector scheduler (leader-only) so two replicas
never double-ingest. The HTTP call is isolated (`_http_get`) so it's unit-tested
against canned responses without a live bucket.
"""
import hashlib
import hmac
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

from dashboard_api.archive import _signing_key

logger = logging.getLogger("dashboard_api.s3_pull")

_HTTP_TIMEOUT = 30
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def s3_config() -> dict | None:
    from dashboard_api import config
    bucket = getattr(config, "S3_PULL_BUCKET", "") or ""
    if not bucket:
        return None
    return {
        "bucket": bucket,
        "prefix": (getattr(config, "S3_PULL_PREFIX", "") or "").lstrip("/"),
        "region": (getattr(config, "S3_PULL_REGION", "") or "us-east-1"),
        "endpoint": (getattr(config, "S3_PULL_ENDPOINT", "") or "").strip(),
        "org_id": (getattr(config, "S3_PULL_ORG", "") or "org-default"),
        "access_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
        "secret_key": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "session_token": os.environ.get("AWS_SESSION_TOKEN", ""),
    }


def enabled() -> bool:
    return s3_config() is not None


def _canonical_query(params: dict) -> str:
    items = sorted((quote(str(k), safe=""), quote(str(v), safe=""))
                   for k, v in params.items() if v not in (None, ""))
    return "&".join(f"{k}={v}" for k, v in items)


def _signed_get(s3: dict, canonical_uri: str, params: dict) -> tuple[str, dict]:
    """Build a SigV4-signed GET. Returns (full_url, headers)."""
    region, service = s3["region"], "s3"
    if s3["endpoint"]:
        ep = s3["endpoint"]
        scheme = "http" if ep.startswith("http://") else "https"
        host = ep.split("://", 1)[-1].strip("/")
    else:
        scheme, host = "https", f"{s3['bucket']}.s3.{region}.amazonaws.com"
    now = datetime.now(timezone.utc)
    amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    headers = {"host": host, "x-amz-content-sha256": _EMPTY_SHA256, "x-amz-date": amzdate}
    if s3["session_token"]:
        headers["x-amz-security-token"] = s3["session_token"]
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    cq = _canonical_query(params)
    canonical_request = "\n".join(["GET", canonical_uri, cq, canonical_headers,
                                   signed_headers, _EMPTY_SHA256])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    signature = hmac.new(_signing_key(s3["secret_key"], datestamp, region, service),
                         string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={s3['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}")
    url = f"{scheme}://{host}{canonical_uri}"
    if cq:
        url += f"?{cq}"
    return url, headers


def list_objects(s3: dict, start_after: str = "", max_keys: int = 1000) -> list[str]:
    """List object keys under the prefix (sorted), after `start_after`."""
    uri = f"/{s3['bucket']}/" if s3["endpoint"] else "/"
    params = {"list-type": "2", "max-keys": str(max_keys)}
    if s3["prefix"]:
        params["prefix"] = s3["prefix"]
    if start_after:
        params["start-after"] = start_after
    url, headers = _signed_get(s3, uri, params)
    body = _http_get(url, headers)
    return sorted(re.findall(r"<Key>([^<]+)</Key>", body))


def get_object(s3: dict, key: str) -> str:
    uri = f"/{s3['bucket']}/{key}" if s3["endpoint"] else f"/{key}"
    url, headers = _signed_get(s3, uri, {})
    return _http_get(url, headers)


def _cursor_key(s3: dict) -> str:
    return f"s3_pull_cursor:{s3['bucket']}/{s3['prefix']}"


def poll(s3: dict, *, max_objects: int = 50) -> dict:
    """List → fetch → ingest new objects past the checkpoint, then advance it.
    Returns {objects, ingested, alerts, cursor}."""
    from dashboard_api.db import get_conn
    from dashboard_api.ingest import ingest_lines
    org_id = s3.get("org_id") or "org-default"
    ck = _cursor_key(s3)
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (ck,)).fetchone()
        start_after = row["value"] if row else ""
    keys = [k for k in list_objects(s3, start_after) if k > start_after][:max_objects]
    objects = ingested = alerts = 0
    last = start_after
    for key in keys:
        try:
            body = get_object(s3, key)
            lines = [ln for ln in body.splitlines() if ln.strip()]
            if lines:
                res = ingest_lines(lines, "auto", f"s3:{key}", org_id)
                ingested += res["parsed"]
                alerts += res["alerts"]
        except Exception:
            # One bad object (network blip, transient throttling/5xx, a
            # malformed body) must not discard the whole batch. Stop here, but
            # advance the checkpoint up to (not including) this key first, so
            # the objects already ingested this poll are never re-ingested on
            # retry - and a permanently-broken object blocks only itself, not
            # progress through everything before it.
            logger.warning("S3 pull: failed on %s; stopping this poll, will retry", key,
                           exc_info=True)
            break
        objects += 1
        last = key
    if last != start_after:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (ck, last))
            conn.commit()
    return {"objects": objects, "ingested": ingested, "alerts": alerts, "cursor": last}


_last_poll = 0.0


def poll_if_configured() -> dict | None:
    """Scheduler hook: poll when an S3 source is configured and at most once per
    `DASHBOARD_S3_PULL_SECONDS`; never raise."""
    global _last_poll
    s3 = s3_config()
    if not s3:
        return None
    import time
    from dashboard_api.config import S3_PULL_INTERVAL
    if time.time() - _last_poll < S3_PULL_INTERVAL:
        return None
    _last_poll = time.time()
    try:
        result = poll(s3)
        if result["objects"]:
            logger.info("S3 pull: %d objects, %d events, %d alerts (cursor=%s)",
                        result["objects"], result["ingested"], result["alerts"], result["cursor"])
        return result
    except Exception:
        logger.exception("S3 pull failed")
        return None


def status() -> dict:
    s3 = s3_config()
    if not s3:
        return {"enabled": False}
    return {"enabled": True, "bucket": s3["bucket"], "prefix": s3["prefix"],
            "endpoint": s3["endpoint"] or None, "org": s3["org_id"]}


def _http_get(url: str, headers: dict) -> str:
    """GET `url`; return the text body, raise on non-2xx. Isolated for tests."""
    import httpx
    r = httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT)
    if r.status_code >= 300:
        raise OSError(f"S3 GET {url} → HTTP {r.status_code}: {r.text[:200]}")
    return r.text
