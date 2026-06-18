"""Cold-storage archival for retention: write purged rows to compressed NDJSON
before they're deleted, so a compliance team can keep raw logs cheaply.

Two sinks, each independently enableable (both run when both are configured, and
a purge is gated on EVERY enabled sink succeeding - a failure raises so the
caller leaves the batch intact rather than deleting it unarchived):

  - **local dir**   - `DASHBOARD_ARCHIVE_DIR`: one gzipped, append-friendly
    NDJSON file per table per purge day (`<table>-<YYYYMMDD>.ndjson.gz`).
  - **object store** - `DASHBOARD_ARCHIVE_S3_BUCKET` (+ `_PREFIX`/`_REGION`/
    `_ENDPOINT`): one **immutable** gzip object per purge batch, written with an
    AWS SigV4-signed `PUT` (works against S3 and S3-compatible stores - MinIO,
    Cloudflare R2, Backblaze B2). Credentials come from the standard AWS
    environment (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / optional
    `AWS_SESSION_TOKEN`). Sync the local dir to object storage, or write straight
    to it - either way cold storage no longer has to be a local disk.
"""
import gzip
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone

_HTTP_TIMEOUT = 30


# ── configuration (read live from config so tests/ops can flip it) ──
def _local_dir() -> str:
    from dashboard_api import config
    return getattr(config, "ARCHIVE_DIR", "") or ""


def _s3_config() -> dict | None:
    from dashboard_api import config
    bucket = getattr(config, "ARCHIVE_S3_BUCKET", "") or ""
    if not bucket:
        return None
    return {
        "bucket": bucket,
        "prefix": (getattr(config, "ARCHIVE_S3_PREFIX", "") or "").strip("/"),
        "region": (getattr(config, "ARCHIVE_S3_REGION", "") or "us-east-1"),
        "endpoint": (getattr(config, "ARCHIVE_S3_ENDPOINT", "") or "").strip(),
        "access_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
        "secret_key": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "session_token": os.environ.get("AWS_SESSION_TOKEN", ""),
    }


def enabled() -> bool:
    return bool(_local_dir() or _s3_config())


def targets() -> dict:
    """Human-readable summary of where archives go (for the retention response)."""
    out = {}
    if _local_dir():
        out["dir"] = _local_dir()
    s3 = _s3_config()
    if s3:
        out["s3"] = f"s3://{s3['bucket']}/{s3['prefix']}".rstrip("/")
    return out


def _ndjson(rows: list) -> str:
    return "".join(json.dumps(dict(r), default=str, separators=(",", ":")) + "\n" for r in rows)


def archive_rows(table: str, rows: list) -> str | None:
    """Archive `rows` for `table` to every configured sink. Returns a target
    description, or None when archival is disabled or there's nothing to write.
    Raises OSError on any sink failure so the caller can abort the delete (rows
    must never be purged unarchived)."""
    if not rows or not enabled():
        return None
    body = _ndjson(rows)
    written = []
    if _local_dir():
        written.append(_write_local(table, body))
    s3 = _s3_config()
    if s3:
        written.append(_write_s3(s3, table, body))
    return ", ".join(written)


def _write_local(table: str, body: str) -> str:
    os.makedirs(_local_dir(), exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    path = os.path.join(_local_dir(), f"{table}-{day}.ndjson.gz")
    with gzip.open(path, "at", encoding="utf-8") as fh:
        fh.write(body)
    return path


def _write_s3(s3: dict, table: str, body: str) -> str:
    """Gzip `body` and PUT it as one immutable object. Wraps any failure as
    OSError so the retention guard ('never delete unarchived') triggers."""
    now = datetime.now(timezone.utc)
    key = "/".join(p for p in (
        s3["prefix"], table, now.strftime("%Y/%m/%d"),
        f"{table}-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}.ndjson.gz",
    ) if p)
    blob = gzip.compress(body.encode("utf-8"))
    try:
        return _sigv4_put(s3, key, blob)
    except OSError:
        raise
    except Exception as e:  # network/HTTP/anything → OSError so the caller aborts
        raise OSError(f"S3 archive PUT failed: {e}") from e


# ── AWS Signature Version 4 (stdlib only) ──
def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    def _h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    k_date = _h(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _h(k_date, region)
    k_service = _h(k_region, service)
    return _h(k_service, "aws4_request")


def _sigv4_put(s3: dict, key: str, body: bytes, content_type: str = "application/gzip") -> str:
    """Sign and PUT `body` to bucket/key. Keys use only unreserved chars + '/',
    so the canonical URI is the path verbatim (no extra percent-encoding)."""
    region, service = s3["region"], "s3"
    if s3["endpoint"]:                                   # path-style (S3-compatible)
        ep = s3["endpoint"]
        scheme = "http" if ep.startswith("http://") else "https"
        host = ep.split("://", 1)[-1].strip("/")
        canonical_uri = f"/{s3['bucket']}/{key}"
    else:                                                # AWS virtual-hosted
        scheme = "https"
        host = f"{s3['bucket']}.s3.{region}.amazonaws.com"
        canonical_uri = f"/{key}"
    url = f"{scheme}://{host}{canonical_uri}"

    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()

    headers = {
        "host": host,
        "content-type": content_type,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amzdate,
    }
    if s3["session_token"]:
        headers["x-amz-security-token"] = s3["session_token"]
    signed_headers, scope, signature = _sign(
        "PUT", canonical_uri, headers, payload_hash, region, service,
        amzdate, datestamp, s3["secret_key"])
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={s3['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    _http_put(url, body, headers)
    return f"s3://{s3['bucket']}/{key}"


def _sign(method: str, canonical_uri: str, headers: dict, payload_hash: str,
          region: str, service: str, amzdate: str, datestamp: str,
          secret: str) -> tuple[str, str, str]:
    """The SigV4 canonical-request → string-to-sign → signature pipeline.
    Returns (signed_headers, credential_scope, signature_hex). Isolated so it can
    be checked against AWS's published example vectors."""
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    canonical_request = "\n".join([
        method, canonical_uri, "", canonical_headers, signed_headers, payload_hash,
    ])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amzdate, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(_signing_key(secret, datestamp, region, service),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return signed_headers, scope, signature


def _http_put(url: str, body: bytes, headers: dict) -> None:
    """PUT `body` to `url`; raise on a non-2xx status. Isolated so tests can stub
    the network."""
    import httpx
    r = httpx.put(url, content=body, headers=headers, timeout=_HTTP_TIMEOUT)
    if r.status_code >= 300:
        raise OSError(f"S3 PUT {url} → HTTP {r.status_code}: {r.text[:200]}")
