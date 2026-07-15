from typing import List, Dict
from urllib.parse import urlparse
import ipaddress
import logging
from threat_api.models import IOC

logger = logging.getLogger("threat_api.normalization")


def normalize_iocs(iocs: List[IOC]) -> List[IOC]:
    normalized = []
    for ioc in iocs:
        # Per-IOC isolation: one malformed value from a feed (e.g. a url/domain
        # like "http://[" that makes urlparse raise) must never abort the whole
        # refresh - that would discard every IOC from every source. Skip it.
        try:
            v = (ioc.value or "").strip()
            if not v:
                continue

            if ioc.ioc_type == "domain":
                v = _normalize_domain(v)
            elif ioc.ioc_type == "url":
                v = _normalize_url(v)
            elif ioc.ioc_type == "hash":
                v = v.lower()
            elif ioc.ioc_type == "ip":
                v = _normalize_ip(v)
                if not v:
                    continue

            if not v:
                continue
            ioc.value = v
            ioc.tags = _merge_tags(ioc.tags, _infer_tags(ioc))
            ioc.description = _enrich_description(ioc.description, ioc)
            normalized.append(ioc)
        except Exception:
            logger.warning("skipping un-normalizable IOC (%s)", ioc.ioc_type, exc_info=True)
            continue

    return normalized


def boost_confidence_by_correlation(iocs: List[IOC]) -> List[IOC]:
    by_key_sources: Dict[tuple, set] = {}
    for i in iocs:
        key = (i.ioc_type, i.value)
        by_key_sources.setdefault(key, set()).add(i.source)

    for i in iocs:
        key = (i.ioc_type, i.value)
        source_count = len(by_key_sources.get(key, []))
        if source_count >= 2:
            i.confidence = min(100, i.confidence + 10)
            i.tags = _merge_tags(i.tags, ["multi-source-confirmed"])
        if source_count >= 3:
            i.confidence = min(100, i.confidence + 10)
            i.tags = _merge_tags(i.tags, ["high-correlation"])
    return iocs


def _normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if d.startswith("http://") or d.startswith("https://"):
        try:
            d = (urlparse(d).hostname or "").lower()
        except ValueError:      # malformed (e.g. unclosed IPv6 bracket) → keep raw
            return domain.strip().lower().rstrip(".")
    return d


def _normalize_url(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else f"http://{url}")
        scheme = (p.scheme or "http").lower()
        netloc = (p.netloc or "").lower()
        path = p.path or "/"
        query = f"?{p.query}" if p.query else ""
    except ValueError:          # malformed URL → return the raw value unchanged
        return url.strip()
    if not netloc and p.path:
        parts = p.path.split("/", 1)
        host = parts[0].lower()
        rest = "/" + parts[1] if len(parts) > 1 else "/"
        return f"{scheme}://{host}{rest}"
    return f"{scheme}://{netloc}{path}{query}"


def _normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ""


def _infer_tags(ioc: IOC):
    tags = []
    val = (ioc.value or "").lower()
    src = (ioc.source or "").lower()

    if src.startswith("rss"):
        tags.append("rss-ingested")
    if "darkweb" in src:
        tags.append("darkweb-osint")
    if "social" in src:
        tags.append("social-osint")
    if ioc.ioc_type == "url" and any(k in val for k in ["login", "verify", "secure", "wallet"]):
        tags.append("possible-phishing")
    return tags


def _merge_tags(existing, inferred):
    out, seen = [], set()
    for t in (existing or []) + (inferred or []):
        t = (t or "").strip()
        if not t:
            continue
        k = t.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(t)
    return out[:20]


def _enrich_description(desc, ioc: IOC):
    base = (desc or "").strip()
    extra = f"Normalized IOC from source: {ioc.source}."
    if not base:
        return extra
    if extra in base:
        return base
    return f"{base} | {extra}"
