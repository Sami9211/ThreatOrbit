from datetime import datetime, timezone
from typing import List, Tuple
import re
import requests
import xml.etree.ElementTree as ET
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from threat_api.models import IOC, FetchResult

RSS_FEEDS_FILE = "rss_feeds.txt"


def get_configured_rss_feeds(path: str = RSS_FEEDS_FILE) -> List[str]:
    return _read_sources(path)


def fetch_rss_iocs() -> FetchResult:
    iocs: List[IOC] = []
    errors: List[str] = []
    feeds = _read_sources(RSS_FEEDS_FILE)

    if not feeds:
        return FetchResult(
            source="RSS",
            ioc_count=0,
            iocs=[],
            fetched_at=datetime.now(timezone.utc),
            errors=["No RSS feeds configured in rss_feeds.txt"],
        )

    for feed_url in feeds:
        fiocs, ferrs = _fetch_feed(feed_url, source_prefix="RSS")
        iocs.extend(fiocs)
        errors.extend(ferrs)

    return FetchResult(
        source="RSS",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors,
    )


def _fetch_feed(feed_url: str, source_prefix: str):
    iocs: List[IOC] = []
    errs: List[str] = []
    try:
        text = _get_capped(feed_url)
        root = ET.fromstring(text)
    except Exception as e:
        return [], [f"{source_prefix} fetch failed {feed_url}: {str(e)}"]

    items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    for item in items:
        title = _node_text(item, "title")
        link = _item_link(item)
        desc = _node_text(item, "description") or _node_text(item, "{http://www.w3.org/2005/Atom}summary")
        pub_date = _node_text(item, "pubDate") or _node_text(item, "{http://www.w3.org/2005/Atom}updated")
        text_blob = f"{title} {link} {desc}"

        for ioc_type, value in _extract_iocs(text_blob):
            iocs.append(IOC(
                ioc_type=ioc_type,
                value=value,
                source=f"{source_prefix}: {feed_url}",
                threat_type="malicious-activity",
                tags=[source_prefix.lower(), "threat-feed"],
                first_seen=_parse_date(pub_date),
                description=f"{title[:180]} | {link[:180]}",
                confidence=55 if source_prefix == "RSS" else 50,
            ))
    return iocs, errs


# Cap the RSS/Atom body we buffer + parse. A hostile or compromised feed could
# otherwise return a multi-GB body that `resp.text` / `ET.fromstring` load fully
# into memory (OOM). 32 MB is far beyond any legitimate feed.
_MAX_FEED_BYTES = 32 * 1024 * 1024


def _get_capped(feed_url: str) -> str:
    """GET a feed with a streamed, size-bounded read; raises if it exceeds the cap."""
    with requests.get(feed_url, timeout=30, stream=True) as resp:
        resp.raise_for_status()
        total = 0
        chunks = []
        for chunk in resp.iter_content(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > _MAX_FEED_BYTES:
                raise ValueError(f"feed body exceeds {_MAX_FEED_BYTES} bytes")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _read_sources(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out


def _node_text(item, tag):
    n = item.find(tag)
    return (n.text or "").strip() if (n is not None and n.text) else ""


def _item_link(item):
    link_text = _node_text(item, "link")
    if link_text:
        return link_text
    atom_link = item.find("{http://www.w3.org/2005/Atom}link")
    if atom_link is not None:
        return (atom_link.attrib.get("href", "") or "").strip()
    return ""


# Bound the text a single item's IOC extraction runs over. RSS/Atom bodies are
# third-party and attacker-influenceable (a compromised or hostile feed), and the
# regexes below have no match timeout. Without a cap, a crafted blob (e.g. a long
# "a.a.a.a…" run) makes the domain regex backtrack for many seconds — a ReDoS that
# stalls the OSINT refresh thread. A real item's title+link+description is tiny;
# this cap is generous for legitimate content and hard-bounds the pathological case.
_MAX_EXTRACT_CHARS = 20000


def _extract_iocs(text: str) -> List[Tuple[str, str]]:
    text = (text or "")[:_MAX_EXTRACT_CHARS]
    out = []
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_pattern = r"https?://[^\s\"'<>]+"
    # Possessive outer quantifier (Python 3.11+): once a domain's label run is
    # consumed it isn't given back, which removes the catastrophic-backtracking
    # path while matching real domains identically.
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)++[a-zA-Z]{2,}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    out += [("url", x.strip(".,);]}>\"'")) for x in re.findall(url_pattern, text)]
    out += [("ip", x) for x in re.findall(ip_pattern, text)]
    out += [("hash", x.lower()) for x in re.findall(sha256_pattern, text)]
    out += [("domain", x.lower().strip(".,);]}>\"'")) for x in re.findall(domain_pattern, text)]

    dedup, seen = [], set()
    for t, v in out:
        if t == "domain" and _looks_like_ip(v):
            continue
        key = (t, v)
        if key not in seen:
            seen.add(key)
            dedup.append((t, v))
    return dedup


def _looks_like_ip(value: str) -> bool:
    try:
        parts = value.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _parse_date(date_str: str):
    if not date_str:
        return None
    fmts = ["%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"]
    for fmt in fmts:
        try:
            return datetime.strptime(date_str, fmt).astimezone(timezone.utc)
        except Exception:
            continue
    return None
