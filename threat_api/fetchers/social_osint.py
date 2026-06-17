"""'Social OSINT' source — an RSS/Atom feed reader, NOT a social-media API client.

It reads whatever feeds are listed in `social_sources.txt` via the shared RSS
fetcher and tags the resulting indicators as community-sourced. There is no
social-platform collection here: treat it as a pluggable slot for security-
community RSS feeds. It is **empty by default** until you add sources — see the
README's "Project status" section for the honest framing.
"""
from datetime import datetime, timezone
from typing import List
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from threat_api.models import IOC, FetchResult
from threat_api.fetchers.rss import _fetch_feed, _read_sources

SOCIAL_SOURCES_FILE = "social_sources.txt"


def get_configured_social_sources(path: str = SOCIAL_SOURCES_FILE) -> List[str]:
    return _read_sources(path)


def fetch_social_osint_iocs() -> FetchResult:
    iocs: List[IOC] = []
    errors: List[str] = []
    sources = _read_sources(SOCIAL_SOURCES_FILE)

    if not sources:
        return FetchResult(
            source="Social OSINT",
            ioc_count=0,
            iocs=[],
            fetched_at=datetime.now(timezone.utc),
            errors=["No social OSINT sources configured in social_sources.txt"],
        )

    for src in sources:
        fiocs, ferrs = _fetch_feed(src, source_prefix="Social OSINT")
        for i in fiocs:
            i.threat_type = "malicious-activity"
            i.tags = (i.tags or []) + ["community-sourced"]
            i.confidence = min(100, i.confidence + 5)
        iocs.extend(fiocs)
        errors.extend(ferrs)

    return FetchResult(
        source="Social OSINT",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors,
    )
