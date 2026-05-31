from datetime import datetime, timezone
from typing import List
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from threat_api.models import IOC, FetchResult
from threat_api.fetchers.rss import _fetch_feed, _read_sources

DARKWEB_SOURCES_FILE = "darkweb_sources.txt"


def get_configured_darkweb_sources(path: str = DARKWEB_SOURCES_FILE) -> List[str]:
    return _read_sources(path)


def fetch_darkweb_osint_iocs() -> FetchResult:
    iocs: List[IOC] = []
    errors: List[str] = []
    sources = _read_sources(DARKWEB_SOURCES_FILE)

    if not sources:
        return FetchResult(
            source="DarkWeb OSINT",
            ioc_count=0,
            iocs=[],
            fetched_at=datetime.now(timezone.utc),
            errors=["No darkweb OSINT sources configured in darkweb_sources.txt"],
        )

    for src in sources:
        fiocs, ferrs = _fetch_feed(src, source_prefix="DarkWeb OSINT")
        for i in fiocs:
            low_desc = (i.description or "").lower()
            if any(k in low_desc for k in ["leak", "dump", "breach", "ransom", "stealer"]):
                i.confidence = min(100, i.confidence + 10)
                i.tags = (i.tags or []) + ["leak-mention"]
            i.threat_type = "malicious-activity"
        iocs.extend(fiocs)
        errors.extend(ferrs)

    return FetchResult(
        source="DarkWeb OSINT",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors,
    )
