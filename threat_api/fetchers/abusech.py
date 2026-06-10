from datetime import datetime, timezone
from typing import List
import requests

from threat_api.config import ABUSECH_URLHAUS_URL, ABUSECH_FEODO_URL, ABUSECH_AUTH_KEY
from threat_api.models import IOC, FetchResult


def fetch_abusech_iocs() -> FetchResult:
    iocs: List[IOC] = []
    errors: List[str] = []
    # abuse.ch query APIs now require an Auth-Key header (free at auth.abuse.ch).
    auth_headers = {"Auth-Key": ABUSECH_AUTH_KEY} if ABUSECH_AUTH_KEY else {}

    # URLHaus (URLs) — needs the Auth-Key; skipped cleanly if no key is set.
    try:
        if not ABUSECH_AUTH_KEY:
            raise RuntimeError("no ABUSECH_AUTH_KEY set (free at auth.abuse.ch) — skipping URLHaus")
        r = requests.post(ABUSECH_URLHAUS_URL, headers=auth_headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        for row in data.get("urls", [])[:500]:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            iocs.append(IOC(
                ioc_type="url",
                value=url,
                source="abuse.ch URLHaus",
                threat_type="malicious-activity",
                tags=["abusech", "urlhaus"],
                first_seen=_parse_time(row.get("date_added")),
                description=f"URL status={row.get('url_status', 'unknown')}",
                confidence=80
            ))
    except Exception as e:
        errors.append(f"URLHaus fetch failed: {e}")

    # Feodo IP blocklist — downloadable JSON, works WITHOUT a key (real data
    # out of the box). The Auth-Key is sent too when available.
    try:
        r = requests.get(ABUSECH_FEODO_URL, headers=auth_headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        for row in data[:1000]:
            ip = (row.get("ip_address") or "").strip()
            if not ip:
                continue
            iocs.append(IOC(
                ioc_type="ip",
                value=ip,
                source="abuse.ch Feodo",
                threat_type="malicious-activity",
                tags=["abusech", "feodo"],
                first_seen=_parse_time(row.get("first_seen_utc")),
                description=f"Feodo malware family={row.get('malware', 'unknown')}",
                confidence=85
            ))
    except Exception as e:
        errors.append(f"Feodo fetch failed: {e}")

    return FetchResult(
        source="abuse.ch",
        ioc_count=len(iocs),
        iocs=iocs,
        fetched_at=datetime.now(timezone.utc),
        errors=errors
    )


def _parse_time(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None
