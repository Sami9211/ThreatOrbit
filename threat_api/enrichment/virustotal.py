import threading
import time
import requests
from datetime import datetime, timezone
from typing import List

from threat_api.config import VIRUSTOTAL_API_KEY, VT_RATE_LIMIT_SECONDS
from threat_api.models import IOC, EnrichedIOC

_session: requests.Session | None = None
_session_lock = threading.Lock()


def _get_session() -> requests.Session:
    global _session
    with _session_lock:
        if _session is None:
            _session = requests.Session()
            _session.headers.update({"x-apikey": VIRUSTOTAL_API_KEY})
            adapter = requests.adapters.HTTPAdapter(
                max_retries=requests.adapters.Retry(
                    total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503]
                )
            )
            _session.mount("https://", adapter)
    return _session


def enrich_iocs(iocs: List[IOC], max_enrichments: int = 50) -> List[EnrichedIOC]:
    out: List[EnrichedIOC] = []

    if not VIRUSTOTAL_API_KEY:
        for i in iocs:
            out.append(EnrichedIOC(**i.model_dump(), enrichment_status="skipped",
                                   enrichment_error="VT key not configured"))
        return out

    enriched_count = 0
    for i in iocs:
        if enriched_count >= max_enrichments:
            out.append(EnrichedIOC(**i.model_dump(), enrichment_status="skipped",
                                   enrichment_error="max enrichments reached"))
            continue
        try:
            ei = _enrich_single(i)
            out.append(ei)
            enriched_count += 1
            time.sleep(VT_RATE_LIMIT_SECONDS)
        except Exception as e:
            out.append(EnrichedIOC(**i.model_dump(), enrichment_status="error",
                                   enrichment_error=str(e)))

    return out


def _enrich_single(ioc: IOC) -> EnrichedIOC:
    endpoint = _vt_endpoint(ioc)
    if not endpoint:
        return EnrichedIOC(**ioc.model_dump(), enrichment_status="skipped",
                           enrichment_error="unsupported IOC type")

    r = _get_session().get(endpoint, timeout=30)
    if r.status_code == 404:
        return EnrichedIOC(**ioc.model_dump(), enrichment_status="not_found")
    r.raise_for_status()

    data = r.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = int(stats.get("malicious", 0))
    harmless = int(stats.get("harmless", 0))
    suspicious = int(stats.get("suspicious", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + harmless + suspicious + undetected

    last_ts = attrs.get("last_analysis_date")
    vt_last_analysis = (
        datetime.fromtimestamp(last_ts, tz=timezone.utc) if last_ts else None
    )

    return EnrichedIOC(
        **ioc.model_dump(),
        vt_malicious_count=malicious,
        vt_total_engines=total if total > 0 else None,
        vt_permalink=f"https://www.virustotal.com/gui/{_gui_path(ioc)}",
        vt_last_analysis=vt_last_analysis,
        enrichment_status="ok",
    )


def _vt_endpoint(ioc: IOC) -> str | None:
    base = "https://www.virustotal.com/api/v3"
    if ioc.ioc_type == "ip":
        return f"{base}/ip_addresses/{ioc.value}"
    if ioc.ioc_type == "domain":
        return f"{base}/domains/{ioc.value}"
    if ioc.ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
        return f"{base}/urls/{url_id}"
    if ioc.ioc_type == "hash":
        return f"{base}/files/{ioc.value}"
    return None


def _gui_path(ioc: IOC) -> str:
    if ioc.ioc_type == "ip":
        return f"ip-address/{ioc.value}"
    if ioc.ioc_type == "domain":
        return f"domain/{ioc.value}"
    if ioc.ioc_type == "url":
        return f"url/{ioc.value}"
    if ioc.ioc_type == "hash":
        return f"file/{ioc.value}"
    return ""
