import logging
import requests

logger = logging.getLogger(__name__)


def push_stix_to_opencti(opencti_url: str, api_key: str, bundle: dict) -> dict:
    if not opencti_url or not api_key:
        return {"ok": False, "error": "OPENCTI_URL or OPENCTI_API_KEY not configured"}

    url = opencti_url.rstrip("/") + "/api/bundles"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(url, json=bundle, headers=headers, timeout=60)
        response.raise_for_status()
        logger.info("STIX bundle pushed to OpenCTI successfully (HTTP %s)", response.status_code)
        return {"ok": True, "status_code": response.status_code, "detail": response.text[:500]}
    except requests.exceptions.ConnectionError as e:
        logger.error("OpenCTI connection failed: %s", e)
        return {"ok": False, "error": f"Connection failed: could not reach {opencti_url}"}
    except requests.exceptions.Timeout:
        logger.error("OpenCTI push timed out after 60s")
        return {"ok": False, "error": "Request timed out after 60s"}
    except requests.exceptions.HTTPError as e:
        logger.error("OpenCTI HTTP error: %s", e)
        return {"ok": False, "error": f"HTTP {response.status_code}: {response.text[:200]}"}
    except Exception as e:
        logger.exception("Unexpected error pushing to OpenCTI")
        return {"ok": False, "error": str(e)}
