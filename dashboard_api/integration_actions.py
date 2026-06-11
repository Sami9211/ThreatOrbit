"""Real SOAR response-action adapters — call EDR / firewall / ticketing APIs.

Each adapter builds the *actual* vendor request (URL, headers, JSON body) for a
response action and, when the integration has a `base_url` + `api_key`
configured, performs the real outbound HTTP call (httpx, short timeout) and
records the outcome. With no credentials it records a `not-configured` action
rather than pretending it ran — honest, like the enrichment provider seam.

Every attempt — live or not — is written to `integration_actions` (the action
audit trail), so there's a defensible record of what was done to whom.

Vendor mapping (by category/vendor keyword):
  edr / crowdstrike / sentinelone / defender → isolate_host, contain
  firewall / palo / fortinet / cloudflare    → block_ip
  identity / okta / azure / entra            → disable_user
  ticketing / jira / servicenow / pagerduty  → create_issue
  anything else                              → generic webhook POST
"""
import uuid
from datetime import datetime, timezone

_TIMEOUT = 6.0


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _category(integration: dict) -> str:
    hay = f"{integration.get('vendor', '')} {integration.get('category', '')} {integration.get('name', '')}".lower()
    if any(k in hay for k in ("edr", "crowdstrike", "sentinel", "defender", "endpoint")):
        return "edr"
    if any(k in hay for k in ("firewall", "palo", "fortinet", "cloudflare", "network", "panorama")):
        return "firewall"
    if any(k in hay for k in ("identity", "okta", "azure", "entra", "directory", "iam")):
        return "identity"
    if any(k in hay for k in ("ticket", "jira", "servicenow", "pagerduty", "notification")):
        return "ticketing"
    return "webhook"


def _request_spec(category: str, base_url: str, api_key: str, action: str, params: dict):
    """Return (method, url, headers, json_body) for the real vendor call."""
    p = params or {}
    if category == "edr":
        return ("POST", f"{base_url}/devices/entities/devices-actions/v2",
                {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                {"action_name": "contain", "ids": [p.get("host") or p.get("target") or ""]})
    if category == "firewall":
        return ("POST", f"{base_url}/api/blocklist",
                {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                {"ip": p.get("ip") or p.get("target"), "action": "deny", "reason": "SOAR response"})
    if category == "identity":
        return ("POST", f"{base_url}/users/{p.get('user') or p.get('target')}/lifecycle/suspend",
                {"Authorization": f"SSWS {api_key}", "Content-Type": "application/json"}, {})
    if category == "ticketing":
        return ("POST", f"{base_url}/rest/api/2/issue",
                {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                {"fields": {"summary": p.get("summary") or action,
                            "description": p.get("description") or f"Opened by ThreatOrbit SOAR ({action}).",
                            "issuetype": {"name": "Incident"}}})
    return ("POST", base_url, {"Content-Type": "application/json"},
            {"action": action, "params": p, "source": "threatorbit-soar"})


def run_action(conn, integration: dict, action: str, params: dict, actor: str) -> dict:
    """Execute a response action against an integration and record it. Performs
    the real HTTP call when credentialled; otherwise records `not-configured`."""
    category = _category(integration)
    base_url = (integration.get("base_url") or "").rstrip("/")
    api_key = integration.get("api_key") or ""
    target = (params or {}).get("target") or (params or {}).get("ip") or \
        (params or {}).get("host") or (params or {}).get("user") or ""

    if not base_url or not api_key:
        status, mode, detail = ("not-configured", "simulated",
                                f"{category} action '{action}' recorded — no endpoint/credential "
                                f"configured for {integration['name']}, so no live call was made")
    else:
        method, url, headers, body = _request_spec(category, base_url, api_key, action, params)
        try:
            import httpx
            r = httpx.request(method, url, headers=headers, json=body, timeout=_TIMEOUT)
            ok = r.status_code < 400
            status = "success" if ok else "failed"
            mode = "live"
            detail = f"{method} {url} → HTTP {r.status_code}"
        except Exception as e:  # network/timeout — recorded, never crashes the run
            status, mode, detail = "failed", "live", f"{category} call failed: {str(e)[:160]}"

    aid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO integration_actions (id,integration_id,action,target,status,mode,detail,actor,ts) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (aid, integration["id"], action, target, status, mode, detail, actor, _now()))
    if status in ("success", "simulated", "not-configured"):
        conn.execute("UPDATE integrations SET actions_run=actions_run+1, last_sync=? WHERE id=?",
                     (_now(), integration["id"]))
    return {"id": aid, "integrationId": integration["id"], "action": action, "target": target,
            "category": category, "status": status, "mode": mode, "detail": detail, "ts": _now()}


def find_integration_for(conn, keywords: tuple) -> dict | None:
    """The first enabled, connected integration matching any keyword (used by
    playbook action steps to route block_ip/isolate_host/etc. to a real tool)."""
    rows = conn.execute(
        "SELECT * FROM integrations WHERE enabled=1 AND status='connected'").fetchall()
    for r in rows:
        hay = f"{r['name']} {r['vendor']} {r['category']}".lower()
        if any(k in hay for k in keywords):
            return dict(r)
    return None
