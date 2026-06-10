"""TAXII 2.1 server — let external tools pull ThreatOrbit's intel as STIX.

A read-only TAXII 2.1 service (discovery → api-root → collections → objects)
exposing two collections, `indicators` and `threat-actors`, serialized as
STIX 2.1. Authenticated with either a dashboard JWT or a platform API key
(`Authorization: Bearer to_rk_live_…`), so a SIEM/CTI client can subscribe.

This makes ThreatOrbit a genuine CTI hub others can consume, not just a UI.
"""
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dashboard_api.auth import decode_token
from dashboard_api.db import get_conn, rows_to_dicts
from dashboard_api import stix

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"

_bearer = HTTPBearer(auto_error=False)

# id → (title, description, stix types served)
COLLECTIONS = {
    "indicators": ("Indicators", "Malicious indicators (IPs, domains, URLs, hashes, CVEs) as STIX 2.1.",
                   {"indicator", "vulnerability", "relationship"}),
    "threat-actors": ("Threat Actors", "Tracked threat actors as STIX 2.1 threat-actor objects.",
                      {"threat-actor"}),
}


def taxii_principal(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    """Authenticate a TAXII client via dashboard JWT or a platform API key."""
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    token = creds.credentials
    # 1) dashboard JWT
    try:
        payload = decode_token(token)
        return {"kind": "user", "id": payload.get("sub"), "email": payload.get("email")}
    except Exception:
        pass
    # 2) platform API key (stored as sha256(secret))
    digest = hashlib.sha256(token.encode()).hexdigest()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, name, scope FROM api_keys WHERE secret_hash=? AND revoked=0",
            (digest,)).fetchone()
        if row:
            conn.execute("UPDATE api_keys SET last_used=datetime('now') WHERE id=?", (row["id"],))
            conn.commit()
            return {"kind": "api_key", "id": row["id"], "scope": row["scope"]}
    raise HTTPException(status_code=401, detail="Invalid credentials",
                        headers={"WWW-Authenticate": "Bearer"})


router = APIRouter(prefix="/taxii2", tags=["taxii"], dependencies=[Depends(taxii_principal)])


def _taxii(content: dict) -> JSONResponse:
    return JSONResponse(content=content, media_type=TAXII_MEDIA)


def _objects_for(collection_id: str) -> list[dict]:
    served = COLLECTIONS[collection_id][2]
    with get_conn() as conn:
        actors = rows_to_dicts(conn.execute("SELECT * FROM threat_actors").fetchall())
        if collection_id == "threat-actors":
            return [stix.actor_to_stix(a) for a in actors]
        # indicators collection: indicators + vulnerabilities + relationships to
        # actors (the threat-actor SDOs themselves live in their own collection).
        iocs = rows_to_dicts(conn.execute(
            "SELECT * FROM iocs WHERE status != 'known-good'").fetchall())
    return [o for o in stix.build_objects(iocs, actors) if o["type"] in served]


@router.get("/")
def discovery(request: Request):
    """TAXII discovery — advertises the API root."""
    base = str(request.base_url).rstrip("/")
    return _taxii({
        "title": "ThreatOrbit TAXII Server",
        "description": "STIX 2.1 threat intelligence published by ThreatOrbit.",
        "contact": "soc@threatorbit.space",
        "default": f"{base}/taxii2/api/",
        "api_roots": [f"{base}/taxii2/api/"],
    })


@router.get("/api/")
def api_root():
    """API root metadata."""
    return _taxii({
        "title": "ThreatOrbit CTI",
        "description": "Indicators and threat actors as STIX 2.1.",
        "versions": [TAXII_MEDIA],
        "max_content_length": 10485760,
    })


@router.get("/api/collections/")
def list_collections():
    cols = [{"id": cid, "title": title, "description": desc,
             "can_read": True, "can_write": False, "media_types": [STIX_MEDIA]}
            for cid, (title, desc, _types) in COLLECTIONS.items()]
    return _taxii({"collections": cols})


@router.get("/api/collections/{collection_id}/")
def get_collection(collection_id: str):
    if collection_id not in COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    title, desc, _ = COLLECTIONS[collection_id]
    return _taxii({"id": collection_id, "title": title, "description": desc,
                   "can_read": True, "can_write": False, "media_types": [STIX_MEDIA]})


@router.get("/api/collections/{collection_id}/objects/")
def get_objects(collection_id: str,
                type: str | None = Query(None, description="filter by STIX type"),
                added_after: str | None = None,
                limit: int = Query(100, le=1000)):
    """The collection's STIX objects in a TAXII envelope (filterable, paginated)."""
    if collection_id not in COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    objects = _objects_for(collection_id)
    if type:
        wanted = {t.strip() for t in type.split(",")}
        objects = [o for o in objects if o["type"] in wanted]
    if added_after:
        objects = [o for o in objects if (o.get("modified") or o.get("created") or "") > added_after]
    objects.sort(key=lambda o: o.get("modified") or o.get("created") or "")
    more = len(objects) > limit
    page = objects[:limit]
    body = {"objects": page, "more": more}
    if page:
        body["next"] = page[-1].get("modified") or page[-1].get("created")
    return _taxii(body)
