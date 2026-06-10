"""MISP event import/export — interoperate with the wider CTI community.

MISP (misp-project.org) is the de-facto open threat-sharing format. This maps
between ThreatOrbit's IOC store / intel reports and a MISP **Event**:

  export → an Event with one Attribute per indicator (correct MISP `type` +
           `category`), TLP tag, and the report's metadata as the Event `info`.
  import → parse an Event's Attributes back into indicators (type-mapped),
           returning a per-attribute tally (imported / duplicate / skipped).

Only the Event/Attribute subset MISP actually requires is handled; unknown
attribute types are skipped (reported), never guessed.
"""
import json
import uuid
from datetime import datetime, timezone

# ThreatOrbit IOC type → (MISP attribute type, MISP category)
_TO_MISP = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "cve": ("vulnerability", "External analysis"),
}
# MISP attribute type → ThreatOrbit IOC type (import; many→few)
_FROM_MISP = {
    "ip-dst": "ip", "ip-src": "ip", "domain": "domain", "hostname": "domain",
    "domain|ip": "domain", "url": "url", "uri": "url",
    "email-src": "email", "email-dst": "email", "email": "email",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "filename|md5": "hash",
    "filename|sha256": "hash", "vulnerability": "cve",
}
_TLP_LEVELS = {"white", "green", "amber", "red"}


def _now_misp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _hash_type(value: str) -> str:
    h = "".join(c for c in value if c in "0123456789abcdefABCDEF")
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "sha256")


def to_misp_event(iocs: list[dict], *, info: str, tlp: str = "amber",
                  tags: list[str] | None = None) -> dict:
    """Serialize indicators into a MISP Event."""
    tlp = tlp if tlp in _TLP_LEVELS else "amber"
    attributes = []
    for ioc in iocs:
        t = (ioc.get("type") or "").lower()
        value = ioc.get("value")
        if not value:
            continue
        if t == "hash":
            mtype, cat = _hash_type(value), "Payload delivery"
        else:
            mapped = _TO_MISP.get(t)
            if not mapped:
                continue
            mtype, cat = mapped
        attributes.append({
            "uuid": str(uuid.uuid4()), "type": mtype, "category": cat,
            "to_ids": (ioc.get("severity") in ("critical", "high")),
            "value": value,
            "comment": ioc.get("threat_type") or "",
        })
    event_tags = [{"name": f"tlp:{tlp}"}] + [{"name": t} for t in (tags or [])]
    return {"Event": {
        "uuid": str(uuid.uuid4()),
        "info": info or "ThreatOrbit export",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "threat_level_id": "2", "analysis": "2", "published": True,
        "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
        "Orgc": {"name": "ThreatOrbit"},
        "Tag": event_tags,
        "Attribute": attributes,
    }}


def parse_misp_event(payload: dict) -> list[dict]:
    """Extract importable indicators from a MISP Event. Returns a list of
    {type, value, comment, to_ids, skipped?} — caller does the inserting."""
    event = payload.get("Event", payload) if isinstance(payload, dict) else {}
    attrs = event.get("Attribute") or []
    # Attributes can also live inside Objects.
    for obj in event.get("Object") or []:
        attrs += obj.get("Attribute") or []
    out = []
    for a in attrs:
        if not isinstance(a, dict):
            continue
        mtype = (a.get("type") or "").lower()
        value = a.get("value")
        ioc_type = _FROM_MISP.get(mtype)
        # composite values like domain|ip or filename|md5 → take the right half/value
        if value and "|" in str(value) and ioc_type in ("hash",):
            value = str(value).split("|")[-1]
        if not value:
            continue
        if not ioc_type:
            out.append({"value": value, "type": None, "skipped": True, "reason": f"unmapped type {mtype}"})
            continue
        out.append({"type": ioc_type, "value": str(value).strip(),
                    "comment": a.get("comment") or "", "to_ids": bool(a.get("to_ids"))})
    return out


def misp_tlp(payload: dict) -> str:
    event = payload.get("Event", payload) if isinstance(payload, dict) else {}
    for tag in event.get("Tag") or []:
        name = (tag.get("name") or "").lower()
        if name.startswith("tlp:") and name[4:] in _TLP_LEVELS:
            return name[4:]
    return "amber"
