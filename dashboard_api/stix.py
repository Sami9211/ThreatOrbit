"""STIX 2.1 serialization - turn ThreatOrbit's intel into standards content.

Maps the live stores onto STIX 2.1 SDOs so other platforms (OpenCTI, MISP,
Anomali, a SIEM's TAXII client) can consume ThreatOrbit as a real CTI source:

  IOC (ip/domain/url/hash/email)  → `indicator` with a proper STIX pattern
  IOC (cve)                       → `vulnerability`
  threat actor                    → `threat-actor`
  IOC attributed to an actor      → `relationship` (indicator `indicates` actor)

Object ids are deterministic (uuid5 over the value), so re-exporting the same
indicator yields the same STIX id - clients can de-duplicate across pulls.
"""
import json
import re
import uuid
from datetime import datetime, timezone

# A stable namespace for deterministic STIX ids (uuidv5).
_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

_INDICATOR_TYPE = {  # ThreatOrbit threat_type-ish → STIX indicator_types vocab
    "c2": "command-and-control", "command-and-control": "command-and-control",
    "malware": "malicious-activity", "phishing": "anomalous-activity",
    "exfil-destination": "exfiltration", "brute-force-source": "anomalous-activity",
    "web-attack": "anomalous-activity", "soar-blocked": "malicious-activity",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ts(value, fallback=None) -> str:
    if not value:
        return fallback or _now()
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (ValueError, TypeError):
        return fallback or _now()


def _det_id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, f'{kind}:{seed}')}"


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


_HASH_BY_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def stix_pattern(ioc_type: str, value: str) -> str | None:
    """STIX 2.1 pattern for an indicator value, or None for non-indicator types."""
    v = _escape(value)
    t = (ioc_type or "").lower()
    if t == "ip":
        kind = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{kind}:value = '{v}']"
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "url":
        return f"[url:value = '{v}']"
    if t == "email":
        return f"[email-addr:value = '{v}']"
    if t == "hash":
        algo = _HASH_BY_LEN.get(len(re.sub(r"[^0-9a-fA-F]", "", value)), "SHA-256")
        return f"[file:hashes.'{algo}' = '{v}']"
    return None


_TA_TYPE = {  # ThreatOrbit actor type → STIX threat-actor-type vocab
    "nation-state": "nation-state", "cybercrime": "crime-syndicate",
    "hacktivist": "hacktivist", "insider": "insider-threat",
}
_SOPH = {1: "minimal", 2: "intermediate", 3: "advanced", 4: "expert", 5: "strategic"}


def _loads(v):
    if isinstance(v, list):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def ioc_to_stix(ioc: dict) -> dict:
    """An IOC row → an `indicator` (or `vulnerability` for CVEs)."""
    value = ioc["value"]
    created = _ts(ioc.get("first_seen"))
    modified = _ts(ioc.get("last_seen"), created)
    if (ioc.get("type") or "").lower() == "cve":
        return {
            "type": "vulnerability", "spec_version": "2.1",
            "id": _det_id("vulnerability", value),
            "created": created, "modified": modified,
            "name": value,
            "description": ioc.get("threat_type") or f"Vulnerability {value}",
            "external_references": [{"source_name": "cve", "external_id": value}],
        }
    pattern = stix_pattern(ioc.get("type"), value) or f"[x-threatorbit:value = '{_escape(value)}']"
    itype = _INDICATOR_TYPE.get((ioc.get("threat_type") or "").lower(), "malicious-activity")
    obj = {
        "type": "indicator", "spec_version": "2.1",
        "id": _det_id("indicator", value),
        "created": created, "modified": modified,
        "name": f"{ioc.get('threat_type') or 'Indicator'}: {value}",
        "description": (f"{ioc.get('threat_type') or 'Malicious indicator'} observed by ThreatOrbit"
                        + (f", attributed to {ioc['actor']}" if ioc.get("actor") else "") + "."),
        "indicator_types": [itype],
        "pattern": pattern, "pattern_type": "stix", "pattern_version": "2.1",
        "valid_from": created,
        "confidence": int(ioc.get("confidence") or 0),
        "labels": _loads(ioc.get("tags")) or [ioc.get("severity") or "unknown"],
    }
    if ioc.get("status") == "known-good":
        obj["indicator_types"] = ["benign"]
    return obj


def actor_to_stix(actor: dict) -> dict:
    name = actor["name"]
    ta_type = _TA_TYPE.get((actor.get("type") or "").lower().replace(" ", "-"), "unknown")
    obj = {
        "type": "threat-actor", "spec_version": "2.1",
        "id": _det_id("threat-actor", name),
        "created": _ts(actor.get("first_seen")),
        "modified": _ts(actor.get("last_seen"), _ts(actor.get("first_seen"))),
        "name": name,
        "description": f"{actor.get('type') or 'Threat actor'} tracked by ThreatOrbit"
                       + (f" (origin {actor['origin']})" if actor.get("origin") else "") + ".",
        "threat_actor_types": [ta_type],
        "aliases": _loads(actor.get("aliases")),
        "sophistication": _SOPH.get(actor.get("sophistication") or 3, "intermediate"),
        "goals": _loads(actor.get("motivations")),
    }
    return {k: v for k, v in obj.items() if v not in (None, [], "")}


def relationship(src_id: str, target_id: str, rel: str = "indicates") -> dict:
    return {
        "type": "relationship", "spec_version": "2.1",
        "id": _det_id("relationship", f"{src_id}|{rel}|{target_id}"),
        "created": _now(), "modified": _now(),
        "relationship_type": rel, "source_ref": src_id, "target_ref": target_id,
    }


def build_objects(iocs: list[dict], actors: list[dict], *, with_relationships=True) -> list[dict]:
    """Serialize iocs + actors (+ indicator→actor relationships) into STIX SDOs."""
    actor_id = {a["name"]: _det_id("threat-actor", a["name"]) for a in actors}
    objects: list[dict] = [actor_to_stix(a) for a in actors]
    for ioc in iocs:
        sdo = ioc_to_stix(ioc)
        objects.append(sdo)
        if with_relationships and ioc.get("actor") and ioc["actor"] in actor_id and sdo["type"] == "indicator":
            objects.append(relationship(sdo["id"], actor_id[ioc["actor"]]))
    return objects


def bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ── Inbound: parse STIX → IOCs (TAXII write / push ingest) ────────────────────────

_PATTERN_RE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file:hashes[^=]*)"
    r"[^=]*=\s*'([^']+)'", re.IGNORECASE)


def parse_indicator_pattern(pattern: str) -> dict | None:
    """Extract {type, value} from a STIX 2.1 indicator pattern, or None."""
    m = _PATTERN_RE.search(pattern or "")
    if not m:
        return None
    kind, value = m.group(1).lower(), m.group(2)
    t = ("ip" if "ipv" in kind else "domain" if "domain" in kind
         else "url" if "url" in kind else "email" if "email" in kind
         else "hash" if "hash" in kind or "file" in kind else None)
    if not t:
        return None
    return {"type": t, "value": value}


def objects_to_iocs(objects: list[dict]) -> list[dict]:
    """Map inbound STIX `indicator` SDOs to importable IOC records."""
    out = []
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        parsed = parse_indicator_pattern(obj.get("pattern", ""))
        if not parsed:
            continue
        labels = obj.get("labels") or obj.get("indicator_types") or []
        out.append({
            **parsed,
            "threat_type": (obj.get("name") or (labels[0] if labels else "stix-indicator")),
            "confidence": int(obj.get("confidence") or 60),
            "severity": "high" if int(obj.get("confidence") or 60) >= 70 else "medium",
            "tags": [str(l) for l in labels],
        })
    return out
