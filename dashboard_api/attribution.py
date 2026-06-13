"""Evidence-weighted actor attribution.

Given observed activity - MITRE techniques, indicators, targeted sectors,
source country - score which tracked threat actor it most likely maps to, and
show *why* (transparent, weighted evidence) rather than a black-box label.

Weights reflect how discriminating each signal is:
  * IOC overlap is strongest (an indicator already attributed to the actor),
  * then shared malware, then technique (TTP) overlap, then sector/origin.
Scores are normalised 0-100 against the best-scoring actor so the ranking is
readable; confidence bands flag how thin the evidence is.
"""
import json

W_IOC = 30        # observed indicator already attributed to this actor
W_MALWARE = 16    # observed malware in the actor's toolset
W_TECHNIQUE = 8   # shared ATT&CK technique
W_SECTOR = 6      # targeted sector matches the actor's victimology
W_ORIGIN = 5      # source country matches the actor's origin


def _loads(v):
    if isinstance(v, list):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def _norm_tech(t: str) -> str:
    """Compare techniques at base id (T1059 == T1059.001)."""
    return str(t).split(".")[0].upper()


def score_actors(conn, *, techniques=None, iocs=None, malware=None,
                 sectors=None, origin=None, limit=10) -> list[dict]:
    """Rank tracked actors against the observed activity with weighted evidence."""
    obs_tech = {_norm_tech(t) for t in (techniques or []) if t}
    obs_iocs = {str(v).strip() for v in (iocs or []) if v}
    obs_mal = {str(m).lower() for m in (malware or []) if m}
    obs_sectors = {str(s).lower() for s in (sectors or []) if s}
    origin = (origin or "").lower()

    # Which observed indicators are attributed to whom (strongest signal).
    ioc_actor: dict[str, list] = {}
    if obs_iocs:
        ph = ",".join("?" * len(obs_iocs))
        for r in conn.execute(
                f"SELECT value, actor FROM iocs WHERE value IN ({ph}) AND actor != ''",
                list(obs_iocs)).fetchall():
            ioc_actor.setdefault(r["actor"], []).append(r["value"])

    rows = conn.execute(
        "SELECT name, type, origin, threat_level, sectors, ttps, malware FROM threat_actors").fetchall()
    scored = []
    for a in rows:
        evidence = []
        pts = 0
        # IOC overlap
        for v in ioc_actor.get(a["name"], []):
            pts += W_IOC
            evidence.append({"type": "ioc", "weight": W_IOC, "detail": f"indicator {v} attributed to {a['name']}"})
        # technique overlap
        a_tech = {_norm_tech(t) for t in _loads(a["ttps"])}
        for t in sorted(obs_tech & a_tech):
            pts += W_TECHNIQUE
            evidence.append({"type": "technique", "weight": W_TECHNIQUE, "detail": f"shared technique {t}"})
        # malware overlap
        a_mal = {m.lower() for m in _loads(a["malware"])}
        for m in sorted(obs_mal & a_mal):
            pts += W_MALWARE
            evidence.append({"type": "malware", "weight": W_MALWARE, "detail": f"uses {m}"})
        # sector match
        a_sectors = {s.lower() for s in _loads(a["sectors"])}
        for s in sorted(obs_sectors & a_sectors):
            pts += W_SECTOR
            evidence.append({"type": "sector", "weight": W_SECTOR, "detail": f"targets {s} sector"})
        # origin match
        if origin and a["origin"] and origin in a["origin"].lower():
            pts += W_ORIGIN
            evidence.append({"type": "origin", "weight": W_ORIGIN, "detail": f"origin {a['origin']}"})
        if pts > 0:
            scored.append({"actor": a["name"], "type": a["type"], "origin": a["origin"],
                           "threatLevel": a["threat_level"], "raw": pts, "evidence": evidence})

    scored.sort(key=lambda x: -x["raw"])
    top = scored[0]["raw"] if scored else 0
    for s in scored:
        s["score"] = round(s["raw"] / top * 100) if top else 0
        n = len(s["evidence"])
        kinds = {e["type"] for e in s["evidence"]}
        # confidence reflects corroboration across independent signal types
        s["confidence"] = ("high" if (s["raw"] >= W_IOC or len(kinds) >= 3)
                           else "medium" if (n >= 2 or len(kinds) >= 2) else "low")
    return scored[:limit]


def attribute_case(conn, case_id: str) -> dict | None:
    """Attribute a SOAR case from its linked alerts' techniques + its entities'
    indicators. Returns None when the case does not exist."""
    from dashboard_api.db import row_to_dict
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        return None
    case = row_to_dict(row)
    values = [e.get("value") for e in (case.get("entities") or [])
              if isinstance(e, dict) and e.get("value")]
    techniques, iocs = set(), set()
    if values:
        ph = ",".join("?" * len(values))
        for a in conn.execute(
                f"SELECT mitre_tech_id FROM alerts WHERE src_ip IN ({ph}) OR hostname IN ({ph}) "
                f"OR username IN ({ph})", values * 3).fetchall():
            if a["mitre_tech_id"]:
                techniques.add(a["mitre_tech_id"])
        for r in conn.execute(f"SELECT value FROM iocs WHERE value IN ({ph})", values).fetchall():
            iocs.add(r["value"])
    ranked = score_actors(conn, techniques=list(techniques), iocs=list(iocs))
    return {"caseId": case_id, "observed": {"techniques": sorted(techniques),
            "indicators": sorted(iocs)}, "candidates": ranked}
