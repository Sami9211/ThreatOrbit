"""Detection-content update channel.

A SIEM has to receive NEW detections without a code release. Rules ship as
versioned JSON **content packs** in `content/rules/*.json`; applying a pack
upserts its rules into `detection_rules` (idempotent, by id) and records the
applied version in `settings`. So updating detections = drop in a newer pack +
`POST /siem/content/apply` - no redeploy. The built-in 15 rules stay
code-shipped (engine.py); packs add to or refresh the library.

An operator's enable/disable choice and a rule's hit stats are preserved across
re-applies; only the content fields (definition, severity, MITRE, …) are
refreshed. Pack rules fire on real ingested logs the same way the built-ins do.

Pack format:
    {"name": "...", "version": 2, "description": "...",
     "rules": [{"id","name","category","severity","mitre_tactic",
                "mitre_tactic_id","mitre_tech_id","mitre_tech","definition", ...}]}
"""
import json
from datetime import datetime, timezone
from pathlib import Path

PACK_DIR = Path(__file__).resolve().parent.parent / "content" / "rules"
_REQUIRED = ("id", "name", "category", "severity", "mitre_tactic", "mitre_tactic_id",
             "mitre_tech_id", "mitre_tech", "definition")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_rule(r: dict, pack: str) -> None:
    for k in _REQUIRED:
        if not r.get(k):
            raise ValueError(f"pack '{pack}': rule {r.get('id', '?')} missing '{k}'")
    if r["severity"] not in _SEVERITIES:
        raise ValueError(f"pack '{pack}': rule {r['id']} bad severity {r['severity']!r}")
    if not (isinstance(r["definition"], dict) and r["definition"].get("conditions")):
        raise ValueError(f"pack '{pack}': rule {r['id']} has no conditions")


def load_packs(pack_dir=None) -> list:
    """Parse + validate every pack in the content dir. Raises on a malformed pack
    (better to refuse the whole update than apply a half-valid one)."""
    d = Path(pack_dir or PACK_DIR)
    packs = []
    if not d.exists():
        return packs
    for f in sorted(d.glob("*.json")):
        data = json.loads(f.read_text())
        name = data.get("name") or f.stem
        rules = data.get("rules") or []
        for r in rules:
            _validate_rule(r, name)
        ids = [r["id"] for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError(f"pack '{name}': duplicate rule ids within the pack")
        packs.append({"name": name, "version": int(data.get("version") or 1),
                      "description": data.get("description", ""),
                      "rules": rules, "file": f.name})
    return packs


def _applied_versions(conn) -> dict:
    out = {}
    for row in conn.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'content_pack:%'").fetchall():
        try:
            out[row["key"].split(":", 1)[1]] = int(row["value"])
        except (ValueError, TypeError):
            pass
    return out


def status(conn, pack_dir=None) -> dict:
    """What packs are available, their versions, and which are pending apply."""
    applied = _applied_versions(conn)
    packs, pending = [], 0
    for p in load_packs(pack_dir):
        cur = applied.get(p["name"])
        is_pending = cur is None or cur < p["version"]
        pending += int(is_pending)
        packs.append({"name": p["name"], "version": p["version"], "appliedVersion": cur,
                      "ruleCount": len(p["rules"]), "pending": is_pending,
                      "description": p["description"]})
    return {"packs": packs, "pending": pending}


def apply(conn, pack_dir=None) -> dict:
    """Upsert all pack rules (idempotent) and record applied versions. Existing
    rules keep their status (operator's enable/disable) + hit stats; only the
    content fields are refreshed."""
    from dashboard_api.db import dumps
    upserted = 0
    packs = load_packs(pack_dir)
    for p in packs:
        for r in p["rules"]:
            tags = dumps(list(r.get("tags") or []) + [f"pack:{p['name']}"])
            desc = r.get("description") or f"{r['name']} (content pack '{p['name']}')."
            if conn.execute("SELECT 1 FROM detection_rules WHERE id=?", (r["id"],)).fetchone():
                conn.execute(
                    "UPDATE detection_rules SET name=?,category=?,severity=?,mitre_tactic=?,"
                    "mitre_tactic_id=?,mitre_tech_id=?,mitre_tech=?,description=?,definition=?,"
                    "tags=?,source='content-pack' WHERE id=?",
                    (r["name"], r["category"], r["severity"], r["mitre_tactic"],
                     r["mitre_tactic_id"], r["mitre_tech_id"], r["mitre_tech"], desc,
                     dumps(r["definition"]), tags, r["id"]))
            else:
                conn.execute(
                    "INSERT INTO detection_rules (id,name,category,severity,mitre_tactic,"
                    "mitre_tactic_id,mitre_tech_id,mitre_tech,status,source,created,description,"
                    "definition,tags) VALUES (?,?,?,?,?,?,?,?, 'enabled','content-pack',?,?,?,?)",
                    (r["id"], r["name"], r["category"], r["severity"], r["mitre_tactic"],
                     r["mitre_tactic_id"], r["mitre_tech_id"], r["mitre_tech"], _now(),
                     desc, dumps(r["definition"]), tags))
            upserted += 1
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
                     (f"content_pack:{p['name']}", str(p["version"])))
    return {"packs": len(packs), "rulesUpserted": upserted,
            "versions": {p["name"]: p["version"] for p in packs}}
