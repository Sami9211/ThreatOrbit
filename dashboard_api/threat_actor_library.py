"""Curated threat-actor reference library.

This is real, public CTI reference data — the well-known tracked actors any
platform ships as a baseline knowledge base (like the CVE catalogue or the
ATT&CK matrix), NOT fabricated activity. Names, origins, aliases,
sophistication, motivations, targeted sectors, malware and ATT&CK technique
IDs are publicly documented facts.

It is the single source of truth for actor identity:
  * `seed_actor_library()` populates `threat_actors` in BOTH demo and live
    modes, so live deployments aren't missing the actor knowledge base;
  * the live engine attributes indicators to these exact names, so
    attribution always lands on a real actor row;
  * per-actor *activity* (indicator counts) is derived from REAL indicators
    attributed in the store via `recompute_actor_activity()` — it starts at
    zero and grows truthfully as the engine/connectors attribute IOCs.
"""
import json
import uuid

# (name, aliases, origin, flag, type, motivations, sophistication, threat_level,
#  sectors, malware, ttps) — all publicly documented.
ACTOR_LIBRARY = [
    ("APT29", ["Cozy Bear", "Nobelium", "Midnight Blizzard"], "RU", "🇷🇺", "Nation-State",
     ["Espionage"], 5, "critical", ["Government", "Defense", "Think Tanks"],
     ["WellMess", "WellMail", "SUNBURST"],
     ["T1566", "T1059.001", "T1078", "T1098", "T1550"]),
    ("APT41", ["Wicked Panda", "Barium", "Winnti"], "CN", "🇨🇳", "Nation-State",
     ["Espionage", "Financial"], 5, "critical", ["Healthcare", "Telecom", "Gaming"],
     ["ShadowPad", "PlugX", "Winnti"],
     ["T1190", "T1059", "T1505.003", "T1071", "T1486"]),
    ("Lazarus Group", ["Hidden Cobra", "APT38"], "KP", "🇰🇵", "Nation-State",
     ["Financial", "Disruption"], 5, "critical", ["Finance", "Crypto", "Defense"],
     ["AppleJeus", "FALLCHILL"],
     ["T1566", "T1204", "T1059.003", "T1486", "T1567"]),
    ("FIN7", ["Carbanak", "Carbon Spider"], "RU", "🇷🇺", "Cybercrime",
     ["Financial"], 4, "high", ["Retail", "Hospitality"],
     ["Carbanak", "Griffon", "BABYMETAL"],
     ["T1566.001", "T1204.002", "T1059.001", "T1055", "T1027"]),
    ("Sandworm", ["Voodoo Bear", "Iridium"], "RU", "🇷🇺", "Nation-State",
     ["Disruption"], 5, "critical", ["Energy", "Government"],
     ["NotPetya", "Industroyer", "BlackEnergy"],
     ["T1190", "T1486", "T1561", "T1499", "T1070"]),
    ("Charming Kitten", ["APT35", "Phosphorus"], "IR", "🇮🇷", "Nation-State",
     ["Espionage"], 4, "high", ["Academia", "Journalism", "NGOs"],
     ["PowerShortShell", "HYPERSCRAPE"],
     ["T1566", "T1598", "T1078", "T1114"]),
    ("Scattered Spider", ["UNC3944", "Muddled Libra"], "US", "🇺🇸", "Cybercrime",
     ["Financial"], 4, "high", ["Telecom", "SaaS", "Gaming"],
     ["AlphV", "RansomHub"],
     ["T1566.004", "T1621", "T1078", "T1098", "T1486"]),
    ("Volt Typhoon", ["Bronze Silhouette"], "CN", "🇨🇳", "Nation-State",
     ["Espionage", "Disruption"], 5, "critical", ["Critical Infrastructure", "Utilities"],
     ["living-off-the-land"],
     ["T1190", "T1078", "T1505.003", "T1070", "T1090"]),
    ("LockBit", ["LockBit 3.0", "Bitwise Spider"], "RU", "🇷🇺", "Cybercrime",
     ["Financial"], 4, "high", ["Manufacturing", "Healthcare", "Government"],
     ["LockBit", "StealBit"],
     ["T1486", "T1490", "T1567", "T1219", "T1047"]),
    ("Black Basta", ["BlackBasta"], "RU", "🇷🇺", "Cybercrime",
     ["Financial"], 4, "high", ["Industrials", "Construction", "Healthcare"],
     ["Black Basta", "QakBot"],
     ["T1486", "T1490", "T1059.001", "T1219", "T1567"]),
]

# Names the engine attributes indicators to (kept in lockstep with the library).
ACTOR_NAMES = [a[0] for a in ACTOR_LIBRARY]


def seed_actor_library(conn) -> int:
    """Idempotently insert the reference actors (by name). Returns how many
    were added. Activity counts start at zero and are filled in by
    recompute_actor_activity() from real attributed indicators."""
    added = 0
    for (name, aliases, origin, flag, typ, mot, soph, level, sectors, malware, ttps) in ACTOR_LIBRARY:
        if conn.execute("SELECT 1 FROM threat_actors WHERE name=?", (name,)).fetchone():
            continue
        conn.execute(
            "INSERT INTO threat_actors (id,name,aliases,origin,flag,type,motivations,active,"
            "first_seen,last_seen,sophistication,threat_level,sectors,ttps,malware,ioc_count,"
            "campaign_count,recent_activity,description,campaigns,iocs) "
            "VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,0,0,?,?,?,?)",
            (str(uuid.uuid4()), name, json.dumps(aliases), origin, flag, typ, json.dumps(mot),
             "2014-01-01", "", soph, level, json.dumps(sectors), json.dumps(ttps),
             json.dumps(malware),
             f"Tracked {typ.lower()} actor ({origin}).",
             f"{name} is a {typ.lower()} group attributed to {origin}, "
             f"known for {mot[0].lower()}-motivated operations targeting "
             f"{sectors[0].lower()}.",
             json.dumps([]), json.dumps([])),
        )
        added += 1
    return added


def recompute_actor_activity(conn) -> int:
    """Set each actor's ioc_count + last_seen from indicators REALLY attributed
    to its name in the IOC store. Honest, dynamic activity — zero until the
    engine/connectors attribute something. Returns the number of actors updated."""
    rows = conn.execute(
        "SELECT actor, COUNT(*) AS n, MAX(last_seen) AS seen FROM iocs "
        "WHERE actor IS NOT NULL AND actor != '' GROUP BY actor"
    ).fetchall()
    counts = {r["actor"]: (r["n"], r["seen"]) for r in rows}
    updated = 0
    for r in conn.execute("SELECT id, name FROM threat_actors").fetchall():
        n, seen = counts.get(r["name"], (0, None))
        conn.execute(
            "UPDATE threat_actors SET ioc_count=?, last_seen=COALESCE(?, last_seen), "
            "active=? WHERE id=?",
            (n, seen, 1 if n > 0 else 0, r["id"]))
        updated += 1
    return updated
