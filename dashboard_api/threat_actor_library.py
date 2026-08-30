"""Curated threat-actor reference library.

Public CTI reference data - the tracked groups any platform ships as a baseline
knowledge base, the way it ships the CVE catalogue or the ATT&CK matrix. Names,
aliases, origin, first public reporting, targeted sectors, malware and ATT&CK
technique IDs are all publicly documented.

Two fields are NOT documented facts and are labelled as such wherever they are
shown: `sophistication` and `threat_level` are this platform's own summary
judgement of published assessments. Everything else can be checked against a
vendor report or a MITRE ATT&CK group page.

`since` is the year the group was FIRST PUBLICLY REPORTED. It exists because the
seeder used to write `2014-01-01` into every actor's `first_seen`, in live mode
as well as demo - so a live deployment stated that Volt Typhoon (first reported
2021) and Scattered Spider (2022) had both been active since January 2014. A
constant presented as a date is not a placeholder an analyst can see through; it
is a fact the platform made up. `_correct_placeholder_first_seen` repairs rows
already carrying it.

Identity lives here and only here:
  * `seed_actor_library()` populates `threat_actors` in BOTH demo and live
    modes, so live deployments are not missing the actor knowledge base;
  * the live engine attributes indicators to these exact names, so attribution
    always lands on a real actor row;
  * per-actor ACTIVITY is derived from real indicators - see
    `recompute_actor_activity`, which counts two distinct things and keeps them
    distinct.
"""
import json
import uuid

# The placeholder every actor's first_seen used to be set to. Rows still holding
# it are corrected on boot; a row an operator has changed is left alone, because
# only this exact constant is unambiguously ours.
_PLACEHOLDER_FIRST_SEEN = "2014-01-01"

ACTOR_LIBRARY: list[dict] = [
    {
        "name": "APT29", "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard"],
        "origin": "RU", "flag": "🇷🇺", "type": "Nation-State",
        "motivations": ["Espionage"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Government", "Defense", "Think Tanks"],
        "malware": ["WellMess", "WellMail", "SUNBURST"],
        "ttps": ["T1566", "T1059.001", "T1078", "T1098", "T1550"], "since": "2008",
        "description": (
            "Russian state-linked espionage group, publicly reported since at "
            "least 2008 and best known for the SolarWinds supply-chain "
            "compromise. Favours stealthy, long-dwell access over disruption."),
    },
    {
        "name": "APT41", "aliases": ["Wicked Panda", "Barium", "Winnti"],
        "origin": "CN", "flag": "🇨🇳", "type": "Nation-State",
        "motivations": ["Espionage", "Financial"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Healthcare", "Telecom", "Gaming"],
        "malware": ["ShadowPad", "PlugX", "Winnti"],
        "ttps": ["T1190", "T1059", "T1505.003", "T1071", "T1486"], "since": "2012",
        "description": (
            "Chinese state-linked group that runs espionage and financially "
            "motivated operations side by side - unusual enough that it is the "
            "group's defining characteristic. Members were indicted in the US "
            "in 2020."),
    },
    {
        "name": "Lazarus Group", "aliases": ["Hidden Cobra", "APT38"],
        "origin": "KP", "flag": "🇰🇵", "type": "Nation-State",
        "motivations": ["Financial", "Disruption"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Finance", "Crypto", "Defense"],
        "malware": ["AppleJeus", "FALLCHILL"],
        "ttps": ["T1566", "T1204", "T1059.003", "T1486", "T1567"], "since": "2009",
        "description": (
            "North Korean state group whose financial operations - bank heists "
            "and large-scale cryptocurrency theft - are widely assessed as "
            "revenue generation for the state."),
    },
    {
        "name": "FIN7", "aliases": ["Carbanak", "Carbon Spider"],
        "origin": "RU", "flag": "🇷🇺", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 4, "threat_level": "high",
        "sectors": ["Retail", "Hospitality"],
        "malware": ["Carbanak", "Griffon", "BABYMETAL"],
        "ttps": ["T1566.001", "T1204.002", "T1059.001", "T1055", "T1027"], "since": "2013",
        "description": (
            "Financially motivated group that ran point-of-sale intrusions at "
            "scale, later moving into ransomware. Several members have been "
            "arrested and convicted in the US."),
    },
    {
        "name": "Sandworm", "aliases": ["Voodoo Bear", "Iridium"],
        "origin": "RU", "flag": "🇷🇺", "type": "Nation-State",
        "motivations": ["Disruption"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Energy", "Government"],
        "malware": ["NotPetya", "Industroyer", "BlackEnergy"],
        "ttps": ["T1190", "T1486", "T1561", "T1499", "T1070"], "since": "2009",
        "description": (
            "Russian military-linked group responsible for destructive attacks "
            "on electrical infrastructure and for NotPetya. Attributed by "
            "several governments to the GRU."),
    },
    {
        "name": "Charming Kitten", "aliases": ["APT35", "Phosphorus", "Mint Sandstorm"],
        "origin": "IR", "flag": "🇮🇷", "type": "Nation-State",
        "motivations": ["Espionage"], "sophistication": 4, "threat_level": "high",
        "sectors": ["Academia", "Journalism", "NGOs"],
        "malware": ["PowerShortShell", "HYPERSCRAPE"],
        "ttps": ["T1566", "T1598", "T1078", "T1114"], "since": "2014",
        "description": (
            "Iranian state-linked group known for patient credential phishing "
            "against individuals - academics, journalists and dissidents - "
            "rather than for technically novel malware."),
    },
    {
        "name": "Scattered Spider", "aliases": ["UNC3944", "Muddled Libra", "Octo Tempest"],
        "origin": "US", "flag": "🇺🇸", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 4, "threat_level": "high",
        "sectors": ["Telecom", "SaaS", "Gaming"],
        "malware": ["AlphV", "RansomHub"],
        "ttps": ["T1566.004", "T1621", "T1078", "T1098", "T1486"], "since": "2022",
        "description": (
            "English-speaking crew whose defining technique is social "
            "engineering the help desk - SIM swaps, MFA fatigue and convincing "
            "phone calls - rather than exploitation."),
    },
    {
        "name": "Volt Typhoon", "aliases": ["Bronze Silhouette", "Vanguard Panda"],
        "origin": "CN", "flag": "🇨🇳", "type": "Nation-State",
        "motivations": ["Espionage", "Disruption"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Critical Infrastructure", "Utilities"],
        "malware": ["living-off-the-land"],
        "ttps": ["T1190", "T1078", "T1505.003", "T1070", "T1090"], "since": "2021",
        "description": (
            "Chinese state-linked group pre-positioning in critical "
            "infrastructure. Uses built-in system tools almost exclusively, "
            "which is precisely what makes it hard to find with indicators."),
    },
    {
        "name": "LockBit", "aliases": ["LockBit 3.0", "Bitwise Spider"],
        "origin": "RU", "flag": "🇷🇺", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 4, "threat_level": "high",
        "sectors": ["Manufacturing", "Healthcare", "Government"],
        "malware": ["LockBit", "StealBit"],
        "ttps": ["T1486", "T1490", "T1567", "T1219", "T1047"], "since": "2019",
        "description": (
            "Ransomware-as-a-service operation - the brand and the affiliates "
            "are different people, so 'LockBit did this' names the platform, "
            "not the intruder. Disrupted by law enforcement in 2024."),
    },
    {
        "name": "Black Basta", "aliases": ["BlackBasta"],
        "origin": "RU", "flag": "🇷🇺", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 4, "threat_level": "high",
        "sectors": ["Industrials", "Construction", "Healthcare"],
        "malware": ["Black Basta", "QakBot"],
        "ttps": ["T1486", "T1490", "T1059.001", "T1219", "T1567"], "since": "2022",
        "description": (
            "Ransomware operation that appeared in 2022 with an unusually "
            "mature toolkit, and leaned on QakBot for initial access until that "
            "botnet was disrupted."),
    },
    # -- The crimeware operators this store can actually evidence --------------
    # Added because the malware catalogue names them: a family whose SOLE
    # operator is one of these makes its indicators that operator's
    # infrastructure, which is the only honest way an actor page here gets a
    # non-zero count. See `recompute_actor_activity`.
    {
        "name": "TA542", "aliases": ["Mummy Spider", "Gold Crestwood"],
        # Deliberately blank. The 2021 takedown involved arrests in Ukraine and
        # the group is generally assessed as Eastern European, but no government
        # has attributed it to a state - and a flag on a card reads as certainty.
        "origin": "", "flag": "", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 4, "threat_level": "high",
        "sectors": ["Opportunistic"],
        "malware": ["Emotet"],
        "ttps": ["T1566.001", "T1204.002", "T1059.005", "T1071"], "since": "2014",
        "description": (
            "Operators of the Emotet botnet, which they ran as an access "
            "business: infect broadly by spam, then sell the resulting foothold "
            "to other crews. Taken down in January 2021 and rebuilt the same "
            "year."),
    },
    {
        "name": "Wizard Spider", "aliases": ["ITG23", "Gold Blackburn", "TrickBot Group"],
        "origin": "RU", "flag": "🇷🇺", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Healthcare", "Manufacturing", "Government"],
        "malware": ["TrickBot", "Conti", "Ryuk", "BazarLoader"],
        "ttps": ["T1566", "T1059.001", "T1486", "T1219", "T1567"], "since": "2016",
        "description": (
            "Developed and operated TrickBot and the Conti/Ryuk ransomware that "
            "followed it. Members have been indicted and sanctioned; internal "
            "chat leaks in 2022 exposed the group as a structured business."),
    },
    {
        "name": "Evil Corp", "aliases": ["INDRIK SPIDER", "Gold Drake"],
        "origin": "RU", "flag": "🇷🇺", "type": "Cybercrime",
        "motivations": ["Financial"], "sophistication": 5, "threat_level": "critical",
        "sectors": ["Finance", "Manufacturing"],
        "malware": ["Dridex", "BitPaymer", "WastedLocker"],
        "ttps": ["T1566.001", "T1204.002", "T1486", "T1490", "T1567"], "since": "2014",
        "description": (
            "Named in a 2019 US indictment and OFAC designation for Dridex - "
            "one of the few crimeware groups attributed to specific individuals "
            "by a government. Moved from banking fraud into ransomware."),
    },
]

# Names the engine attributes indicators to (kept in lockstep with the library).
ACTOR_NAMES = [a["name"] for a in ACTOR_LIBRARY]

# actor name -> the malware families it is publicly reported to USE. Reported
# use is NOT the same claim as operating one: several of these are commodity,
# so holding indicators of them says nothing about this actor. Kept as its own
# lookup so the two can never be presented as the same thing.
def reported_malware() -> dict[str, list[str]]:
    return {a["name"]: list(a.get("malware") or []) for a in ACTOR_LIBRARY}


def seed_actor_library(conn) -> int:
    """Idempotently insert the reference actors (by name). Returns how many were
    added. Activity counts start at zero and are filled in by
    `recompute_actor_activity` from real indicators."""
    added = 0
    for a in ACTOR_LIBRARY:
        if conn.execute("SELECT 1 FROM threat_actors WHERE name=?", (a["name"],)).fetchone():
            continue
        conn.execute(
            "INSERT INTO threat_actors (id,name,aliases,origin,flag,type,motivations,active,"
            "first_seen,last_seen,sophistication,threat_level,sectors,ttps,malware,ioc_count,"
            "campaign_count,recent_activity,description,campaigns,iocs) "
            "VALUES (?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,0,0,?,?,?,?)",
            (str(uuid.uuid4()), a["name"], json.dumps(a["aliases"]), a["origin"], a["flag"],
             a["type"], json.dumps(a["motivations"]),
             # The year it was first publicly reported, not a constant.
             a["since"], "", a["sophistication"], a["threat_level"],
             json.dumps(a["sectors"]), json.dumps(a["ttps"]), json.dumps(a["malware"]),
             f"Tracked {a['type'].lower()} actor.", a["description"],
             json.dumps([]), json.dumps([])),
        )
        added += 1
    return added


def correct_placeholder_first_seen(conn) -> int:
    """Replace the constant `2014-01-01` with the real year, where we know it.

    Every actor row written before this carried that date, in live deployments
    too, so the platform asserted that groups first reported in 2021 and 2022
    had been active since January 2014. Only rows still holding that exact
    constant are touched - anything else is somebody's own edit.
    """
    fixed = 0
    for a in ACTOR_LIBRARY:
        cur = conn.execute(
            "UPDATE threat_actors SET first_seen=? WHERE name=? AND first_seen=?",
            (a["since"], a["name"], _PLACEHOLDER_FIRST_SEEN))
        fixed += getattr(cur, "rowcount", 0) or 0
    return fixed


def operated_families(conn) -> dict[str, list[str]]:
    """actor name -> families whose SOLE named operator is that actor.

    This is the one link that lets an indicator count toward an actor. The
    malware catalogue sets `operator` on three of thirty-five families, and only
    where a single group is consistently and publicly named as running it; every
    other family is sold, leaked, open-source or cracked, so its indicators
    belong to whoever bought a copy.
    """
    out: dict[str, list[str]] = {}
    try:
        rows = conn.execute(
            "SELECT name, operator FROM malware_families "
            "WHERE operator IS NOT NULL AND operator <> ''").fetchall()
    except Exception:      # catalogue not migrated yet (first boot)
        return out
    for r in rows:
        out.setdefault(r["operator"], []).append(r["name"])
    return out


def recompute_actor_activity(conn) -> int:
    """Set each actor's ioc_count + last_seen from indicators REALLY tied to it.

    Two different links, and the difference matters enough to spell out:

      * `iocs.actor = <name>` - a source named this adversary on this value.
      * `iocs.malware_family` is a family whose SOLE operator is this actor. An
        Emotet C2 is TA542's infrastructure in the same sense; that is what the
        catalogue's `operator` field asserts, and it is why it is set on three
        families out of thirty-five.

    What is deliberately NOT counted is `threat_actors.malware` - the families a
    group is reported to USE. Black Basta used QakBot, and this store holds
    7,611 QakBot indicators; almost none of them are Black Basta's, because
    QakBot was distributed by several affiliates. Counting those would hand the
    actor page a large, confident, wrong number.

    Honest and dynamic: zero until something real attributes.
    """
    direct = {r["actor"]: (r["n"], r["seen"]) for r in conn.execute(
        "SELECT actor, COUNT(*) AS n, MAX(last_seen) AS seen FROM iocs "
        "WHERE actor IS NOT NULL AND actor != '' GROUP BY actor").fetchall()}
    operated = operated_families(conn)
    updated = 0
    for r in conn.execute("SELECT id, name FROM threat_actors").fetchall():
        n, seen = direct.get(r["name"], (0, None))
        for fam in operated.get(r["name"], []):
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(last_seen) AS seen FROM iocs WHERE malware_family=?",
                (fam,)).fetchone()
            n += row["n"] or 0
            if row["seen"] and (seen is None or row["seen"] > seen):
                seen = row["seen"]
        conn.execute(
            "UPDATE threat_actors SET ioc_count=?, last_seen=COALESCE(?, last_seen), "
            "active=? WHERE id=?",
            (n, seen, 1 if n > 0 else 0, r["id"]))
        updated += 1
    return updated
