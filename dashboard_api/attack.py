"""MITRE ATT&CK: what the malware DOES, from the authority that publishes it.

The store can name 178,911 of its indicators to a malware family. That was the
hard part, and on its own it stops one step short of useful: an analyst who
learns a domain is Emotet infrastructure still has to leave the platform to find
out what Emotet does, who has been reported using it, and what to look for on the
host. "They are just IOCs" is a fair description of a store that cannot answer
that, and it is what a public CTI library answers for free.

ATT&CK answers it, and answers it citably. Every technique here carries its
Txxxx id and its attack.mitre.org URL, so nothing on the page is this platform's
opinion - it is MITRE's, quoted, with a link to check it.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
ATT&CK records `intrusion-set --uses--> malware`. It would be one join to write
those group names onto every indicator of that family, and the store's
attribution column would fill up overnight. It would also be false. Cobalt
Strike is used by THIRTY groups in this data - it is licensed software sold to
red teams and cracked by nearly everyone else - so "this IP is Cobalt Strike
infrastructure" supports no claim whatever about who is behind it.

So groups are surfaced as what they are: a list of everyone reported to use the
family, presented as the reason NOT to attribute from a family alone. Thirty
names against one indicator makes that argument better than any warning text
could. `iocs.actor` is never written from here.

THE MATCH IS BY NAME, AND SOME FAMILIES DO NOT MATCH
----------------------------------------------------
20 of 35 families resolve to an ATT&CK object, by name or by alias. The other
fifteen are mostly commodity stealers and older botnets that ATT&CK does not
track (RedLine, Raccoon, Vidar, Arkei, Formbook, Tofsee, Necurs...). Those pages
say so - "MITRE ATT&CK does not track this family" is a fact about the coverage
of a public dataset, and it is more useful than a blank panel that reads like a
loading failure.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

# The collection index, which names the current release of each matrix. Resolved
# rather than pinned: ATT&CK ships a numbered version several times a year, and a
# hard-coded path is a URL that silently 404s the moment it moves - which is
# exactly the failure `connectors._record_feed_health` exists to make visible.
ATTACK_INDEX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json")
ATTACK_COLLECTION = "Enterprise ATT&CK"

# The bundle is ~54 MB of STIX, of which we keep a few MB. Read in full because
# it is JSON and there is no streaming shape to exploit; done on a weekly cadence
# rather than per sync, since ATT&CK changes a few times a year.
ATTACK_MAX_BYTES = 96 * 1024 * 1024

_ATTACK_SOURCE = "mitre-attack"

# How often to re-check for a new release. Weekly: ATT&CK ships a few numbered
# releases a year, and the bundle is ~54 MB, so a per-sync refresh would be tens
# of gigabytes a year to learn nothing. 0 disables it - an air-gapped deployment
# loads the tables once and keeps them.
REFRESH_SECONDS = int(os.environ.get("DASHBOARD_ATTACK_REFRESH_SECONDS",
                                    str(7 * 24 * 3600)))


def _norm(name: str | None) -> str:
    """Match key for a family name. ATT&CK writes "Cobalt Strike" and the feed
    writes "cobaltstrike"; neither is wrong, and neither matches the other."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _live(o: dict) -> bool:
    """ATT&CK never deletes: it revokes and deprecates in place. A store that
    ignores those two flags reports retired techniques as current."""
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def _attack_id(o: dict) -> str | None:
    for ref in o.get("external_references") or []:
        if ref.get("source_name") == _ATTACK_SOURCE:
            return ref.get("external_id")
    return None


def _attack_url(o: dict) -> str | None:
    for ref in o.get("external_references") or []:
        if ref.get("source_name") == _ATTACK_SOURCE:
            return ref.get("url")
    return None


# ATT&CK descriptions are STIX prose: Markdown links to other ATT&CK pages, and
# a trail of (Citation: Vendor-Report-Year) markers where the evidence is.
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CITATION = re.compile(r"\s*\(Citation:\s*([^)]*)\)")


def _describe(text: str | None) -> tuple[str, list[str]]:
    """Split an ATT&CK description into readable prose and its citations.

    Rendered raw, these read as source code: "The [2022 Ukraine Electric Power
    Attack](https://attack.mitre.org/campaigns/C0034) was a [Sandworm
    Team](https://attack.mitre.org/groups/G0034) campaign ...(Citation:
    Mandiant-Sandworm-Ukraine-2022)(Citation: Dragos-Sandworm-Ukraine-2022)".

    Stripping the citations outright would be the wrong fix - they are the
    evidence, and this platform's whole argument is that a claim travels with its
    source. So they come out of the prose and are returned alongside it, for the
    page to render as what they are: who reported this.
    """
    if not text:
        return "", []
    cites = [c.strip() for c in _CITATION.findall(text) if c.strip()]
    prose = _CITATION.sub("", text)
    prose = _MD_LINK.sub(r"\1", prose)
    # Deduplicate, keeping the order they were cited in.
    seen, ordered = set(), []
    for c in cites:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return prose.strip(), ordered


def _tactics(o: dict) -> str:
    """The kill-chain phases a technique belongs to, comma-separated.

    Stored flat rather than in a join table: a technique has one to three of
    these, they are only ever read together, and a table of 15 rows joined 697
    times buys nothing."""
    return ",".join(p["phase_name"] for p in (o.get("kill_chain_phases") or [])
                    if p.get("kill_chain_name") == _ATTACK_SOURCE)


def parse_bundle(bundle: dict, families: list[str]) -> dict[str, Any]:
    """Reduce a 26,000-object STIX bundle to the handful of answers we ask of it.

    Kept as a pure function of (bundle, families) so the shape of the extraction
    is testable against a small fixture, without a network or a database.
    """
    objs = [o for o in bundle.get("objects") or [] if _live(o)]
    by_id = {o["id"]: o for o in objs}

    techniques = {o["id"]: o for o in objs if o["type"] == "attack-pattern"}
    groups = {o["id"]: o for o in objs if o["type"] == "intrusion-set"}
    # `tool` as well as `malware`: ATT&CK files Cobalt Strike as a tool, because
    # it is one. To an analyst looking at C2 infrastructure that distinction is
    # not interesting, and dropping tools would lose the single best example of
    # why a family is not an actor.
    software = [o for o in objs if o["type"] in ("malware", "tool")]

    by_name: dict[str, dict] = {}
    for o in software:
        for n in [o.get("name")] + list(o.get("aliases") or []):
            by_name.setdefault(_norm(n), o)

    fam_obj = {f: by_name[_norm(f)] for f in families if _norm(f) in by_name}
    fam_by_ref = {o["id"]: f for f, o in fam_obj.items()}

    uses = [r for r in objs if r["type"] == "relationship"
            and r.get("relationship_type") == "uses"]

    fam_tech: list[tuple[str, str]] = []
    fam_group: list[tuple[str, str]] = []
    group_tech: list[tuple[str, str]] = []
    for r in uses:
        src, dst = r.get("source_ref"), r.get("target_ref")
        if src in fam_by_ref and dst in techniques:
            fam_tech.append((fam_by_ref[src], dst))
        elif src in groups and dst in fam_by_ref:
            fam_group.append((fam_by_ref[dst], src))
        elif src in groups and dst in techniques:
            group_tech.append((src, dst))

    # Tactic names and their kill-chain ORDER, taken from the matrix object
    # rather than hardcoded. ATT&CK renames tactics between releases - v19
    # replaced "Defense Evasion" with "Stealth" and added "Defense Impairment" -
    # and a frontend carrying its own list would render last year's kill chain
    # while claiming to quote MITRE. This session has already fixed one silently
    # stale hardcoded reference; that is enough.
    matrix = next((o for o in objs if o["type"] == "x-mitre-matrix"), {})
    order = {ref: i for i, ref in enumerate(matrix.get("tactic_refs") or [])}
    tactics = [{
        "shortname": o.get("x_mitre_shortname") or "",
        "name": o.get("name") or "",
        "position": order.get(o["id"], 99),
    } for o in objs if o["type"] == "x-mitre-tactic" and o.get("x_mitre_shortname")]
    tactics.sort(key=lambda t: t["position"])

    # Campaigns: real, dated, named operations, attributed where MITRE attributes
    # them. The actor page has had a "Known Campaigns" section since it was
    # written, and on a live deployment it rendered a heading with nothing under
    # it on every actor - the library carries no campaign records, and only the
    # demo seeder ever added illustrative ones. Six of the thirteen shipped
    # actors have MITRE campaigns; those six now have the real thing.
    campaigns = {o["id"]: o for o in objs if o["type"] == "campaign"}
    camp_group: list[tuple[str, str]] = []
    camp_soft: list[tuple[str, str]] = []
    for r in objs:
        if r["type"] != "relationship":
            continue
        src, dst = r.get("source_ref"), r.get("target_ref")
        if src not in campaigns:
            continue
        if r.get("relationship_type") == "attributed-to" and dst in groups:
            camp_group.append((src, dst))
        elif r.get("relationship_type") == "uses" and dst in fam_by_ref:
            camp_soft.append((src, fam_by_ref[dst]))

    return {
        "version": (bundle.get("objects") and _collection_version(bundle)) or "",
        "tactics": tactics,
        "campaigns": [{
            "id": _attack_id(o), "stix_id": o["id"], "name": o.get("name") or "",
            "aliases": json.dumps([a for a in (o.get("aliases") or [])
                                   if a != o.get("name")]),
            "url": _attack_url(o),
            "description": _describe(o.get("description"))[0],
            "citations": json.dumps(_describe(o.get("description"))[1]),
            # Dates as ATT&CK publishes them: a date, not a timestamp, because
            # "June 2024" is the resolution the reporting actually supports.
            "first_seen": str(o.get("first_seen") or "")[:10],
            "last_seen": str(o.get("last_seen") or "")[:10],
        } for o in campaigns.values() if _attack_id(o)],
        "campaign_groups": sorted({
            (_attack_id(campaigns[c]), _attack_id(by_id[g])) for c, g in camp_group
            if _attack_id(campaigns[c]) and _attack_id(by_id[g])}),
        "campaign_families": sorted({
            (_attack_id(campaigns[c]), f) for c, f in camp_soft
            if _attack_id(campaigns[c])}),
        "techniques": [{
            "id": _attack_id(o), "stix_id": o["id"], "name": o.get("name") or "",
            "tactics": _tactics(o), "url": _attack_url(o),
            "description": _describe(o.get("description"))[0],
            # A sub-technique (T1055.011) is a specific way of doing its parent.
            # Worth marking so a page can lead with the parents rather than
            # opening on forty near-identical variants.
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
        } for o in techniques.values() if _attack_id(o)],
        "groups": [{
            "id": _attack_id(o), "stix_id": o["id"], "name": o.get("name") or "",
            "aliases": json.dumps([a for a in (o.get("aliases") or [])
                                   if a != o.get("name")]),
            "url": _attack_url(o),
            "description": _describe(o.get("description"))[0],
            "citations": json.dumps(_describe(o.get("description"))[1]),
        } for o in groups.values() if _attack_id(o)],
        "software": [{
            "family": f, "id": _attack_id(o), "name": o.get("name") or "",
            "url": _attack_url(o), "kind": o["type"],
            "description": _describe(o.get("description"))[0],
        } for f, o in fam_obj.items() if _attack_id(o)],
        "family_techniques": sorted({
            (f, _attack_id(by_id[t])) for f, t in fam_tech if _attack_id(by_id[t])}),
        "family_groups": sorted({
            (f, _attack_id(by_id[g])) for f, g in fam_group if _attack_id(by_id[g])}),
        "group_techniques": sorted({
            (_attack_id(by_id[g]), _attack_id(by_id[t])) for g, t in group_tech
            if _attack_id(by_id[g]) and _attack_id(by_id[t])}),
    }


def _collection_version(bundle: dict) -> str:
    """The ATT&CK release this bundle is, so a page can say which it is quoting.

    Read from the x-mitre-collection object the bundle ships rather than from the
    filename, which is a thing the fetcher chose."""
    for o in bundle.get("objects") or []:
        if o.get("type") == "x-mitre-collection":
            versions = o.get("x_mitre_version")
            if versions:
                return str(versions)
    return ""


def latest_bundle_url(index: dict, collection: str = ATTACK_COLLECTION) -> str | None:
    """The newest published bundle for a matrix, from the collection index."""
    for col in index.get("collections") or []:
        if col.get("name") != collection:
            continue
        versions = col.get("versions")
        if isinstance(versions, dict):
            versions = versions.get("all") or []
        for v in versions or []:
            if v.get("url"):
                return v["url"]
    return None


def store(conn, parsed: dict[str, Any]) -> dict[str, int]:
    """Replace the ATT&CK tables with a freshly parsed release.

    A full replace rather than an upsert, because ATT&CK revokes and deprecates:
    merging a new release into an old one leaves retired techniques behind
    forever, still attached to families, indistinguishable from current ones.
    The dataset is small enough that correctness is free here.
    """
    for table in ("attack_family_technique", "attack_family_group",
                  "attack_group_technique", "attack_software",
                  "attack_technique", "attack_group", "attack_group_name",
                  "attack_campaign_group", "attack_campaign_family",
                  "attack_campaign", "attack_tactic"):
        conn.execute(f"DELETE FROM {table}")
    conn.executemany(
        "INSERT INTO attack_tactic (shortname,name,position) VALUES (?,?,?)",
        [(t["shortname"], t["name"], t["position"]) for t in parsed["tactics"]])
    conn.executemany(
        "INSERT INTO attack_technique (id,name,tactics,url,description,is_subtechnique) "
        "VALUES (?,?,?,?,?,?)",
        [(t["id"], t["name"], t["tactics"], t["url"], t["description"],
          1 if t["is_subtechnique"] else 0) for t in parsed["techniques"]])
    # One row per (group, name-or-alias). ATT&CK's names and the library's names
    # rarely match exactly - "Sandworm" is "Sandworm Team", "Evil Corp" is
    # "Indrik Spider" - so the alias set is the join, and a normalised key makes
    # it an indexed lookup rather than a scan that parses 176 JSON blobs.
    conn.executemany(
        "INSERT INTO attack_group (id,name,aliases,url,description,citations) "
        "VALUES (?,?,?,?,?,?)",
        [(g["id"], g["name"], g["aliases"], g["url"], g["description"], g["citations"])
         for g in parsed["groups"]])
    conn.executemany(
        "INSERT INTO attack_group_name (norm_key,group_id) VALUES (?,?) "
        "ON CONFLICT(norm_key) DO NOTHING",
        sorted({(_norm(n), g["id"]) for g in parsed["groups"]
                for n in [g["name"]] + json.loads(g["aliases"] or "[]") if _norm(n)}))
    conn.executemany(
        "INSERT INTO attack_software (family,id,name,url,kind,description) "
        "VALUES (?,?,?,?,?,?)",
        [(s["family"], s["id"], s["name"], s["url"], s["kind"], s["description"])
         for s in parsed["software"]])
    conn.executemany(
        "INSERT INTO attack_family_technique (family,technique_id) VALUES (?,?)",
        parsed["family_techniques"])
    conn.executemany(
        "INSERT INTO attack_family_group (family,group_id) VALUES (?,?)",
        parsed["family_groups"])
    conn.executemany(
        "INSERT INTO attack_group_technique (group_id,technique_id) VALUES (?,?)",
        parsed["group_techniques"])
    conn.executemany(
        "INSERT INTO attack_campaign (id,name,aliases,url,description,citations,"
        "first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
        [(c["id"], c["name"], c["aliases"], c["url"], c["description"],
          c["citations"], c["first_seen"], c["last_seen"])
         for c in parsed["campaigns"]])
    conn.executemany(
        "INSERT INTO attack_campaign_group (campaign_id,group_id) VALUES (?,?)",
        parsed["campaign_groups"])
    conn.executemany(
        "INSERT INTO attack_campaign_family (campaign_id,family) VALUES (?,?)",
        parsed["campaign_families"])
    return {
        "tactics": len(parsed["tactics"]),
        "techniques": len(parsed["techniques"]),
        "groups": len(parsed["groups"]),
        "campaigns": len(parsed["campaigns"]),
        "attributedCampaigns": len(parsed["campaign_groups"]),
        "families": len(parsed["software"]),
        "familyTechniques": len(parsed["family_techniques"]),
        "familyGroups": len(parsed["family_groups"]),
        "groupTechniques": len(parsed["group_techniques"]),
    }


def refresh(conn=None) -> dict[str, Any]:
    """Fetch the current Enterprise release and replace what we hold.

    Returns the tallies, or `{"error": ...}`. Never raises: ATT&CK is context on
    top of the store, and a platform that will not start because MITRE's CDN is
    slow has its priorities the wrong way round.
    """
    from dashboard_api.connectors import _http_get
    from dashboard_api.connectors import _MALWARE_FAMILIES
    from dashboard_api.db import get_conn

    try:
        index = json.loads(_http_get(ATTACK_INDEX_URL).text)
        url = latest_bundle_url(index)
        if not url:
            return {"error": f"no {ATTACK_COLLECTION} collection in the ATT&CK index"}
        bundle = json.loads(_http_get(url, truncate_at=ATTACK_MAX_BYTES).text)
        parsed = parse_bundle(bundle, list(_MALWARE_FAMILIES))
    except Exception as e:
        logging.warning("ATT&CK refresh failed: %s", e)
        return {"error": str(e)}

    # Take the caller's connection when there is one. Opening a second while the
    # first holds a write transaction is how this codebase has deadlocked SQLite
    # before, and boot-time seeding is exactly that situation.
    try:
        if conn is not None:
            counts = store(conn, parsed)
            _record_version(conn, parsed["version"], url)
        else:
            with get_conn() as c:
                counts = store(c, parsed)
                _record_version(c, parsed["version"], url)
                c.commit()
    except Exception as e:
        logging.warning("storing ATT&CK failed: %s", e)
        return {"error": str(e)}
    counts["version"] = parsed["version"]
    counts["url"] = url
    logging.info("ATT&CK %s: %d techniques, %d groups, %d families mapped",
                 parsed["version"], counts["techniques"], counts["groups"],
                 counts["families"])
    return counts


def _record_version(conn, version: str, url: str) -> None:
    """Which release is on the page, so a reader can tell current from stale."""
    from dashboard_api.db import _utc_now_iso
    conn.execute("DELETE FROM attack_release")
    conn.execute(
        "INSERT INTO attack_release (version,url,fetched_at) VALUES (?,?,?)",
        (version, url, _utc_now_iso()))


# -- reading it back -----------------------------------------------------------

def family_attack(conn, family: str) -> dict[str, Any]:
    """Everything ATT&CK says about one family, shaped for a page.

    `tracked` false is a real answer - ATT&CK covers 20 of the 35 families this
    engine imports - and the page says which, rather than rendering an empty
    panel that reads as a failure.
    """
    key = (family or "").strip().lower()
    soft = conn.execute(
        "SELECT id,name,url,kind,description FROM attack_software WHERE family=?",
        (key,)).fetchone()
    if soft is None:
        return {"tracked": False, "techniqueCount": 0, "byTactic": [],
                "techniques": [], "groups": []}
    techniques = [dict(r) for r in conn.execute(
        "SELECT t.id, t.name, t.tactics, t.url, t.is_subtechnique "
        "FROM attack_family_technique ft JOIN attack_technique t ON t.id = ft.technique_id "
        "WHERE ft.family=? ORDER BY t.tactics, t.id", (key,)).fetchall()]
    groups = [dict(r) for r in conn.execute(
        "SELECT g.id, g.name, g.url FROM attack_family_group fg "
        "JOIN attack_group g ON g.id = fg.group_id WHERE fg.family=? ORDER BY g.name",
        (key,)).fetchall()]
    # Grouped by tactic here rather than in the page, because the ORDER is
    # ATT&CK's - the kill chain reads reconnaissance to impact, and a page that
    # sorts alphabetically has thrown that away.
    names = {r["shortname"]: (r["name"], r["position"]) for r in conn.execute(
        "SELECT shortname,name,position FROM attack_tactic").fetchall()}
    buckets: dict[str, list] = {}
    for t in techniques:
        entry = {"id": t["id"], "name": t["name"], "url": t["url"],
                 "isSubtechnique": bool(t["is_subtechnique"])}
        for short in [x for x in (t["tactics"] or "").split(",") if x]:
            buckets.setdefault(short, []).append(entry)
    by_tactic = [{
        "shortname": short,
        "name": names.get(short, (short.replace("-", " ").title(), 99))[0],
        "techniques": sorted(items, key=lambda x: x["id"]),
    } for short, items in buckets.items()]
    by_tactic.sort(key=lambda b: names.get(b["shortname"], ("", 99))[1])
    return {
        "tracked": True,
        "id": soft["id"], "name": soft["name"], "url": soft["url"],
        "kind": soft["kind"], "description": soft["description"],
        "techniqueCount": len(techniques),
        "byTactic": by_tactic,
        "techniques": [{
            "id": t["id"], "name": t["name"], "url": t["url"],
            "tactics": [x for x in (t["tactics"] or "").split(",") if x],
            "isSubtechnique": bool(t["is_subtechnique"]),
        } for t in techniques],
        "groups": [{"id": g["id"], "name": g["name"], "url": g["url"]} for g in groups],
    }


def actor_attack(conn, name: str, aliases: list[str] | None = None) -> dict[str, Any]:
    """Everything ATT&CK says about one threat actor, matched by name or alias.

    Ten of the thirteen actors in the shipped library resolve to an ATT&CK group,
    and each gains between 33 and 93 sourced techniques where the library holds
    four or five. The library's own entries are a hand-written summary; these are
    MITRE's, with a link per technique.

    The three that do not resolve are not an error and are not padded over.
    ATT&CK does not track LockBit or Black Basta as intrusion sets at all, and it
    does not track TA542 - it attributes Emotet to Wizard Spider instead. That is
    a real disagreement between two sources about who runs a botnet, and a
    platform that silently picked one has destroyed the more useful fact.
    """
    candidates = [name] + list(aliases or [])
    row = None
    for cand in candidates:
        key = _norm(cand)
        if not key:
            continue
        row = conn.execute(
            "SELECT g.id,g.name,g.aliases,g.url,g.description FROM attack_group_name n "
            "JOIN attack_group g ON g.id = n.group_id WHERE n.norm_key=?",
            (key,)).fetchone()
        if row is not None:
            break
    if row is None:
        return {"tracked": False, "techniqueCount": 0, "byTactic": [],
                "families": [], "campaigns": []}

    techniques = conn.execute(
        "SELECT t.id, t.name, t.tactics, t.url, t.is_subtechnique "
        "FROM attack_group_technique gt JOIN attack_technique t ON t.id = gt.technique_id "
        "WHERE gt.group_id=? ORDER BY t.id", (row["id"],)).fetchall()
    names = {r["shortname"]: (r["name"], r["position"]) for r in conn.execute(
        "SELECT shortname,name,position FROM attack_tactic").fetchall()}
    buckets: dict[str, list] = {}
    for t in techniques:
        entry = {"id": t["id"], "name": t["name"], "url": t["url"],
                 "isSubtechnique": bool(t["is_subtechnique"])}
        for short in [x for x in (t["tactics"] or "").split(",") if x]:
            buckets.setdefault(short, []).append(entry)
    by_tactic = [{
        "shortname": short,
        "name": names.get(short, (short.replace("-", " ").title(), 99))[0],
        "techniques": sorted(items, key=lambda x: x["id"]),
    } for short, items in buckets.items()]
    by_tactic.sort(key=lambda b: names.get(b["shortname"], ("", 99))[1])

    # Families MITRE reports this group using, restricted to families this engine
    # actually imports - so every one of them is a page the reader can open,
    # rather than a name that leads nowhere.
    families = [r["family"] for r in conn.execute(
        "SELECT family FROM attack_family_group WHERE group_id=? ORDER BY family",
        (row["id"],)).fetchall()]
    campaigns = [{
        "id": r["id"], "name": r["name"], "url": r["url"],
        "description": r["description"],
        "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
        "aliases": json.loads(r["aliases"] or "[]"),
        # Who reported it. Pulled out of the prose rather than deleted from it:
        # the citations are the evidence, and a claim without its source is the
        # thing this platform exists not to publish.
        "citations": json.loads(r["citations"] or "[]"),
        "families": [x["family"] for x in conn.execute(
            "SELECT family FROM attack_campaign_family WHERE campaign_id=? "
            "ORDER BY family", (r["id"],)).fetchall()],
    } for r in conn.execute(
        "SELECT c.id,c.name,c.url,c.description,c.citations,c.first_seen,"
        "c.last_seen,c.aliases "
        "FROM attack_campaign_group cg JOIN attack_campaign c ON c.id = cg.campaign_id "
        "WHERE cg.group_id=? ORDER BY c.first_seen DESC, c.id DESC",
        (row["id"],)).fetchall()]
    return {
        "tracked": True, "id": row["id"], "name": row["name"], "url": row["url"],
        "description": row["description"],
        "aliases": json.loads(row["aliases"] or "[]"),
        "techniqueCount": len(techniques),
        "byTactic": by_tactic,
        "families": families,
        "campaigns": campaigns,
    }


def family_brief(conn, family: str) -> dict[str, Any] | None:
    """The compact form, for a single indicator's triage view.

    An analyst looking at one value is deciding what to do in the next minute,
    not reading a reference page. Handing them forty-seven techniques there would
    be the same mistake as handing them the raw feed: technically complete,
    operationally useless. So this answers the smaller question the moment
    actually poses - *if this is real, what is going on and where else do I
    look?* - as the family's role and the tactics ATT&CK records for it, in
    kill-chain order, with the full page one click away.

    Returns None when ATT&CK does not track the family, so the caller can stay
    silent rather than render an empty heading.
    """
    key = (family or "").strip().lower()
    if not key:
        return None
    soft = conn.execute(
        "SELECT id,name,url,kind FROM attack_software WHERE family=?", (key,)).fetchone()
    if soft is None:
        return None
    rows = conn.execute(
        "SELECT t.tactics FROM attack_family_technique ft "
        "JOIN attack_technique t ON t.id = ft.technique_id WHERE ft.family=?",
        (key,)).fetchall()
    names = {r["shortname"]: (r["name"], r["position"]) for r in conn.execute(
        "SELECT shortname,name,position FROM attack_tactic").fetchall()}
    counts: dict[str, int] = {}
    total = 0
    for r in rows:
        total += 1
        for short in [x for x in (r["tactics"] or "").split(",") if x]:
            counts[short] = counts.get(short, 0) + 1
    tactics = [{"shortname": k,
                "name": names.get(k, (k.replace("-", " ").title(), 99))[0],
                "techniques": v} for k, v in counts.items()]
    tactics.sort(key=lambda t: names.get(t["shortname"], ("", 99))[1])
    return {"id": soft["id"], "name": soft["name"], "url": soft["url"],
            "kind": soft["kind"], "techniqueCount": total, "tactics": tactics}


def release(conn) -> dict[str, Any] | None:
    r = conn.execute("SELECT version,url,fetched_at FROM attack_release").fetchone()
    return None if r is None else {
        "version": r["version"], "url": r["url"], "fetchedAt": r["fetched_at"]}
