"""Detection coverage, measured against the threats this deployment actually holds.

Two things existed in this platform and had never been introduced to each other.
The IOC store knows which malware families its indicators belong to - 178,911 of
them, across 35 families. ATT&CK knows what each of those families does, in 628
family/technique pairs. The detection rules each carry the technique they fire
on. Nothing joined them, so the only available answer to "would we see this?" was
somebody's memory.

Joined, the answer is uncomfortable and useful: **enabled rules cover 61 of 628
technique instances - 9.7%** - and the single highest-volume family in the store
(AsyncRAT, 18,355 indicators) is covered at 5%.

WHAT THIS IS AND IS NOT
-----------------------
It is NOT a statement that this deployment is exposed, or compromised, or that
these families are present on the network. The IOC store holds *infrastructure
other people reported*; whether any of it has been near this network is a
different question the sightings ledger answers.

It is a conditional, and the conditional is the useful part: **if the threats
this deployment's own feeds describe turned up here, which of their techniques
would the enabled rules see?** That is a question a SOC lead is asked in every
budget conversation, and answering it from the deployment's own data rather than
from a generic ATT&CK heatmap is the whole point.

Indicator volume ranks the gaps because it is the only prevalence signal
available - it says how much of what the feeds publish concerns a family, not how
likely that family is to appear HERE. Ranking by it is better than ranking
alphabetically and worse than ranking by local sightings, which is what this
should use once a deployment has enough of them.

SUB-TECHNIQUES
--------------
A rule on a parent (T1059) covers its children (T1059.001, T1059.003), because
detecting "command interpreter execution" catches PowerShell and cmd alike. A
rule on ONE child does not cover a sibling: T1059.001 is PowerShell logging and
says nothing about VBScript. Getting that backwards inflates coverage by exactly
the amount that would make it useless.
"""
from __future__ import annotations

from typing import Any


def _covered_by(technique: str, rules: set[str]) -> str | None:
    """Which rule technique covers this one - itself, or its parent. None if
    neither. Returned rather than a bool so a panel can say WHY it is covered."""
    if technique in rules:
        return technique
    parent = technique.split(".")[0]
    return parent if parent in rules else None


def detection_coverage(conn, org_id: str | None = None) -> dict[str, Any]:
    """Coverage of the ATT&CK techniques used by the families in this store.

    Only ENABLED rules count. A disabled rule is a rule that does not fire, and
    counting it would be the same self-flattery as counting a feed's historical
    value_count while its fetch is failing.
    """
    where, params = "status='enabled' AND mitre_tech_id IS NOT NULL AND mitre_tech_id<>''", []
    if org_id:
        where += " AND (org_id IS NULL OR org_id=?)"
        params.append(org_id)
    rule_rows = conn.execute(
        f"SELECT mitre_tech_id, name FROM detection_rules WHERE {where}", params).fetchall()
    rules: dict[str, list[str]] = {}
    for r in rule_rows:
        rules.setdefault(r["mitre_tech_id"], []).append(r["name"])
    rule_set = set(rules)

    held = {r["malware_family"]: r["n"] for r in conn.execute(
        "SELECT malware_family, COUNT(*) AS n FROM iocs "
        "WHERE malware_family IS NOT NULL AND malware_family<>'' "
        "GROUP BY malware_family").fetchall()}
    tech = {r["id"]: r for r in conn.execute(
        "SELECT id, name, tactics, url FROM attack_technique").fetchall()}
    pairs = conn.execute(
        "SELECT family, technique_id FROM attack_family_technique").fetchall()
    labels = {r["family"]: r["name"] for r in conn.execute(
        "SELECT family, name FROM attack_software").fetchall()}
    tactic_names = {r["shortname"]: (r["name"], r["position"]) for r in conn.execute(
        "SELECT shortname, name, position FROM attack_tactic").fetchall()}

    by_family: dict[str, dict] = {}
    gap_families: dict[str, set] = {}
    gap_volume: dict[str, int] = {}
    covered_total = total = 0
    for p in pairs:
        fam, tid = p["family"], p["technique_id"]
        if tid not in tech:
            continue
        entry = by_family.setdefault(fam, {"covered": [], "missing": [], "tactics": set()})
        total += 1
        for short in (tech[tid]["tactics"] or "").split(","):
            if short:
                entry["tactics"].add(short)
        by = _covered_by(tid, rule_set)
        if by:
            covered_total += 1
            entry["covered"].append(tid)
        else:
            entry["missing"].append(tid)
            gap_families.setdefault(tid, set()).add(fam)
            gap_volume[tid] = gap_volume.get(tid, 0) + held.get(fam, 0)

    families = []
    for fam, e in by_family.items():
        n_cov, n_all = len(e["covered"]), len(e["covered"]) + len(e["missing"])
        # Which tactics this family operates in that NO enabled rule touches.
        # More useful than a percentage: "blind through the whole of Discovery
        # and Lateral Movement" is a sentence somebody can act on.
        blind = []
        for short in e["tactics"]:
            in_tactic = [t for t in e["covered"] + e["missing"]
                         if short in (tech[t]["tactics"] or "").split(",")]
            if in_tactic and not any(_covered_by(t, rule_set) for t in in_tactic):
                blind.append(short)
        blind.sort(key=lambda s: tactic_names.get(s, ("", 99))[1])
        families.append({
            "family": fam,
            "label": labels.get(fam, fam.title()),
            "indicators": held.get(fam, 0),
            "covered": n_cov,
            "techniques": n_all,
            "blindTactics": [{"shortname": s,
                              "name": tactic_names.get(s, (s.replace("-", " ").title(), 99))[0]}
                             for s in blind],
        })
    # By how much of the store the family accounts for: the gap that matters most
    # is the one in front of the most of what the feeds are actually publishing.
    families.sort(key=lambda f: (-f["indicators"], f["family"]))

    gaps = []
    for tid, vol in sorted(gap_volume.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        t = tech[tid]
        gaps.append({
            "id": tid, "name": t["name"], "url": t["url"],
            "tactics": [{"shortname": s,
                         "name": tactic_names.get(s, (s.replace("-", " ").title(), 99))[0]}
                        for s in (t["tactics"] or "").split(",") if s],
            "families": sorted(gap_families[tid]),
            "familyCount": len(gap_families[tid]),
            "indicators": vol,
        })

    return {
        "rules": sum(len(v) for v in rules.values()),
        "ruleTechniques": len(rule_set),
        "covered": covered_total,
        "techniqueInstances": total,
        "families": families,
        "gaps": gaps,
    }
