"""MITRE ATT&CK: the layer that answers "what does this actually do?".

The store can name 178,911 indicators to a malware family. On its own that stops
one step short of useful - an analyst who learns a domain is Emotet
infrastructure still has to leave the platform to find out what Emotet does. "It
is just IOCs" is a fair description of a store that cannot answer that.

These pin the two things that make the answer trustworthy: that it is MITRE's
answer rather than ours (every technique carries its id and its MITRE URL), and
that the group data is never allowed to become an attribution. ATT&CK records
`intrusion-set --uses--> malware`; it is one join from there to writing thirty
group names onto every Cobalt Strike indicator in the store, and it would be
false in every case.
"""
import json

import pytest

from dashboard_api.attack import (family_attack, latest_bundle_url, parse_bundle,
                                  release, store)
from dashboard_api.db import get_conn


def _bundle(objects):
    return {"type": "bundle", "objects": objects}


def _tech(tid, name, tactics, sub=False, **kw):
    return {"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p}
                                  for p in tactics],
            "x_mitre_is_subtechnique": sub,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                     "url": f"https://attack.mitre.org/techniques/{tid}"}],
            **kw}


def _soft(sid, name, aliases=(), kind="malware", **kw):
    return {"type": kind, "id": f"{kind}--{sid}", "name": name, "aliases": list(aliases),
            "external_references": [{"source_name": "mitre-attack", "external_id": sid,
                                     "url": f"https://attack.mitre.org/software/{sid}"}],
            **kw}


def _group(gid, name, **kw):
    return {"type": "intrusion-set", "id": f"intrusion-set--{gid}", "name": name,
            "aliases": [name], "external_references": [
                {"source_name": "mitre-attack", "external_id": gid,
                 "url": f"https://attack.mitre.org/groups/{gid}"}], **kw}


def _uses(src, dst):
    return {"type": "relationship", "id": f"relationship--{src}-{dst}",
            "relationship_type": "uses", "source_ref": src, "target_ref": dst}


def _tactic(short, name):
    return {"type": "x-mitre-tactic", "id": f"x-mitre-tactic--{short}", "name": name,
            "x_mitre_shortname": short}


FIXTURE = _bundle([
    {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "19.2"},
    {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1",
     "tactic_refs": ["x-mitre-tactic--initial-access", "x-mitre-tactic--execution",
                     "x-mitre-tactic--command-and-control"]},
    _tactic("initial-access", "Initial Access"),
    _tactic("execution", "Execution"),
    _tactic("command-and-control", "Command and Control"),
    _tech("T1566", "Phishing", ["initial-access"]),
    _tech("T1059.001", "PowerShell", ["execution"], sub=True),
    _tech("T1071.001", "Web Protocols", ["command-and-control"], sub=True),
    _tech("T1499", "Retired Technique", ["execution"], x_mitre_deprecated=True),
    _soft("S0367", "Emotet", ["Geodo"]),
    _soft("S0154", "Cobalt Strike", [], kind="tool"),
    _soft("S9999", "Ghostware", [], revoked=True),
    _group("G0102", "Wizard Spider"),
    _group("G0016", "APT29"),
    _uses("malware--S0367", "attack-pattern--T1566"),
    _uses("malware--S0367", "attack-pattern--T1059.001"),
    _uses("malware--S0367", "attack-pattern--T1499"),          # deprecated
    _uses("tool--S0154", "attack-pattern--T1071.001"),
    _uses("intrusion-set--G0102", "malware--S0367"),
    _uses("intrusion-set--G0016", "tool--S0154"),
    _uses("intrusion-set--G0102", "tool--S0154"),
    _uses("intrusion-set--G0016", "attack-pattern--T1566"),
])

FAMILIES = ["emotet", "cobaltstrike", "redline"]


@pytest.fixture()
def loaded():
    """The fixture bundle, parsed and stored. Cleaned up so the real tables (which
    a live deployment fills from MITRE) are not left holding test data."""
    parsed = parse_bundle(FIXTURE, FAMILIES)
    with get_conn() as conn:
        counts = store(conn, parsed)
        conn.commit()
    yield counts
    with get_conn() as conn:
        for t in ("attack_family_technique", "attack_family_group",
                  "attack_group_technique", "attack_software", "attack_technique",
                  "attack_group", "attack_tactic", "attack_release"):
            conn.execute(f"DELETE FROM {t}")
        conn.commit()


# -- it is MITRE's answer, not ours -------------------------------------------

def test_every_technique_carries_its_id_and_a_link_to_mitre(loaded):
    """The whole value is that this is quotable. A technique rendered without its
    Txxxx and its URL is this platform asserting something about malware
    behaviour on its own authority, which it has no basis to do."""
    with get_conn() as conn:
        a = family_attack(conn, "emotet")
    assert a["tracked"]
    for t in a["techniques"]:
        assert t["id"].startswith("T"), t
        assert (t["url"] or "").startswith("https://attack.mitre.org/"), t


def test_the_release_being_quoted_is_recorded(loaded):
    """"ATT&CK says" is worth less than "ATT&CK v19.2 says". A reader has to be
    able to tell a current reference from one three years stale."""
    parsed = parse_bundle(FIXTURE, FAMILIES)
    assert parsed["version"] == "19.2"


# -- revoked and deprecated content is not current content --------------------

def test_a_deprecated_technique_is_not_reported_as_current(loaded):
    """ATT&CK never deletes - it revokes and deprecates in place. Ignoring those
    flags means quoting retired guidance as if MITRE still published it."""
    with get_conn() as conn:
        a = family_attack(conn, "emotet")
    assert "T1499" not in {t["id"] for t in a["techniques"]}


def test_a_revoked_software_object_does_not_become_a_family():
    parsed = parse_bundle(FIXTURE, FAMILIES + ["ghostware"])
    assert "ghostware" not in {s["family"] for s in parsed["software"]}


# -- the kill chain is an order, and the order is MITRE's ---------------------

def test_tactics_come_back_in_kill_chain_order_not_alphabetical(loaded):
    """Alphabetically, command-and-control comes first and initial-access third.
    That is not a kill chain, it is a word list."""
    with get_conn() as conn:
        a = family_attack(conn, "emotet")
    assert [b["shortname"] for b in a["byTactic"]] == ["initial-access", "execution"]


def test_tactic_names_come_from_the_data(loaded):
    """v19 renamed "Defense Evasion" to "Stealth". A display name held in our own
    code renders last year's kill chain while claiming to quote MITRE - which is
    the same class of failure as a feed URL that has silently moved."""
    with get_conn() as conn:
        a = family_attack(conn, "emotet")
    assert {b["name"] for b in a["byTactic"]} == {"Initial Access", "Execution"}


# -- a family is still not an actor -------------------------------------------

def test_loading_attack_never_attributes_an_indicator(loaded):
    """The error this whole module is one join away from. ATT&CK records which
    groups use a family; writing those names into `iocs.actor` would fill the
    attribution column overnight and every entry would be unfounded - thirty
    groups use Cobalt Strike.

    Behavioural rather than a source-code grep: an indicator of a family MITRE
    maps to a group goes in, ATT&CK is loaded on top of it, and it must come
    back out with the attribution it arrived with."""
    import uuid
    value = f"attack-test-{uuid.uuid4().hex[:10]}.example.test"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO iocs (id,type,value,severity,confidence,source,actor,"
            "malware_family,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), "domain", value, "high", 70, "test", "",
             "emotet", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"))
        conn.commit()
    try:
        with get_conn() as conn:
            store(conn, parse_bundle(FIXTURE, FAMILIES))
            conn.commit()
            actor = conn.execute("SELECT actor FROM iocs WHERE value=?",
                                 (value,)).fetchone()["actor"]
        assert actor == "", (
            f"loading ATT&CK attributed an indicator to {actor!r} - a group "
            f"using a family does not make every sighting of it theirs")
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM iocs WHERE value=?", (value,))
            conn.commit()


def test_a_family_used_by_many_groups_reports_all_of_them(loaded):
    """Cobalt Strike is used by thirty groups in the real data. Showing all of
    them is the argument against attributing from a family - truncating to the
    first one would make the opposite argument."""
    with get_conn() as conn:
        a = family_attack(conn, "cobaltstrike")
    assert {g["name"] for g in a["groups"]} == {"APT29", "Wizard Spider"}


def test_a_tool_is_still_a_family_here(loaded):
    """ATT&CK files Cobalt Strike as a `tool` because it is licensed software.
    To an analyst looking at C2 infrastructure that distinction is not
    interesting, and dropping tools would lose the clearest case for why a
    family cannot name an adversary."""
    with get_conn() as conn:
        a = family_attack(conn, "cobaltstrike")
    assert a["tracked"] and a["kind"] == "tool"


# -- what ATT&CK does not cover -----------------------------------------------

def test_an_untracked_family_says_so_rather_than_returning_nothing(loaded):
    """ATT&CK covers 20 of the 35 families this engine imports. "MITRE does not
    track this" is a real answer; an empty panel reads as a failed request."""
    with get_conn() as conn:
        a = family_attack(conn, "redline")
    assert a["tracked"] is False
    assert a["techniques"] == [] and a["groups"] == []


def test_a_family_matches_on_an_alias_too():
    """The feed writes "emotet"; ATT&CK writes "Emotet" with alias "Geodo".
    Matching only on the exact primary name loses families needlessly."""
    parsed = parse_bundle(FIXTURE, ["geodo"])
    assert [s["family"] for s in parsed["software"]] == ["geodo"]


# -- refreshing --------------------------------------------------------------

def test_a_refresh_replaces_rather_than_merges(loaded):
    """ATT&CK deprecates in place, so merging a new release into an old one
    leaves retired techniques attached to families forever."""
    smaller = _bundle([
        {"type": "x-mitre-collection", "id": "c--1", "x_mitre_version": "20.0"},
        _tactic("execution", "Execution"),
        _tech("T1059.001", "PowerShell", ["execution"], sub=True),
        _soft("S0367", "Emotet"),
        _uses("malware--S0367", "attack-pattern--T1059.001"),
    ])
    with get_conn() as conn:
        store(conn, parse_bundle(smaller, FAMILIES))
        conn.commit()
        a = family_attack(conn, "emotet")
    assert {t["id"] for t in a["techniques"]} == {"T1059.001"}, \
        "the previous release's techniques survived the refresh"


def test_the_bundle_url_is_resolved_from_the_index_not_hardcoded():
    """A pinned path is a URL that silently 404s the moment MITRE publishes a new
    version - the exact failure that killed all 35 family trails this week."""
    idx = {"collections": [{"name": "Enterprise ATT&CK", "versions": [
        {"version": "19.2", "url": "https://example.test/enterprise-19.2.json"}]}]}
    assert latest_bundle_url(idx) == "https://example.test/enterprise-19.2.json"
    assert latest_bundle_url({"collections": []}) is None


def test_the_index_shape_with_nested_versions_is_handled():
    idx = {"collections": [{"name": "Enterprise ATT&CK", "versions": {"all": [
        {"version": "19.2", "url": "https://example.test/e.json"}]}}]}
    assert latest_bundle_url(idx) == "https://example.test/e.json"


def test_release_is_none_before_anything_is_loaded():
    with get_conn() as conn:
        conn.execute("DELETE FROM attack_release")
        conn.commit()
        assert release(conn) is None


# -- actors ---------------------------------------------------------------------

def test_an_actor_resolves_through_an_alias(loaded):
    """ATT&CK's names and this library's names rarely match exactly: what the
    library calls "Sandworm" ATT&CK calls "Sandworm Team", and "Evil Corp" is
    "Indrik Spider". Matching on the primary name alone loses most of the
    library, so the alias set is the join."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        # Wizard Spider's own name matches; the alias path is what needs proving,
        # so ask under a name that is only ever an alias.
        direct = actor_attack(conn, "Wizard Spider")
        assert direct["tracked"] and direct["id"] == "G0102"
        # An unrelated primary name plus a matching alias must still resolve.
        aliased = actor_attack(conn, "Some Vendor Codename", ["Wizard Spider"])
        assert aliased["tracked"] and aliased["id"] == "G0102"


def test_an_actor_mitre_does_not_track_says_so(loaded):
    """ATT&CK models 10 of the 13 shipped actors. It does not track LockBit or
    Black Basta as intrusion sets, and it does not track TA542 at all - it
    attributes Emotet to Wizard Spider instead. That is a real disagreement
    between two sources about who runs a botnet, and a platform that silently
    picked one has destroyed the more useful fact."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        a = actor_attack(conn, "TA542", ["Mummy Spider", "Gold Crestwood"])
    assert a["tracked"] is False
    assert a["byTactic"] == [] and a["techniqueCount"] == 0


def test_an_actors_techniques_are_in_kill_chain_order(loaded):
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        a = actor_attack(conn, "APT29")
    assert a["tracked"]
    assert [b["shortname"] for b in a["byTactic"]] == ["initial-access"]


def test_an_actor_only_lists_families_this_engine_imports(loaded):
    """A name that leads nowhere teaches nobody. The families on an actor are
    restricted to the ones the engine actually pulls, so each is a page the
    reader can open rather than a chip that does nothing."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        a = actor_attack(conn, "Wizard Spider")
    assert set(a["families"]) <= set(FAMILIES)
    assert "emotet" in a["families"] and "cobaltstrike" in a["families"]


# -- the triage view -----------------------------------------------------------

def test_the_indicator_brief_is_compact_and_ordered(loaded):
    """An analyst triaging one value is deciding what to do in the next minute.
    Handing them the full technique list there is the same mistake as handing
    them the raw feed - complete, and operationally useless - so the brief
    answers the smaller question: what is going on, and in what order."""
    from dashboard_api.attack import family_brief
    with get_conn() as conn:
        b = family_brief(conn, "emotet")
    assert b is not None
    assert b["id"] == "S0367"
    assert [t["shortname"] for t in b["tactics"]] == ["initial-access", "execution"]
    assert all("techniques" in t and t["techniques"] > 0 for t in b["tactics"])
    # Compact: tactic counts, not the techniques themselves.
    assert not any("techniques" in t and isinstance(t["techniques"], list)
                   for t in b["tactics"])


def test_an_untracked_family_has_no_brief_at_all(loaded):
    """None rather than an empty shape, so the page can stay silent instead of
    rendering a heading with nothing under it."""
    from dashboard_api.attack import family_brief
    with get_conn() as conn:
        assert family_brief(conn, "redline") is None
        assert family_brief(conn, "") is None
        assert family_brief(conn, None) is None


# -- campaigns ------------------------------------------------------------------

CAMPAIGN_FIXTURE = _bundle(FIXTURE["objects"] + [
    {"type": "campaign", "id": "campaign--C0024", "name": "SolarWinds Compromise",
     "aliases": ["SolarWinds Compromise"], "description": "A supply chain intrusion.",
     "first_seen": "2019-08-01T04:00:00.000Z", "last_seen": "2021-01-01T05:00:00.000Z",
     "external_references": [{"source_name": "mitre-attack", "external_id": "C0024",
                              "url": "https://attack.mitre.org/campaigns/C0024"}]},
    {"type": "campaign", "id": "campaign--C9999", "name": "Retired Operation",
     "external_references": [{"source_name": "mitre-attack", "external_id": "C9999",
                              "url": "https://attack.mitre.org/campaigns/C9999"}],
     "x_mitre_deprecated": True},
    {"type": "relationship", "id": "relationship--c1", "relationship_type": "attributed-to",
     "source_ref": "campaign--C0024", "target_ref": "intrusion-set--G0016"},
    {"type": "relationship", "id": "relationship--c2", "relationship_type": "uses",
     "source_ref": "campaign--C0024", "target_ref": "tool--S0154"},
])


@pytest.fixture()
def campaigns():
    parsed = parse_bundle(CAMPAIGN_FIXTURE, FAMILIES)
    with get_conn() as conn:
        store(conn, parsed)
        conn.commit()
    yield parsed
    with get_conn() as conn:
        for t in ("attack_family_technique", "attack_family_group",
                  "attack_group_technique", "attack_software", "attack_technique",
                  "attack_group", "attack_group_name", "attack_campaign_group",
                  "attack_campaign_family", "attack_campaign", "attack_tactic",
                  "attack_release"):
            conn.execute(f"DELETE FROM {t}")
        conn.commit()


def test_an_actor_gets_the_campaigns_mitre_attributes_to_them(campaigns):
    """The section this fills rendered a heading with nothing under it on every
    actor of every live deployment: the library carries no campaign records, and
    only the demo seeder ever added illustrative ones."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        a = actor_attack(conn, "APT29")
    assert a["tracked"]
    assert [c["id"] for c in a["campaigns"]] == ["C0024"]
    c = a["campaigns"][0]
    assert c["name"] == "SolarWinds Compromise"
    assert c["url"].startswith("https://attack.mitre.org/")


def test_a_campaign_carries_a_span_not_a_year(campaigns):
    """A campaign that ran from December 2015 into January 2016 is not a 2015
    campaign, and the reporting behind these supports a month, not a day."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        c = actor_attack(conn, "APT29")["campaigns"][0]
    assert c["firstSeen"] == "2019-08-01"
    assert c["lastSeen"] == "2021-01-01"
    assert "T" not in c["firstSeen"], "a date, not a timestamp"


def test_a_campaign_links_to_the_families_this_engine_imports(campaigns):
    """So a campaign is a way into the store rather than a paragraph."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        c = actor_attack(conn, "APT29")["campaigns"][0]
    assert c["families"] == ["cobaltstrike"]


def test_a_deprecated_campaign_is_not_published(campaigns):
    ids = {c["id"] for c in campaigns["campaigns"]}
    assert "C9999" not in ids


def test_an_actor_with_no_campaigns_gets_an_empty_list_not_an_error(campaigns):
    """Seven of the thirteen shipped actors have none. That is a fact about
    MITRE's coverage, and the page shows the section only when there is
    something in it."""
    from dashboard_api.attack import actor_attack
    with get_conn() as conn:
        assert actor_attack(conn, "Wizard Spider")["campaigns"] == []
        assert actor_attack(conn, "LockBit")["campaigns"] == []


# -- MITRE's prose is STIX, not text --------------------------------------------

def test_a_description_is_not_rendered_as_source_code():
    """ATT&CK descriptions are STIX prose: Markdown links to other ATT&CK pages
    and a trail of (Citation: Vendor-Year) markers. Rendered raw they read as
    source code - "The [2022 Ukraine Electric Power Attack](https://attack.mitre.
    org/campaigns/C0034) was a [Sandworm Team](...) campaign(Citation: X)"."""
    from dashboard_api.attack import _describe
    raw = ("The [2022 Ukraine Electric Power Attack]"
           "(https://attack.mitre.org/campaigns/C0034) was a "
           "[Sandworm Team](https://attack.mitre.org/groups/G0034) campaign."
           "(Citation: Mandiant-2022)(Citation: Dragos-2022)")
    prose, cites = _describe(raw)
    assert prose == ("The 2022 Ukraine Electric Power Attack was a Sandworm Team "
                     "campaign.")
    assert "http" not in prose and "[" not in prose
    assert cites == ["Mandiant-2022", "Dragos-2022"]


def test_the_citations_are_kept_rather_than_deleted():
    """Stripping them outright would be the wrong fix. They are the evidence, and
    a claim without its source is what this platform exists not to publish."""
    from dashboard_api.attack import _describe
    _, cites = _describe("Something happened.(Citation: ESET Industroyer)")
    assert cites == ["ESET Industroyer"]


def test_a_citation_repeated_is_listed_once():
    from dashboard_api.attack import _describe
    _, cites = _describe("A.(Citation: X) B.(Citation: X) C.(Citation: Y)")
    assert cites == ["X", "Y"]


def test_a_description_with_no_citations_yields_none():
    from dashboard_api.attack import _describe
    prose, cites = _describe("Plain sentence with no markers.")
    assert prose == "Plain sentence with no markers."
    assert cites == []


def test_an_empty_description_is_handled():
    from dashboard_api.attack import _describe
    assert _describe(None) == ("", [])
    assert _describe("") == ("", [])
