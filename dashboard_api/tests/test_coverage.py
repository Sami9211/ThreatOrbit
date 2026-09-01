"""Would we see it? The join that two halves of this platform had never made.

The IOC store knows which malware family each of its indicators belongs to.
ATT&CK knows what each of those families does. The detection rules each name the
technique they fire on. Nothing joined the three, so the ATT&CK Navigator - a
page whose entire purpose is answering "are we blind to this?" - was built from a
hand-written dictionary of fourteen techniques, and the only real answer
available to the question was somebody's memory.

Joined against the live store the answer is 61 of 628 technique instances, 9.7%,
with the highest-volume family in the store covered at 5%.

These pin the arithmetic that makes that number honest rather than flattering:
which rules count, how sub-techniques inherit, and that the ranking reflects this
deployment rather than a generic heatmap.
"""
import uuid

import pytest

from dashboard_api.attack import parse_bundle, store
from dashboard_api.coverage import _covered_by, detection_coverage
from dashboard_api.db import get_conn
from dashboard_api.tests.test_attack import FAMILIES, FIXTURE


@pytest.fixture()
def world():
    """ATT&CK loaded, plus indicators and rules we control."""
    tag = uuid.uuid4().hex[:8]
    values = []
    with get_conn() as conn:
        store(conn, parse_bundle(FIXTURE, FAMILIES))
        # Emotet uses T1566 (initial-access) and T1059.001 (execution) in the
        # fixture; Cobalt Strike uses T1071.001.
        for fam, n in (("emotet", 3), ("cobaltstrike", 1)):
            for i in range(n):
                v = f"cov-{tag}-{fam}-{i}.example.test"
                values.append(v)
                conn.execute(
                    "INSERT INTO iocs (id,type,value,severity,confidence,source,"
                    "malware_family,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), "domain", v, "high", 70, "test", fam,
                     "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"))
        conn.commit()
    yield tag
    with get_conn() as conn:
        conn.executemany("DELETE FROM iocs WHERE value=?", [(v,) for v in values])
        conn.execute("DELETE FROM detection_rules WHERE name LIKE ?", (f"covtest-{tag}%",))
        for t in ("attack_family_technique", "attack_family_group",
                  "attack_group_technique", "attack_software", "attack_technique",
                  "attack_group", "attack_group_name", "attack_tactic", "attack_release"):
            conn.execute(f"DELETE FROM {t}")
        conn.commit()


def _rule(tag, technique, status="enabled"):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO detection_rules (id,name,category,severity,mitre_tech_id,status) "
            "VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), f"covtest-{tag}-{technique}", "test", "high",
             technique, status))
        conn.commit()


# -- sub-techniques inherit downward, never sideways ---------------------------

def test_a_parent_rule_covers_its_subtechniques():
    """Detecting "command interpreter execution" catches PowerShell and cmd
    alike, so a rule on T1059 covers T1059.001."""
    assert _covered_by("T1059.001", {"T1059"}) == "T1059"


def test_a_subtechnique_rule_does_not_cover_its_siblings():
    """T1059.001 is PowerShell logging. It says nothing about VBScript, and
    treating it as if it did inflates coverage by exactly the amount that would
    make the number useless."""
    assert _covered_by("T1059.005", {"T1059.001"}) is None


def test_a_subtechnique_rule_does_not_cover_its_parent():
    """Covering one way of doing a thing is not covering the thing."""
    assert _covered_by("T1059", {"T1059.001"}) is None


# -- only rules that would actually fire count ---------------------------------

def test_a_disabled_rule_does_not_count_as_coverage(world):
    """A disabled rule is a rule that does not fire. Counting it is the same
    self-flattery as counting a feed's historical value count while its fetch is
    failing - and this platform has already made that mistake once today.

    Measured as a DELTA: the shipped rule set already covers some of these
    techniques, and an absolute assertion would be a test of the seed data."""
    with get_conn() as conn:
        base = detection_coverage(conn)["covered"]
    _rule(world, "T1566", status="disabled")
    with get_conn() as conn:
        assert detection_coverage(conn)["covered"] == base, "a disabled rule was counted"
    _rule(world, "T1566", status="enabled")
    with get_conn() as conn:
        assert detection_coverage(conn)["covered"] == base + 1


# -- the ranking is about THIS deployment --------------------------------------

def test_families_rank_by_what_this_store_actually_holds(world):
    """A generic ATT&CK heatmap tells every SOC the same thing. The point of
    computing this from the store is that the gap in front of 18,355 indicators
    outranks the gap in front of 20."""
    with get_conn() as conn:
        cov = detection_coverage(conn)
    ours = [f for f in cov["families"] if f["family"] in ("emotet", "cobaltstrike")]
    assert [f["family"] for f in ours] == ["emotet", "cobaltstrike"], \
        "families are not ordered by how much of the store they account for"
    assert ours[0]["indicators"] == 3 and ours[1]["indicators"] == 1


def test_a_gap_names_the_families_behind_it(world):
    """"T1566 is uncovered" is a fact about ATT&CK. "T1566 is uncovered and two
    families in your store use it" is a fact about you, and only the second one
    tells somebody what to do next."""
    with get_conn() as conn:
        cov = detection_coverage(conn)
    gap = next(g for g in cov["gaps"] if g["id"] == "T1566")
    assert "emotet" in gap["families"]
    assert gap["indicators"] >= 3


def test_gaps_are_ordered_by_how_much_of_the_store_they_expose(world):
    with get_conn() as conn:
        cov = detection_coverage(conn)
    vols = [g["indicators"] for g in cov["gaps"]]
    assert vols == sorted(vols, reverse=True)


# -- blind tactics --------------------------------------------------------------

def test_a_family_reports_the_tactics_nothing_covers(world):
    """A percentage is a score; "blind through the whole of Initial Access" is a
    sentence somebody can act on.

    Emotet's only initial-access technique in the fixture is T1566, which the
    shipped rules do not cover (they carry T1566.002, a sibling sub-technique -
    and a sibling covers nothing, which is the point of the test above)."""
    with get_conn() as conn:
        cov = detection_coverage(conn)
    emotet = next(f for f in cov["families"] if f["family"] == "emotet")
    assert "initial-access" in {b["shortname"] for b in emotet["blindTactics"]}, \
        "Initial Access is uncovered and was not reported"


def test_covering_a_tactic_removes_it_from_the_blind_list(world):
    _rule(world, "T1566")
    with get_conn() as conn:
        cov = detection_coverage(conn)
    emotet = next(f for f in cov["families"] if f["family"] == "emotet")
    assert "initial-access" not in {b["shortname"] for b in emotet["blindTactics"]}


# -- it stays honest when there is nothing to say -------------------------------

def test_coverage_never_exceeds_what_there_is_to_cover(world):
    """The arithmetic that stops this being a vanity metric. Every covered
    technique has to be one a family here actually uses, so the fraction can
    never be flattered by counting rules for things nothing in the store does."""
    with get_conn() as conn:
        cov = detection_coverage(conn)
    assert 0 <= cov["covered"] <= cov["techniqueInstances"]
    assert cov["techniqueInstances"] == sum(f["techniques"] for f in cov["families"])
    assert cov["covered"] == sum(f["covered"] for f in cov["families"])


# -- what the store says about itself ------------------------------------------

def test_the_store_summary_reports_how_much_carries_a_behavioural_profile(client, auth):
    """The number that answers "they are just IOCs, a public library has more
    than this engine can import".

    Naming a family is half the job. The half that decides whether an indicator
    is investigable is whether the platform can then say what that family DOES,
    and for the families MITRE describes it can. A value with a kill chain
    attached is a different object from a string on a blocklist, so the store has
    to be able to say how much of it is which.
    """
    s = client.get("/cti/store-summary", headers=auth).json()
    for key in ("profiledByAttack", "profiledShare", "profiledFamilies"):
        assert key in s, f"{key} missing - the store cannot say how much it can explain"
    # A subset of what is named, which is a subset of the store. ATT&CK covers 20
    # of the 35 families the engine imports, so it can never be all of it.
    assert s["profiledByAttack"] <= s["attributedToFamily"] <= s["total"]
    assert 0 <= s["profiledShare"] <= 100
