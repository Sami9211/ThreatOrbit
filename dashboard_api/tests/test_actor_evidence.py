"""Actors: real counts, real dates, and two malware relationships kept apart.

Three things this file holds.

**Nobody's birthday is invented.** Every actor row used to be written with
`first_seen = 2014-01-01` - a constant, in live deployments as well as demo - so
the platform stated that Volt Typhoon (first reported 2021) and Scattered Spider
(2022) had both been active since January 2014. A constant presented as a date
is not a placeholder a reader can see through; it is a fact the platform made
up. The demo seeder then overwrote it with a RANDOM year, which was worse.

**A count has to be evidenced.** Ten tracked actors sat at zero indicators
because nothing in a blocklist names an adversary. Three now have real numbers,
and they come from exactly one link: a malware family whose SOLE named operator
is that group. Emotet's C2s are TA542's infrastructure in the same sense that
the catalogue's `operator` field asserts - which is why that field is set on
three families out of thirty-five.

**Reported use is not operation.** Black Basta used QakBot, and this store holds
thousands of QakBot indicators of which almost none are theirs, because QakBot
was distributed by several affiliates. Counting those would hand the actor page
a large, confident, wrong number. Both lists are returned; neither is summed
into the other.
"""
import uuid

import pytest

from dashboard_api import malware
from dashboard_api.db import get_conn
from dashboard_api.threat_actor_library import (
    ACTOR_LIBRARY, ACTOR_NAMES, _PLACEHOLDER_FIRST_SEEN,
    correct_placeholder_first_seen, operated_families, recompute_actor_activity,
    seed_actor_library)


@pytest.fixture(autouse=True)
def _clean():
    with get_conn() as conn:
        before = {r["id"] for r in conn.execute("SELECT id FROM iocs").fetchall()}
    yield
    with get_conn() as conn:
        for r in conn.execute("SELECT id FROM iocs").fetchall():
            if r["id"] not in before:
                conn.execute("DELETE FROM iocs WHERE id=?", (r["id"],))
        recompute_actor_activity(conn)
        conn.commit()


# -- dates ------------------------------------------------------------------------

def test_no_actor_shares_one_invented_start_date():
    years = [a["since"] for a in ACTOR_LIBRARY]
    assert all(y and y.isdigit() and 1990 < int(y) < 2100 for y in years), years
    assert len(set(years)) > 4, "every actor cannot have been first reported in the same year"
    assert _PLACEHOLDER_FIRST_SEEN not in years


def test_the_groups_reported_most_recently_say_so():
    since = {a["name"]: a["since"] for a in ACTOR_LIBRARY}
    assert since["Scattered Spider"] == "2022"
    assert since["Volt Typhoon"] == "2021"
    assert since["APT29"] < since["Scattered Spider"]


def test_a_row_still_holding_the_placeholder_is_repaired():
    with get_conn() as conn:
        conn.execute("UPDATE threat_actors SET first_seen=? WHERE name='Volt Typhoon'",
                     (_PLACEHOLDER_FIRST_SEEN,))
        conn.commit()
        fixed = correct_placeholder_first_seen(conn)
        conn.commit()
        row = conn.execute(
            "SELECT first_seen FROM threat_actors WHERE name='Volt Typhoon'").fetchone()
    assert fixed >= 1
    assert row["first_seen"] == "2021"


def test_an_operators_own_date_is_left_alone():
    """Only the exact constant is unambiguously ours to overwrite."""
    with get_conn() as conn:
        conn.execute("UPDATE threat_actors SET first_seen='1999' WHERE name='APT41'")
        conn.commit()
        correct_placeholder_first_seen(conn)
        conn.commit()
        row = conn.execute("SELECT first_seen FROM threat_actors WHERE name='APT41'").fetchone()
        assert row["first_seen"] == "1999"
        conn.execute("UPDATE threat_actors SET first_seen='2012' WHERE name='APT41'")
        conn.commit()


def test_the_demo_seeder_no_longer_randomises_the_year():
    import inspect
    from dashboard_api import seed as seed_mod
    src = inspect.getsource(seed_mod._seed_actors)
    assert "first_seen=?" not in src, (
        "demo flavour may add texture; it must not replace something true with "
        "something invented")


# -- counts -----------------------------------------------------------------------

def test_operating_a_family_is_the_only_link_that_counts():
    with get_conn() as conn:
        ops = operated_families(conn)
    assert ops == {"TA542": ["emotet"], "Wizard Spider": ["trickbot"],
                   "Evil Corp": ["dridex"]}, ops
    # And it agrees with the catalogue rather than being a second opinion.
    for actor, families in ops.items():
        for f in families:
            assert malware.CATALOGUE[f]["operator"] == actor


def test_an_operated_familys_indicators_count_toward_its_operator():
    marker = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        before = conn.execute(
            "SELECT ioc_count FROM threat_actors WHERE name='TA542'").fetchone()["ioc_count"]
        for i in range(5):
            insert_ioc(conn, type="domain", value=f"{marker}-{i}.example.test",
                       source="osint:trails", malware_family="emotet")
        recompute_actor_activity(conn)
        conn.commit()
        row = conn.execute(
            "SELECT ioc_count, active FROM threat_actors WHERE name='TA542'").fetchone()
    assert row["ioc_count"] == before + 5
    assert row["active"] == 1


def test_a_family_an_actor_merely_uses_is_not_counted():
    """QakBot is not Black Basta's. Several affiliates distributed it, so an
    indicator carrying it says which malware, not whose campaign.

    Measured as a DELTA: the demo seeder attributes indicators to actor names
    directly, so an absolute zero would be testing the fixture rather than the
    rule."""
    marker = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        recompute_actor_activity(conn)
        before = conn.execute(
            "SELECT ioc_count FROM threat_actors WHERE name='Black Basta'").fetchone()["ioc_count"]
        for i in range(9):
            insert_ioc(conn, type="domain", value=f"{marker}-qb-{i}.example.test",
                       source="osint:trails", malware_family="qakbot")
        recompute_actor_activity(conn)
        conn.commit()
        after = conn.execute(
            "SELECT ioc_count FROM threat_actors WHERE name='Black Basta'").fetchone()["ioc_count"]
    assert after == before, (
        "reported use was counted as ownership - that is how an actor page gets "
        "a large, confident, wrong number")


def test_an_actor_counts_only_what_a_source_named_it_on():
    """`active` and `ioc_count` are derived, never stored as flavour: an actor
    with nothing attributed to it reads zero and inactive."""
    with get_conn() as conn:
        conn.execute("UPDATE iocs SET actor='' WHERE actor='Sandworm'")
        recompute_actor_activity(conn)
        conn.commit()
        row = conn.execute(
            "SELECT ioc_count, active FROM threat_actors WHERE name='Sandworm'").fetchone()
    assert row["ioc_count"] == 0 and row["active"] == 0


def test_the_library_is_idempotent():
    with get_conn() as conn:
        assert seed_actor_library(conn) == 0
        n = conn.execute("SELECT COUNT(*) AS n FROM threat_actors").fetchone()["n"]
    assert n >= len(ACTOR_NAMES)


# -- the API -----------------------------------------------------------------------

def test_the_actor_endpoint_separates_operation_from_use(client, auth):
    marker = uuid.uuid4().hex[:8]
    actors = {a["name"]: a for a in client.get("/cti/actors", headers=auth).json()}
    ta_id, bb_id = actors["TA542"]["id"], actors["Black Basta"]["id"]
    with get_conn() as conn:
        recompute_actor_activity(conn)
        conn.commit()
    ta_before = client.get(f"/cti/actors/{ta_id}", headers=auth).json()["ioc_count"]
    bb_before = client.get(f"/cti/actors/{bb_id}", headers=auth).json()["ioc_count"]

    with get_conn() as conn:
        from dashboard_api.ioc_store import insert_ioc
        # One of each: a family TA542 OPERATES, and one Black Basta merely USES.
        insert_ioc(conn, type="domain", value=f"{marker}-e.example.test",
                   source="osint:trails", malware_family="emotet")
        insert_ioc(conn, type="domain", value=f"{marker}-q.example.test",
                   source="osint:trails", malware_family="qakbot")
        recompute_actor_activity(conn)
        conn.commit()

    ta = client.get(f"/cti/actors/{ta_id}", headers=auth).json()
    assert [m["family"] for m in ta["operatedMalware"]] == ["emotet"]
    assert ta["operatedMalware"][0]["indicators"] >= 1
    assert ta["reportedMalware"] == [], "a family already stated as theirs must not repeat"
    assert ta["ioc_count"] == ta_before + 1, "operating it must count"

    bb = client.get(f"/cti/actors/{bb_id}", headers=auth).json()
    assert bb["operatedMalware"] == []
    held = next(m for m in bb["reportedMalware"] if m["family"] == "qakbot")
    assert held["indicators"] >= 1, "the store holds it, so the page should say so"
    assert bb["ioc_count"] == bb_before, (
        "merely using it must not count - that is how an actor page gets a "
        "large, confident, wrong number")


def test_a_family_page_can_reach_its_operator(client, auth):
    d = client.get("/cti/malware/emotet", headers=auth).json()
    assert d["operator"] == "TA542"
    assert d["operatorActorId"], "the operator is a name with nowhere to click"
    actor = client.get(f"/cti/actors/{d['operatorActorId']}", headers=auth).json()
    assert actor["name"] == "TA542"


def test_an_unoperated_family_offers_no_actor_link(client, auth):
    d = client.get("/cti/malware/asyncrat", headers=auth).json()
    assert d["operator"] is None and d["operatorActorId"] is None


def test_the_operator_link_lands_somewhere_that_opens_the_actor():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2] / "frontend"
    family = (root / "app/dashboard/cti/malware/[family]/page.tsx").read_text()
    assert "/dashboard/cti/actors?actor=" in family
    actors = (root / "app/dashboard/cti/actors/page.tsx").read_text()
    assert "get('actor')" in actors, "the actors page must honour ?actor="
    assert "operatedMalware" in actors and "reportedMalware" in actors, \
        "both relationships have to be rendered, and rendered apart"


def test_the_panel_shows_no_empty_headings():
    """A heading with nothing under it reads as a broken panel, not as "we have
    none". On a live deployment the actor library carries no campaign records
    and no pinned indicators, so three sections rendered as bare titles on every
    actor - and one of them, "Recent Activity", printed the description a second
    time under a label that promised something else."""
    import pathlib
    page = (pathlib.Path(__file__).resolve().parents[2]
            / "frontend/app/dashboard/cti/actors/page.tsx").read_text()
    assert "{actor.campaigns.length > 0 && (" in page, \
        "Known Campaigns renders even when there are none"
    assert "actor.iocs.length > 0 ||" in page, \
        "Associated IOCs renders even when there are none"
    assert "recentActivity: a.description" not in page, \
        "the description was being rendered twice, once under the wrong heading"
    assert "Activity in this deployment" in page, \
        "the section must report what this store actually holds"
