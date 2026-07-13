"""Risk-scoring consistency fences.

The asset list shows the *stored* score (`asset_risk`); the detail panel shows
`risk_breakdown`, which claims to explain that same score. They used to diverge:
`risk_breakdown` summed per-axis contributions each rounded to 1 decimal, while
`asset_risk` rounded the exact weighted sum once — a drift of up to ~0.2 that was
enough to cross a band boundary (an asset reading "at-risk" in the list but
"clean" in its own breakdown). `risk_breakdown` now derives its headline score
from `asset_risk`, so the two can never disagree.
"""
from dashboard_api import scoring as s


def test_breakdown_score_matches_stored_for_known_band_crossing():
    """The exact input that used to score 45/at-risk stored but 44/clean in the
    breakdown — now identical."""
    kw = dict(
        cves={"critical": 0, "high": 0, "medium": 0, "low": 1},
        criticality="critical", patch_age=39, open_alerts=8,
        open_ports=[3389, 445, 23, 1433], tags=["internet-facing"],
    )
    stored = s.asset_risk(**kw)
    bd = s.risk_breakdown(**kw)
    assert bd["score"] == stored
    assert bd["band"] == s.risk_band(stored)
    assert bd["band"] == "at-risk"


def test_breakdown_never_disagrees_with_stored_score():
    """Sweep realistic inputs: the breakdown headline score and band always equal
    the stored asset_risk score and its band."""
    crits = ["critical", "high", "medium", "low"]
    checked = 0
    for crit in crits:
        for ncrit in range(0, 6):
            for nhigh in range(0, 6):
                for patch in range(0, 200, 11):
                    for alerts in range(0, 10, 2):
                        for internet in (True, False):
                            for nports in range(0, 4):
                                kw = dict(
                                    cves={"critical": ncrit, "high": nhigh, "medium": 2, "low": 1},
                                    criticality=crit, patch_age=patch, open_alerts=alerts,
                                    open_ports=[3389, 445, 23, 1433][:nports],
                                    tags=["internet-facing"] if internet else [],
                                )
                                stored = s.asset_risk(**kw)
                                bd = s.risk_breakdown(**kw)
                                assert bd["score"] == stored, kw
                                assert bd["band"] == s.risk_band(stored), kw
                                checked += 1
    assert checked > 5000  # the fence actually swept a broad space


def test_breakdown_components_are_bounded_and_complete():
    bd = s.risk_breakdown(
        cves={"critical": 3, "high": 2, "medium": 1, "low": 0},
        criticality="high", patch_age=90, open_alerts=4,
        open_ports=[3389], tags=["internet-facing"],
    )
    axes = {c["axis"] for c in bd["components"]}
    assert axes == {"vulnerability", "exposure", "patch", "alerts"}
    for c in bd["components"]:
        assert 0.0 <= c["value"] <= 100.0
        assert c["contribution"] >= 0.0
    assert 0 <= bd["score"] <= 100
    # components are sorted by contribution, descending
    contribs = [c["contribution"] for c in bd["components"]]
    assert contribs == sorted(contribs, reverse=True)
