"""A deployed frontend is routinely newer than the backend it is talking to.

Found on a preview deployment. The malware family page did:

    <AttackPanel a={d.attack} ... />          // AttackPanel: if (!a.tracked)

`attack` is a field the API only started sending today. Against any backend that
predates it - a preview build pointed at production, a rolling deploy, a cached
response - `d.attack` is `undefined`, `a.tracked` throws, and React unmounts the
whole route:

    Cannot read properties of undefined (reading 'tracked')

A blank page, on the page that has the most to say. Reproduced by serving the
built frontend against a proxy that strips every field added today: both family
pages threw, and every other page was fine.

The type was the root cause. TypeScript describes the code that CALLS the API;
it says nothing about the JSON that ARRIVES, so a field typed as required is a
field nobody guards. Marking the new fields optional turned the compiler into
the thing that insists on the guard - it immediately found two more unguarded
reads that had been shipped.

These tests pin both halves, because either one alone lets the crash back in.
"""
import pathlib

import pytest

_FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"


def _read(rel: str) -> str:
    return (_FRONTEND / rel).read_text()


@pytest.fixture(scope="module")
def api_types() -> str:
    return _read("lib/api.ts")


# -- the guard ------------------------------------------------------------------

def test_the_attack_panel_tolerates_a_missing_profile():
    """The specific crash. A panel that dereferences its prop before checking it
    exists takes the entire route down when the field is absent."""
    src = _read("components/dashboard/AttackPanel.tsx")
    assert "if (!a?.tracked)" in src, (
        "AttackPanel dereferences `a` without an optional chain - a backend that "
        "does not send `attack` white-screens the family page")
    assert "a?: AttackProfile | null" in src, \
        "the prop must be typed optional, or callers are not forced to think about it"


def test_the_panel_does_not_iterate_a_possibly_absent_array():
    """`byTactic` arrives from the same payload and can be absent on its own -
    a partial response is not the same thing as no response."""
    src = _read("components/dashboard/AttackPanel.tsx")
    assert "a.byTactic ?? []" in src, "byTactic is mapped without a fallback"


# -- the root cause -------------------------------------------------------------

@pytest.mark.parametrize("field", [
    "attack?: AttackProfile",
    "attackRelease?: AttackRelease | null",
    "profiledByAttack?: number",
    "profiledShare?: number",
    "profiledFamilies?: number",
    "techniqueCount?: number",
    "byTactic?: Array<{",
])
def test_fields_the_server_may_not_send_are_typed_optional(api_types, field):
    """Required is a promise about the wire that TypeScript cannot keep.

    Every field here was added to the API today. Any deployment whose backend is
    even one release behind sends a payload without it, and a required type means
    no call site guards it. Optional makes the compiler do the arguing.
    """
    assert field in api_types, (
        f"`{field}` is not marked optional - a backend that predates it will "
        f"crash the page that reads it")


def test_the_new_dereferences_are_guarded():
    """The two the compiler caught the moment these fields became optional, plus
    the ones found by sweeping the same day's diff."""
    checks = [
        ("app/dashboard/cti/actors/page.tsx", "(attack.techniqueCount ?? 0)"),
        ("app/dashboard/cti/actors/page.tsx", "(c.families ?? []).map"),
        ("app/dashboard/cti/actors/page.tsx", "(c.citations?.length ?? 0) > 0"),
        ("components/dashboard/StoreCompositionPanel.tsx", "(s.profiledByAttack ?? 0) > 0"),
        ("components/dashboard/StoreCompositionPanel.tsx", "(s.profiledByAttack ?? 0).toLocaleString()"),
        ("app/dashboard/siem/attack/page.tsx", "(cov.tactics ?? []).map"),
        ("app/dashboard/cti/indicator/[value]/page.tsx", "detail?.familyBrief?.tactics?.length"),
    ]
    missing = [f"{path}: {needle}" for path, needle in checks if needle not in _read(path)]
    assert not missing, "unguarded reads of fields an older API will not send: " + "; ".join(missing)
