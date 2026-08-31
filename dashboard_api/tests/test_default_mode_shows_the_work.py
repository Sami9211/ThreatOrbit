"""The default mode has to show what the platform actually knows.

The app defaults to Normal mode. Two information architectures are maintained in
parallel here - the plan lists that duality as something to remove, and calls it
"the reason the SIEM funnel fix was invisible until I found the right tab". This
file fences the specific version of that failure that keeps happening: work
lands, and it lands only in the mode most people never switch to.

The measured case: the store can name 178,873 of its 499,501 indicators, and the
panel reporting that - along with corroboration, belief distribution, and how
much has been seen on this deployment's own network - was Power-only. The
500k-row list belongs behind a toggle. The verdict on whether the intelligence
is any good does not.
"""
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2] / "frontend"


def _cti_page() -> str:
    return (ROOT / "app/dashboard/cti/page.tsx").read_text()


def _normal_view(page: str) -> str:
    """The NormalCTI component's body, up to the page component after it."""
    start = page.index("function NormalCTI()")
    end = page.index("export default function CTIPage()")
    return page[start:end]


def test_the_store_panel_is_not_power_only():
    normal = _normal_view(_cti_page())
    assert "<StoreCompositionPanel />" in normal, (
        "the answer to 'is this intelligence any good' is hidden in the mode "
        "the app defaults to")


def test_the_default_mode_reports_what_the_store_can_name():
    """Attribution is the difference between an indicator you can investigate
    and one you can only block, so it belongs on the tile strip a Normal-mode
    reader sees first."""
    normal = _normal_view(_cti_page())
    assert "attributedToFamily" in normal


def test_a_tile_that_is_always_zero_is_not_a_tile():
    """"Campaigns" read 0 on every live deployment - the actor library carries
    no campaign records, so the number never moved. A metric that cannot change
    teaches nobody anything and costs a quarter of the strip."""
    normal = _normal_view(_cti_page())
    # The TILE, not the word - the comment explaining its removal mentions it,
    # and a guard that matches its own rationale is a guard that never fails.
    assert "label: 'Campaigns'" not in normal


@pytest.mark.parametrize("field", ["attributedToFamily", "topFamilies"])
def test_the_summary_endpoint_supplies_it(client, auth, field):
    body = client.get("/cti/summary", headers=auth).json()
    assert field in body, f"/cti/summary does not return {field}"
