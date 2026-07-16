"""Single source of truth for the product version.

Bump PRODUCT_VERSION when cutting a release (the release workflow fires on
``v*`` tags - keep the tag and this constant in step). Everything that needs
to report "what build is this?" - the /platform/about endpoint, support
bundles, future update checks - reads it from here so the answer can never
drift between surfaces.
"""
from __future__ import annotations

import os
from pathlib import Path

PRODUCT_VERSION = "1.0.0-beta.1"


def _resolve_git_sha() -> str | None:
    """Best-effort commit identity, without shelling out.

    Order: the GIT_SHA env var (deploy pipelines bake it into the image /
    environment), then the checkout's .git metadata when running from a git
    working copy. Returns None when neither exists (e.g. a Docker image built
    from a source archive) - the API reports null rather than inventing one.
    """
    env = os.environ.get("GIT_SHA", "").strip()
    if env:
        return env[:12]
    try:
        git_dir = Path(__file__).resolve().parent.parent / ".git"
        head = (git_dir / "HEAD").read_text().strip()
        if head.startswith("ref:"):
            ref = head.split(None, 1)[1]
            ref_file = git_dir / ref
            if ref_file.exists():
                return ref_file.read_text().strip()[:12]
            packed = git_dir / "packed-refs"
            if packed.exists():
                for line in packed.read_text().splitlines():
                    if line.endswith(" " + ref):
                        return line.split(" ", 1)[0][:12]
            return None
        return head[:12]
    except OSError:
        return None


GIT_SHA = _resolve_git_sha()
