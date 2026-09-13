#!/usr/bin/env bash
# Generate CycloneDX SBOMs for the whole product:
#   - backend: the resolved Python environment (all three services' deps)
#   - frontend: the npm dependency tree
# Used locally (`bash scripts/sbom.sh`) and by .github/workflows/supply-chain.yml.
set -euo pipefail

OUT="${1:-sbom}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/$OUT"

echo "==> backend SBOM (resolved Python environment)"
python -m pip install -q cyclonedx-bom
python -m pip install -q -r "$ROOT/dashboard_api/requirements.txt" \
                          -r "$ROOT/threat_api/requirements.txt" \
                          -r "$ROOT/log_api/requirements.txt"
cyclonedx-py environment -o "$ROOT/$OUT/backend.cdx.json"

echo "==> frontend SBOM (npm tree)"
# `npm ls` problems are REPORTED but do not fail the inventory. cyclonedx-npm
# shells out to `npm ls --json --long --all`, which exits non-zero for anything
# in the ELSPROBLEMS family - including "extraneous", which is cosmetic here.
# sharp 0.35.4 ships an `@img/sharp-wasm32` that npm installs and then cannot
# attribute to a dependency edge; it is extraneous on a clean regenerate, with
# the override at ^0.35.0 or ^0.35.4 alike, so it is upstream packaging rather
# than anything this repo chose.
#
# Tolerating it here is not the same as ignoring dependency health: that is the
# npm-audit gate in security.yml and Trivy below. This job's job is to produce
# an inventory. The problems are echoed first so they stay visible in the log
# instead of being swallowed by a flag.
( cd "$ROOT/frontend" && npm ci --silent \
    && { echo "--- npm ls problems (non-fatal, inventory only) ---"; \
         npm ls --all >/dev/null 2>&1 || npm ls --all 2>&1 | grep -E "^npm (error|warn)" | head -20 || true; } \
    && npx --yes @cyclonedx/cyclonedx-npm@latest --ignore-npm-errors \
         --output-file "$ROOT/$OUT/frontend.cdx.json" )

echo "==> done:"
ls -1 "$ROOT/$OUT"/*.cdx.json
