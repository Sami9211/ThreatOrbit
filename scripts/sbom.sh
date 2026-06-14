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
( cd "$ROOT/frontend" && npm ci --silent \
    && npx --yes @cyclonedx/cyclonedx-npm@latest --output-file "$ROOT/$OUT/frontend.cdx.json" )

echo "==> done:"
ls -1 "$ROOT/$OUT"/*.cdx.json
