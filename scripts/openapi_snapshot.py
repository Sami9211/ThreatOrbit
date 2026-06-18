#!/usr/bin/env python3
"""Emit per-release API contract artifacts.

  python scripts/openapi_snapshot.py            # refresh docs/api/v1-paths.json
  python scripts/openapi_snapshot.py --full     # + write the full OpenAPI schema

`docs/api/v1-paths.json` is the stable path surface enforced by
`test_api_contract.py` (a route may not silently disappear). The full
`openapi.json` is a release artifact (FastAPI also serves it live at
`/openapi.json` and renders `/docs`), so it is written only with --full to keep
the repo from carrying a large file that rots between releases.
"""
import json
import os
import sys

os.environ.setdefault("DASHBOARD_DATA_MODE", "demo")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import after env defaults so module-level config picks them up.
from dashboard_api.main import app  # noqa: E402
from dashboard_api.api_versioning import API_VERSION, stable_paths  # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "api")


def main(argv: list[str]) -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    paths = stable_paths(app)
    with open(os.path.join(OUT_DIR, f"{API_VERSION}-paths.json"), "w") as fh:
        json.dump({"version": API_VERSION, "paths": paths}, fh, indent=2)
        fh.write("\n")
    print(f"wrote {len(paths)} stable paths → docs/api/{API_VERSION}-paths.json")
    if "--full" in argv:
        schema = app.openapi()
        with open(os.path.join(OUT_DIR, "openapi.json"), "w") as fh:
            json.dump(schema, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote OpenAPI {schema['info']['version']} ({len(schema.get('paths', {}))} paths)"
              " → docs/api/openapi.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
