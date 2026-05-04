#!/usr/bin/env python3
"""Strict OpenAPI conformance gate between yauth (Rust) and yauth-go.

The companion `openapi-diff.py` script is the diagnostic tool — it reports
BREAKING/MISSING as failures and SHAPE/GO-EXTRA as informational. This
script is the **CI gate**: it imports the same diff machinery and fails on
*any* of those categories. A clean run means the two specs agree on every
path, every method, and every top-level request/response field.

Pure byte-equality between the two JSON files is unreachable in practice —
utoipa (Rust) and huma (Go) emit different schema-name conventions
(`ApiKeyResponse` vs `ApiKeyJSON`), nullability styles
(`type: [string, null]` vs `required` arrays), and `additionalProperties`
defaults. Forcing those conventions to match would be a framework rewrite.
External-contract equivalence (paths + methods + top-level field sets) is
the right correctness criterion and what we gate on.

Usage:

    python3 openapi-conformance.py <rust-spec.json> <go-spec.json>
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def _load_diff_module():
    here = Path(__file__).resolve().parent
    spec_path = here / "openapi-diff.py"
    spec = importlib.util.spec_from_file_location("openapi_diff", spec_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {spec_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(rust_path: str, go_path: str) -> int:
    diff = _load_diff_module()
    rust = diff.load_spec(rust_path)
    go = diff.load_spec(go_path)
    must, info = diff.diff_specs(rust, go)

    breaking = [f for f in must if f["category"] == "BREAKING"]
    missing = [f for f in must if f["category"] == "MISSING"]
    shape = [f for f in info if f["category"] == "SHAPE"]
    go_extra = [f for f in info if f["category"] == "GO-EXTRA"]

    blocking_total = len(breaking) + len(missing) + len(shape) + len(go_extra)
    if blocking_total == 0:
        print(
            f"OK: {rust_path} and {go_path} are in conformance "
            f"(0 BREAKING / 0 MISSING / 0 SHAPE / 0 GO-EXTRA)."
        )
        return 0

    # Print the same human-readable report so CI logs explain what to fix.
    sys.stdout.write(diff.render_report(rust_path, go_path, rust, go, must, info))
    print(
        "\nFAIL: spec drift between yauth and yauth-go. Resolve "
        "BREAKING/MISSING/SHAPE/GO-EXTRA above before merging.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            f"usage: {os.path.basename(sys.argv[0])} <rust-openapi.json> <go-openapi.json>",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
