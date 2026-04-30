#!/usr/bin/env python3
"""Cross-language OpenAPI conformance diff.

Reads two openapi.json paths from argv and emits a markdown report comparing
the Rust (yauth) spec against the Go (yauth-go) spec.

Findings are categorised:

- BREAKING: a path exists in Rust but not in Go (Go is missing a route the
  Rust crate publishes — a real divergence in feature coverage).
- MISSING : a path+method (operation) exists in Rust but not in Go.
- SHAPE   : top-level request or response schema fields differ between the
  two specs for the same operation. Informational only — yauth-go intentionally
  diverges on shape decisions (e.g. wrapped pagination metadata over bare
  arrays, {user: {...}} envelopes for forward compatibility). Feature parity
  is required; shape parity is not.
- DOC     : description/summary-only differences (informational).

Anything in Go that is not in Rust is *not* a breaking finding — yauth-go is
intentionally a "Go superset" and may add routes the Rust crate has not
shipped yet. Those show up as INFO entries so reviewers can see the delta.

Exit code is non-zero iff any BREAKING or MISSING gap is found. SHAPE
divergences are reported but do not fail the check.

Usage:
    python3 scripts/openapi-diff.py <rust-openapi.json> <go-openapi.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


HTTP_METHODS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}


def load_spec(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        sys.stderr.write(f"openapi-diff: file not found: {path}\n")
        sys.exit(2)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def operations(spec: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Flatten paths -> {(path, method): operation}."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(op, dict):
                continue
            out[(path, method.lower())] = op
    return out


def resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a local $ref of the form '#/components/schemas/Foo'."""
    if not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node if isinstance(node, dict) else {}


def schema_top_level_fields(
    spec: dict[str, Any], schema: dict[str, Any] | None
) -> set[str]:
    """Return the set of top-level property names for a schema, resolving
    a single layer of $ref. Deliberately shallow — we don't drill into
    nested objects."""
    if not schema:
        return set()
    if "$ref" in schema:
        schema = resolve_ref(spec, schema["$ref"])
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        return set(props.keys())
    return set()


def request_body_schema(
    spec: dict[str, Any], op: dict[str, Any]
) -> dict[str, Any] | None:
    rb = op.get("requestBody")
    if not isinstance(rb, dict):
        return None
    content = rb.get("content")
    if not isinstance(content, dict):
        return None
    json_ct = content.get("application/json")
    if not isinstance(json_ct, dict):
        return None
    schema = json_ct.get("schema")
    return schema if isinstance(schema, dict) else None


def success_response_schema(
    spec: dict[str, Any], op: dict[str, Any]
) -> dict[str, Any] | None:
    responses = op.get("responses")
    if not isinstance(responses, dict):
        return None
    # Prefer 200, then 201, then any 2xx
    for code in ("200", "201"):
        resp = responses.get(code)
        if isinstance(resp, dict):
            content = resp.get("content")
            if isinstance(content, dict):
                json_ct = content.get("application/json")
                if isinstance(json_ct, dict):
                    schema = json_ct.get("schema")
                    if isinstance(schema, dict):
                        return schema
    for code, resp in responses.items():
        if not (isinstance(code, str) and code.startswith("2")):
            continue
        if not isinstance(resp, dict):
            continue
        content = resp.get("content")
        if not isinstance(content, dict):
            continue
        json_ct = content.get("application/json")
        if isinstance(json_ct, dict):
            schema = json_ct.get("schema")
            if isinstance(schema, dict):
                return schema
    return None


def diff_specs(
    rust: dict[str, Any], go: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (must_findings, info_findings).

    must_findings  -> drive non-zero exit (BREAKING, MISSING).
    info_findings  -> reported but not failing (SHAPE, DOC, Go-extra).

    SHAPE divergences are reported as informational because yauth-go
    intentionally diverges on shape decisions (wrapped pagination over
    bare arrays, {user: {...}} envelopes, etc.) for forward
    compatibility. Feature parity is required; shape parity is not.
    """
    must: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []

    rust_paths = set((rust.get("paths") or {}).keys())
    go_paths = set((go.get("paths") or {}).keys())

    for p in sorted(rust_paths - go_paths):
        must.append(
            {
                "category": "BREAKING",
                "path": p,
                "detail": "path present in Rust spec but missing in Go spec",
            }
        )

    for p in sorted(go_paths - rust_paths):
        info.append(
            {
                "category": "GO-EXTRA",
                "path": p,
                "detail": "path present in Go spec only (Go superset)",
            }
        )

    rust_ops = operations(rust)
    go_ops = operations(go)

    for key in sorted(rust_ops.keys() - go_ops.keys()):
        path, method = key
        if path not in go_paths:
            continue  # already reported as BREAKING
        must.append(
            {
                "category": "MISSING",
                "path": path,
                "method": method.upper(),
                "detail": "operation present in Rust spec but missing in Go spec",
            }
        )

    for key in sorted(go_ops.keys() - rust_ops.keys()):
        path, method = key
        if path not in rust_paths:
            continue  # already reported as GO-EXTRA at path level
        info.append(
            {
                "category": "GO-EXTRA",
                "path": path,
                "method": method.upper(),
                "detail": "operation present in Go spec only",
            }
        )

    for key in sorted(rust_ops.keys() & go_ops.keys()):
        path, method = key
        rop = rust_ops[key]
        gop = go_ops[key]

        rust_req = schema_top_level_fields(rust, request_body_schema(rust, rop))
        go_req = schema_top_level_fields(go, request_body_schema(go, gop))
        if rust_req or go_req:
            only_rust = rust_req - go_req
            only_go = go_req - rust_req
            if only_rust or only_go:
                info.append(
                    {
                        "category": "SHAPE",
                        "path": path,
                        "method": method.upper(),
                        "detail": "request body top-level fields diverge",
                        "only_in_rust": sorted(only_rust),
                        "only_in_go": sorted(only_go),
                    }
                )

        rust_resp = schema_top_level_fields(rust, success_response_schema(rust, rop))
        go_resp = schema_top_level_fields(go, success_response_schema(go, gop))
        if rust_resp or go_resp:
            only_rust = rust_resp - go_resp
            only_go = go_resp - rust_resp
            if only_rust or only_go:
                info.append(
                    {
                        "category": "SHAPE",
                        "path": path,
                        "method": method.upper(),
                        "detail": "success response top-level fields diverge",
                        "only_in_rust": sorted(only_rust),
                        "only_in_go": sorted(only_go),
                    }
                )

        rust_desc = (rop.get("description") or "").strip()
        go_desc = (gop.get("description") or "").strip()
        rust_sum = (rop.get("summary") or "").strip()
        go_sum = (gop.get("summary") or "").strip()
        if (rust_desc and go_desc and rust_desc != go_desc) or (
            rust_sum and go_sum and rust_sum != go_sum
        ):
            info.append(
                {
                    "category": "DOC",
                    "path": path,
                    "method": method.upper(),
                    "detail": "description or summary differs",
                }
            )

    return must, info


def render_report(
    rust_path: str,
    go_path: str,
    rust: dict[str, Any],
    go: dict[str, Any],
    must: list[dict[str, Any]],
    info: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# OpenAPI Conformance Report")
    lines.append("")
    lines.append(f"- Rust spec: `{rust_path}` (version `{rust.get('info', {}).get('version', '?')}`)")
    lines.append(f"- Go spec:   `{go_path}` (version `{go.get('info', {}).get('version', '?')}`)")
    lines.append("")
    lines.append(
        f"Rust paths: **{len(rust.get('paths') or {})}** · "
        f"Go paths: **{len(go.get('paths') or {})}**"
    )
    lines.append("")
    lines.append("Anything Rust exposes that Go does not is a real divergence we need to")
    lines.append("close. Routes that exist only in Go are listed for transparency but do")
    lines.append("not fail the check (yauth-go is intentionally a Go superset).")
    lines.append("")

    breaking = [f for f in must if f["category"] == "BREAKING"]
    missing = [f for f in must if f["category"] == "MISSING"]
    shape = [f for f in info if f["category"] == "SHAPE"]
    go_extra = [f for f in info if f["category"] == "GO-EXTRA"]
    doc = [f for f in info if f["category"] == "DOC"]

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- BREAKING (path missing in Go): **{len(breaking)}**")
    lines.append(f"- MISSING (operation missing in Go): **{len(missing)}**")
    lines.append(f"- SHAPE (request/response field divergence, informational): **{len(shape)}**")
    lines.append(f"- DOC (description-only diffs): **{len(doc)}**")
    lines.append(f"- GO-EXTRA (Go-only routes/operations, informational): **{len(go_extra)}**")
    lines.append("")

    def section(title: str, items: list[dict[str, Any]]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        if not items:
            lines.append("_None._")
            lines.append("")
            return
        for f in items:
            method = f.get("method")
            path = f.get("path", "")
            head = f"- **{method} {path}**" if method else f"- **{path}**"
            lines.append(f"{head} — {f['detail']}")
            if f.get("only_in_rust"):
                lines.append(f"  - only in Rust: `{', '.join(f['only_in_rust'])}`")
            if f.get("only_in_go"):
                lines.append(f"  - only in Go: `{', '.join(f['only_in_go'])}`")
        lines.append("")

    section("BREAKING — paths missing in Go", breaking)
    section("MISSING — operations missing in Go", missing)
    section("SHAPE — request/response top-level field differences", shape)
    section("DOC — description-only differences", doc)
    section("GO-EXTRA — Go-only routes (informational)", go_extra)

    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write(
            "usage: openapi-diff.py <rust-openapi.json> <go-openapi.json>\n"
        )
        return 2
    rust_path, go_path = argv[1], argv[2]
    rust = load_spec(rust_path)
    go = load_spec(go_path)
    must, info = diff_specs(rust, go)
    sys.stdout.write(render_report(rust_path, go_path, rust, go, must, info))
    return 1 if must else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
