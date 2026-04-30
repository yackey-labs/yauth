#!/usr/bin/env bash
# Run bench.sh + bench-rust.sh + bench-runtime.sh, parse their outputs, and
# write BUILD_PERF.md with side-by-side tables and conclusions.
#
# Usage: bash scripts/bench-compare.sh
# Env:
#   GO_ROOT     default /Users/syackey/steveyackey/yackey-labs/yauth-go
#   RUST_ROOT   default /Users/syackey/steveyackey/yackey-labs/yauth
#   SKIP_RUNTIME=1   skip the runtime/load benchmark
#   SKIP_RUST=1      skip Rust phases entirely
#   BENCH_ITERS=3    iterations per phase
set -uo pipefail

GO_ROOT="${GO_ROOT:-/Users/syackey/steveyackey/yackey-labs/yauth-go}"
RUST_ROOT="${RUST_ROOT:-/Users/syackey/steveyackey/yackey-labs/yauth}"
SCRIPTS="$GO_ROOT/scripts"
ARTIFACTS="$SCRIPTS/bench-output"
BUILD_PERF="$GO_ROOT/BUILD_PERF.md"

mkdir -p "$ARTIFACTS"

GO_OUT="$ARTIFACTS/yauth-go-bench.txt"
RUST_OUT="$ARTIFACTS/yauth-rust-bench.txt"
RUNTIME_OUT="$ARTIFACTS/yauth-runtime-bench.txt"

echo ">>> running Go build/test/lint bench"
bash "$SCRIPTS/bench.sh" "$GO_OUT"

if [[ "${SKIP_RUST:-0}" != "1" ]]; then
    echo ">>> running Rust build/test/lint bench"
    bash "$SCRIPTS/bench-rust.sh" "$RUST_OUT" || echo "(rust bench failed; continuing)"
elif [[ ! -s "$RUST_OUT" ]]; then
    : > "$RUST_OUT"
    echo "## Rust bench skipped (SKIP_RUST=1)" >> "$RUST_OUT"
else
    echo ">>> SKIP_RUST=1 but $RUST_OUT already has data; keeping it"
fi

if [[ "${SKIP_RUNTIME:-0}" != "1" ]]; then
    echo ">>> running runtime/load bench"
    bash "$SCRIPTS/bench-runtime.sh" "$RUNTIME_OUT" || echo "(runtime bench failed; continuing)"
elif [[ ! -s "$RUNTIME_OUT" ]]; then
    : > "$RUNTIME_OUT"
    echo "## Runtime bench skipped (SKIP_RUNTIME=1)" >> "$RUNTIME_OUT"
else
    echo ">>> SKIP_RUNTIME=1 but $RUNTIME_OUT already has data; keeping it"
fi

# ---- Parse + write BUILD_PERF.md ----
python3 "$SCRIPTS/_bench_format.py" "$GO_OUT" "$RUST_OUT" "$RUNTIME_OUT" "$BUILD_PERF"

echo ">>> wrote $BUILD_PERF"
