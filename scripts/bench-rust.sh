#!/usr/bin/env bash
# Symmetric to bench.sh but runs against the Rust yauth workspace.
# Same /usr/bin/time format; same phases (cold build / warm build / vet-equiv / lint / test).
#
# Note: Rust does not have a separate "vet" pass — `cargo check` is the closest
# (typecheck without codegen), so we run cargo check in that slot. The compare
# script lines this up against `go vet`.
set -uo pipefail

RUST_ROOT="${RUST_ROOT:-/Users/syackey/steveyackey/yackey-labs/yauth}"
OUT="${1:-/tmp/yauth-rust-bench.txt}"
TIME=/usr/bin/time
ITERS="${BENCH_ITERS:-3}"
FEATURES="${RUST_FEATURES:-full,all-backends}"

if [[ ! -d "$RUST_ROOT" ]]; then
    echo "RUST_ROOT not found: $RUST_ROOT" >&2
    exit 2
fi
cd "$RUST_ROOT"

mkdir -p "$(dirname "$OUT")"
: > "$OUT"

uname_s="$(uname -s)"
case "$uname_s" in
    Darwin)
        cpus="$(sysctl -n hw.physicalcpu 2>/dev/null || echo 0)"
        mem_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
        ;;
    *)
        cpus="$(nproc 2>/dev/null || echo 0)"
        mem_bytes="$(awk '/MemTotal/ {print $2*1024}' /proc/meminfo 2>/dev/null || echo 0)"
        ;;
esac

{
    echo "## yauth Rust bench"
    echo "host: $(uname -mrs)"
    echo "cpus_physical: $cpus"
    echo "mem_bytes: $mem_bytes"
    echo "rustc: $(rustc --version 2>/dev/null || echo 'rustc: not installed')"
    echo "cargo: $(cargo --version 2>/dev/null || echo 'cargo: not installed')"
    echo "rust_root: $RUST_ROOT"
    echo "features: $FEATURES"
    echo "iters_per_phase: $ITERS"
    echo
} >> "$OUT"

run_phase() {
    local label="$1"; shift
    local iter="$1"; shift
    echo "=== phase=$label iter=$iter cmd=$* ===" >> "$OUT"
    if [[ "$uname_s" == "Darwin" ]]; then
        $TIME -l -- "$@" >/dev/null 2>>"$OUT"
    else
        $TIME -v -- "$@" >/dev/null 2>>"$OUT"
    fi
    echo "=== end phase=$label iter=$iter ===" >> "$OUT"
}

phase_with_cold() {
    local cold_label="$1"; shift
    local warm_label="$1"; shift
    local cleaner="$1"; shift
    bash -c "$cleaner" >/dev/null 2>&1 || true
    run_phase "$cold_label" 1 "$@"
    for i in $(seq 2 "$ITERS"); do
        run_phase "$warm_label" "$i" "$@"
    done
}

phase_repeat() {
    local label="$1"; shift
    for i in $(seq 1 "$ITERS"); do
        run_phase "$label" "$i" "$@"
    done
}

# SQLX offline so we don't need a live DB for typecheck/test compilation
export SQLX_OFFLINE=true

# ---- BUILD ----
phase_with_cold "build_cold" "build_warm" "cargo clean" \
    cargo build --workspace --features "$FEATURES"

# ---- CHECK (slot equivalent to `go vet`) ----
phase_repeat "vet" cargo check --workspace --features "$FEATURES"

# ---- LINT (clippy) ----
phase_repeat "lint" cargo clippy --workspace --features "$FEATURES" -- -D warnings

# ---- TEST ----
# `cargo test --no-run` would just compile; we run the unit tests like Rust CI does.
phase_with_cold "test_cold" "test_warm" "cargo clean" \
    cargo test --workspace --features "$FEATURES" --lib

echo >> "$OUT"
echo "## done" >> "$OUT"

cat "$OUT"
