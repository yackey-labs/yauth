#!/usr/bin/env bash
# Capture build/test/lint wall time, user/sys CPU, peak RSS, and utilization%
# for the Go yauth-go workspace.
#
# - macOS uses /usr/bin/time -l (BSD time, prints peak RSS)
# - Linux uses /usr/bin/time -v (GNU time, prints "Maximum resident set size")
#
# Each phase is run 3 times and we capture each iteration; bench-compare.sh
# parses the output and takes the median.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${1:-/tmp/yauth-go-bench.txt}"
TIME=/usr/bin/time
ITERS="${BENCH_ITERS:-3}"

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
    echo "## yauth-go bench"
    echo "host: $(uname -mrs)"
    echo "cpus_physical: $cpus"
    echo "mem_bytes: $mem_bytes"
    echo "go: $(go version 2>/dev/null || echo 'go: not installed')"
    echo "iters_per_phase: $ITERS"
    echo
} >> "$OUT"

# Run a command under /usr/bin/time, append a delimited record to OUT.
run_phase() {
    local label="$1"; shift
    local iter="$1"; shift
    echo "=== phase=$label iter=$iter cmd=$* ===" >> "$OUT"
    if [[ "$uname_s" == "Darwin" ]]; then
        # BSD /usr/bin/time -l writes resource usage to stderr
        $TIME -l -- "$@" >/dev/null 2>>"$OUT"
    else
        # GNU /usr/bin/time -v writes resource usage to stderr
        $TIME -v -- "$@" >/dev/null 2>>"$OUT"
    fi
    echo "=== end phase=$label iter=$iter ===" >> "$OUT"
}

# Cold = clean caches once, run iter 1; iters 2..N implicitly warm.
phase_with_cold() {
    local cold_label="$1"; shift
    local warm_label="$1"; shift
    local cleaner="$1"; shift   # shell command run before cold iter
    # Cold
    bash -c "$cleaner" >/dev/null 2>&1 || true
    run_phase "$cold_label" 1 "$@"
    # Warm iters
    for i in $(seq 2 "$ITERS"); do
        run_phase "$warm_label" "$i" "$@"
    done
}

# Plain repeated phase (no cold/warm distinction).
phase_repeat() {
    local label="$1"; shift
    for i in $(seq 1 "$ITERS"); do
        run_phase "$label" "$i" "$@"
    done
}

# Resolve golangci-lint (CI installs it; locally users may need to brew install)
GCL="$(command -v golangci-lint || true)"

# ---- BUILD ----
phase_with_cold "build_cold" "build_warm" "go clean -cache" go build ./...

# ---- VET ----
# vet is cheap; we run BENCH_ITERS times and take the median. The first iter
# is post-build_warm (cache populated), so all iters are essentially "warm".
phase_repeat "vet" go vet ./...

# ---- LINT ----
if [[ -n "$GCL" ]]; then
    phase_repeat "lint" "$GCL" run ./...
else
    echo "## lint: golangci-lint not installed; skipping" >> "$OUT"
fi

# ---- TEST ----
phase_with_cold "test_cold" "test_warm" "go clean -testcache" go test ./...

echo >> "$OUT"
echo "## done" >> "$OUT"

cat "$OUT"
