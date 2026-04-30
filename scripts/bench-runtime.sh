#!/usr/bin/env bash
# Runtime benchmark: idle RSS + load throughput/latency for both servers.
#
# - Spawns the Go example (`go run ./examples/sqlite`) and a Rust example
#   (cargo run --example minimal --features email-password,memory-backend).
#   If the Rust example is unavailable, the Rust portion is skipped and a
#   note is left in the output.
# - For each: wait for /api/auth/session to respond, capture idle RSS,
#   register + login a user, then run a load generator against the session
#   endpoint with the auth cookie. Captures peak RSS during load.
#
# Output is written to OUT (default /tmp/yauth-runtime-bench.txt) and printed.
set -uo pipefail

GO_ROOT="${GO_ROOT:-/Users/syackey/steveyackey/yackey-labs/yauth-go}"
RUST_ROOT="${RUST_ROOT:-/Users/syackey/steveyackey/yackey-labs/yauth}"
OUT="${1:-/tmp/yauth-runtime-bench.txt}"

DURATION="${BENCH_DURATION:-30s}"
THREADS="${BENCH_THREADS:-4}"
CONNS="${BENCH_CONNS:-100}"
# Both servers default to port 3000; they run sequentially so this is fine.
# Override PORT_GO / PORT_RUST if your env conflicts.
PORT_GO="${PORT_GO:-3000}"
PORT_RUST="${PORT_RUST:-3000}"

mkdir -p "$(dirname "$OUT")"
: > "$OUT"

# Pick a load generator (wrk > hey > ab > curl-loop fallback).
LOADGEN=""
if command -v wrk >/dev/null 2>&1; then
    LOADGEN=wrk
elif command -v hey >/dev/null 2>&1; then
    LOADGEN=hey
elif command -v ab >/dev/null 2>&1; then
    LOADGEN=ab
fi

uname_s="$(uname -s)"

log() { echo "$*" | tee -a "$OUT"; }

# Polled-RSS sampler. Polls every 500ms and writes max RSS (KB) to the named
# file when interrupted. Writes its PID to a named file (so the caller can read
# it via `cat`) — using `echo $!` plus command substitution `$(...)` deadlocks
# because the subshell holds open the substitution's stdout.
start_rss_sampler() {
    local pid="$1"
    local outfile="$2"
    local pidfile="$3"
    (
        max=0
        # Write the running max on every SIGTERM (caller kills us when load
        # finishes) AND when the watched pid exits naturally.
        trap 'echo "$max" > "$outfile"; exit 0' TERM INT
        while kill -0 "$pid" 2>/dev/null; do
            rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
            if [[ -n "$rss" && "$rss" =~ ^[0-9]+$ && "$rss" -gt "$max" ]]; then
                max=$rss
            fi
            sleep 0.5
        done
        echo "$max" > "$outfile"
    ) </dev/null >/dev/null 2>&1 &
    echo $! > "$pidfile"
}

wait_for_http() {
    # Returns 0 when the server speaks HTTP at all (any status, including
    # 401/404). Skips connection refused / timeout.
    local url="$1"
    local timeout_secs="${2:-30}"
    local end=$(( $(date +%s) + timeout_secs ))
    while [[ $(date +%s) -lt $end ]]; do
        local code
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || echo "000")
        if [[ "$code" != "000" ]]; then return 0; fi
        sleep 0.5
    done
    return 1
}

register_and_login() {
    local base="$1"
    local email="bench+$RANDOM@example.com"
    # Avoid the legendary "correct horse battery staple" — Rust's pwned-passwords
    # check rejects it (it's in breach lists). Use a long random-ish phrase.
    local pw="zR4qeT7vBn9Lp3sM-bench-$RANDOM-$(date +%s)"
    local cookie_jar="$2"

    # Register (best-effort — server may auto-login or require login)
    curl -sf -X POST "$base/api/auth/register" \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"$email\",\"password\":\"$pw\"}" \
        -c "$cookie_jar" -o /dev/null || true

    # Login (always run — registers may not auto-session)
    curl -sf -X POST "$base/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"$email\",\"password\":\"$pw\"}" \
        -c "$cookie_jar" -o /dev/null || true

    # Verify session works
    curl -sf -b "$cookie_jar" "$base/api/auth/session" -o /dev/null && return 0
    return 1
}

# Run load against URL with cookie jar; print "rps p50 p99" parsed from output.
run_load() {
    local url="$1"
    local cookie_jar="$2"
    local raw_out="$3"

    local cookie_header=""
    if [[ -s "$cookie_jar" ]]; then
        # Extract cookies from curl's Netscape jar. curl marks HttpOnly cookies
        # with a "#HttpOnly_" prefix on the host column — strip that, but skip
        # genuine comment lines (which start with "# " or are just "#").
        cookie_header=$(awk 'BEGIN{ORS=""}
            /^# / || /^#$/ { next }
            { sub(/^#HttpOnly_/, "", $1); }
            NF==7 { print $6"="$7"; " }' "$cookie_jar")
    fi

    case "$LOADGEN" in
        wrk)
            wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" \
                --header "Cookie: $cookie_header" "$url" > "$raw_out" 2>&1
            ;;
        hey)
            # hey doesn't support multiple cookies in one flag well; use -H Cookie
            hey -z "$DURATION" -c "$CONNS" -H "Cookie: $cookie_header" "$url" > "$raw_out" 2>&1
            ;;
        ab)
            local total=$((CONNS * 1000))
            ab -t "${DURATION%s}" -c "$CONNS" -H "Cookie: $cookie_header" "$url" > "$raw_out" 2>&1
            ;;
        *)
            # Curl loop fallback — measures sequential RPS, not real load.
            local end=$(( $(date +%s) + 30 ))
            local count=0
            while [[ $(date +%s) -lt $end ]]; do
                curl -sf -b "$cookie_jar" "$url" -o /dev/null && count=$((count+1)) || true
            done
            echo "curl-loop: $count requests in 30s ($(awk -v c=$count 'BEGIN{printf "%.1f", c/30}') req/s)" > "$raw_out"
            ;;
    esac
}

bench_one() {
    local lang="$1"
    local pid="$2"
    local base="$3"
    local port="$4"

    log
    log "=== runtime: $lang ==="

    if ! wait_for_http "$base/api/auth/session"; then
        log "$lang: server failed to respond on $base"
        return 1
    fi

    # The PID we got may be a wrapper (e.g. `cargo run`). Find the actual
    # process bound to the listening port and measure that one. The lsof
    # `-s TCP:LISTEN` flag silently filters everything on macOS, so we just
    # take the first PID with an open socket on the port.
    local actual_pid
    actual_pid=$(lsof -ti tcp:"$port" 2>/dev/null | head -1)
    if [[ -n "$actual_pid" ]]; then
        pid="$actual_pid"
        log "$lang: server pid resolved via lsof to $pid"
    else
        log "$lang: lsof returned no pid for tcp:$port — using launcher pid $pid"
    fi

    # Idle RSS after warmup
    sleep 10
    local idle_rss
    idle_rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
    log "$lang: idle_rss_kb=${idle_rss:-NA}"

    local cookie_jar
    cookie_jar=$(mktemp)
    if ! register_and_login "$base" "$cookie_jar"; then
        log "$lang: failed to register/login — load test cookie may be invalid"
    fi

    # Start RSS sampler during load
    local rss_file pid_file
    rss_file=$(mktemp)
    pid_file=$(mktemp)
    start_rss_sampler "$pid" "$rss_file" "$pid_file"
    local sampler_pid
    sampler_pid=$(cat "$pid_file")
    rm -f "$pid_file"

    local raw_out
    raw_out=$(mktemp)
    log "$lang: load-gen=${LOADGEN:-curl-loop} duration=$DURATION threads=$THREADS conns=$CONNS"
    run_load "$base/api/auth/session" "$cookie_jar" "$raw_out"

    # Stop sampler (it'll exit when the server PID dies, but we want it now)
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true

    local peak_rss
    peak_rss=$(cat "$rss_file" 2>/dev/null || echo "")
    log "$lang: peak_load_rss_kb=${peak_rss:-NA}"
    log "$lang: --- raw load output ---"
    cat "$raw_out" >> "$OUT"
    log "$lang: --- end raw output ---"

    rm -f "$cookie_jar" "$rss_file" "$raw_out"
}

start_go_server() {
    cd "$GO_ROOT"
    # Pre-built binary if available (much faster startup than `go run`).
    local bin="/tmp/yauth-go-example-sqlite"
    if [[ ! -x "$bin" ]] || [[ "$bin" -ot "examples/sqlite/main.go" ]]; then
        log "go: building example binary..."
        go build -o "$bin" ./examples/sqlite >/tmp/yauth-go-server.log 2>&1
    fi
    PORT="$PORT_GO" "$bin" >/tmp/yauth-go-server.log 2>&1 &
    echo $!
}

start_rust_server() {
    cd "$RUST_ROOT"
    if [[ ! -f crates/yauth/examples/server.rs ]]; then
        echo ""
        return 1
    fi
    # Build the example first so timing isn't dominated by the compile.
    local bin="$RUST_ROOT/target/debug/examples/server"
    if [[ ! -x "$bin" ]]; then
        log "rust: building example binary..."
        cargo build --quiet --example server --features full,memory-backend \
            >/tmp/yauth-rust-server.log 2>&1
    fi
    if [[ ! -x "$bin" ]]; then
        echo ""
        return 1
    fi
    PORT="$PORT_RUST" YAUTH_BACKEND=memory "$bin" \
        >/tmp/yauth-rust-server.log 2>&1 &
    echo $!
    return 0
}

# ---- main ----
log "## yauth runtime bench"
log "host: $(uname -mrs)"
log "loadgen: ${LOADGEN:-curl-loop (fallback)}"
log "duration: $DURATION  threads: $THREADS  conns: $CONNS"

# --- Go ---
log
log "starting Go server (port $PORT_GO)..."
GO_PID=$(start_go_server)
trap "kill $GO_PID 2>/dev/null || true; lsof -ti tcp:$PORT_GO 2>/dev/null | xargs -r kill -9 2>/dev/null || true" EXIT
bench_one "go" "$GO_PID" "http://127.0.0.1:$PORT_GO" "$PORT_GO" || true
kill "$GO_PID" 2>/dev/null || true
lsof -ti tcp:$PORT_GO 2>/dev/null | xargs -r kill -9 2>/dev/null || true
wait "$GO_PID" 2>/dev/null || true
trap - EXIT

# --- Rust ---
log
RUST_PID=""
if [[ -d "$RUST_ROOT" ]] && command -v cargo >/dev/null 2>&1; then
    log "starting Rust server (port $PORT_RUST)..."
    RUST_PID=$(start_rust_server || true)
    if [[ -n "$RUST_PID" ]]; then
        trap "kill $RUST_PID 2>/dev/null || true; lsof -ti tcp:$PORT_RUST 2>/dev/null | xargs -r kill -9 2>/dev/null || true" EXIT
        bench_one "rust" "$RUST_PID" "http://127.0.0.1:$PORT_RUST" "$PORT_RUST" || true
        kill "$RUST_PID" 2>/dev/null || true
        lsof -ti tcp:$PORT_RUST 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        wait "$RUST_PID" 2>/dev/null || true
        trap - EXIT
    else
        log "rust: no runnable example found in $RUST_ROOT/examples — skipping"
    fi
else
    log "rust: cargo or RUST_ROOT not available — skipping"
fi

log
log "## done"
cat "$OUT"
