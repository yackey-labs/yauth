#!/usr/bin/env bash
#
# test-toasty-example.sh — end-to-end smoke test for the yauth-toasty
# example app.
#
# Boots crates/yauth-toasty/examples/toasty_backend.rs, posts to
# /register, asserts a 2xx response, tears everything down. Used to
# catch regressions where the documented adoption path silently breaks
# (e.g. a yauth API rename, a Toasty release that drops a method, or a
# feature-flag mix that no longer compiles).
#
# Usage:
#   scripts/test-toasty-example.sh
#
# Exit codes:
#   0 — example served and registered a user successfully
#   1 — example failed to start, crashed, or returned a non-2xx status
#
# Notes:
# - yauth-toasty is excluded from the workspace, so --manifest-path is
#   required. Don't change to `cargo run -p yauth-toasty` — it won't
#   resolve.
# - The example's SQLite file lives at ./example.db relative to the
#   invocation directory. We cd into the repo root to keep it there and
#   clean it up in a trap.
# - Use features `email-password,sqlite` — the smallest feature set that
#   exercises a write path through yauth without pulling in openssl via
#   webauthn. `full,sqlite` also works if libssl-dev is installed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT=${PORT:-3000}
HOST=${HOST:-127.0.0.1}
# A password that has enough entropy + a specific noun mix to avoid
# tripping the HIBP k-anonymity check on a public hash match.
PASSWORD=${PASSWORD:-'RosyPlank_Orbital_4x7Zq!'}
EMAIL=${EMAIL:-"ci-$(date +%s)@example.com"}

CARGO_PID=""
EXAMPLE_LOG="$(mktemp -t yauth-toasty-example.XXXXXX.log)"

cleanup() {
  local code=$?
  if [[ -n "${CARGO_PID}" ]]; then
    kill "${CARGO_PID}" 2>/dev/null || true
    wait "${CARGO_PID}" 2>/dev/null || true
  fi
  rm -f ./example.db ./example.db-journal ./example.db-wal ./example.db-shm
  if (( code != 0 )); then
    echo "--- example stderr/stdout (${EXAMPLE_LOG}) ---"
    tail -n 200 "${EXAMPLE_LOG}" || true
  fi
  rm -f "${EXAMPLE_LOG}"
  exit "${code}"
}
trap cleanup EXIT INT TERM

echo "--> Starting yauth-toasty example on ${HOST}:${PORT}"
rm -f ./example.db
cargo run --manifest-path crates/yauth-toasty/Cargo.toml \
  --example toasty_backend \
  --features email-password,sqlite \
  >"${EXAMPLE_LOG}" 2>&1 &
CARGO_PID=$!

# Wait up to ~30s for the server to accept connections.
for i in $(seq 1 30); do
  if curl -fsS "http://${HOST}:${PORT}/" >/dev/null 2>&1 \
    || curl -fsS "http://${HOST}:${PORT}/healthz" >/dev/null 2>&1 \
    || nc -z "${HOST}" "${PORT}" 2>/dev/null; then
    break
  fi
  # If the process died, give up early — don't wait the full 30s.
  if ! kill -0 "${CARGO_PID}" 2>/dev/null; then
    echo "!! example process exited before becoming ready" >&2
    exit 1
  fi
  sleep 1
done

echo "--> POST /register  email=${EMAIL}"
response_code=$(
  curl -s -o /tmp/toasty-register-body -w "%{http_code}" \
    -X POST "http://${HOST}:${PORT}/register" \
    -H "Content-Type: application/json" \
    --data "$(printf '{"email":"%s","password":"%s"}' "${EMAIL}" "${PASSWORD}")" \
    || echo "curl_failed"
)

echo "    HTTP ${response_code}"
echo "    body: $(head -c 300 /tmp/toasty-register-body)"

case "${response_code}" in
  2??)
    echo "--> OK: yauth-toasty example served a 2xx response"
    exit 0
    ;;
  *)
    echo "!! yauth-toasty example returned HTTP ${response_code}" >&2
    exit 1
    ;;
esac
