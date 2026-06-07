#!/usr/bin/env bash
# Headless end-to-end driver for the yauth→yauth SSO example.
# Starts the IdP + RP, registers a shared-email user in both, then drives the
# full SSO login (RP → IdP authorize+consent → RP callback) with curl cookie
# jars and asserts the RP session is the SAME user (JIT link-by-email, no dup).
set -uo pipefail
cd "$(dirname "$0")/../.."   # repo root (yauth/)

IDP=http://127.0.0.1:8081
RP=http://127.0.0.1:8080
EMAIL=user@demo.test
PASS='Demo-Wombat-7Hq2-Kx9r-Pa55'
TMP=$(mktemp -d); IDPJAR=$TMP/idp.jar; RPJAR=$TMP/rp.jar
pids=()
cleanup(){ for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$TMP"; }
trap cleanup EXIT
fail(){ echo "FAIL: $*" >&2; exit 1; }

waitup(){ for i in $(seq 1 60); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.5; done; return 1; }

echo "→ building…"
go build -o "$TMP/idp" ./examples/sso/idp || fail "build idp"
go build -o "$TMP/rp"  ./examples/sso/rp  || fail "build rp"

echo "→ starting IdP…"
"$TMP/idp" >"$TMP/idp.log" 2>&1 & pids+=($!)
waitup "$IDP/" || { cat "$TMP/idp.log"; fail "IdP did not start"; }
echo "  IdP up (trusts the RP's issuer for keyless DCR)."

echo "→ starting RP (federates keylessly — signs a software_statement, no admin key)…"
"$TMP/rp" >"$TMP/rp.log" 2>&1 & pids+=($!)
waitup "$RP/" || { cat "$TMP/rp.log"; fail "RP did not start"; }
grep -q "federated with the IdP keylessly" "$TMP/rp.log" || { cat "$TMP/rp.log"; fail "RP did not federate"; }
echo "  RP up + federated (zero admin key, zero secret pasted)."

reg(){ curl -fsS -o /dev/null -X POST "$1/api/auth/register" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" 2>/dev/null || true; }
echo "→ registering $EMAIL in IdP and RP (so SSO links, not duplicates)…"
reg "$IDP"; reg "$RP"

echo "→ [RP] begin SSO login…"
loc=$(curl -s -c "$RPJAR" -o /dev/null -D - \
  "$RP/api/auth/sso/login?org=demo&redirect=$RP/" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
[ -n "$loc" ] || { cat "$TMP/rp.log"; fail "no redirect from /sso/login"; }
echo "  → IdP authorize: ${loc:0:80}…"

echo "→ [IdP] sign in…"
curl -fsS -c "$IDPJAR" -o /dev/null -X POST "$IDP/api/auth/login" \
  -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  || { cat "$TMP/idp.log"; fail "IdP login failed"; }

# Translate the SPA consent URL to the JSON authorize API (a browser would load
# the /authorize page, which calls this same endpoint with the same query).
qs=${loc#*\?}
authjson="$IDP/api/auth/oauth/authorize?$qs"
resp=$(curl -sS -b "$IDPJAR" "$authjson"); code=$(curl -s -o /dev/null -w '%{http_code}' -b "$IDPJAR" "$authjson")
[ "$code" = 200 ] || { echo "authorize $code: $resp"; fail "GET authorize"; }
rurl=$(jq -r '.redirect_url // empty' <<<"$resp")
if [ -z "$rurl" ]; then
  rid=$(jq -r '.request_id' <<<"$resp"); csrf=$(jq -r '.csrf_token' <<<"$resp")
  [ "$rid" != null ] && [ -n "$rid" ] || { echo "$resp"; fail "no request_id/csrf"; }
  echo "→ [IdP] approve consent…"
  resp=$(curl -fsS -b "$IDPJAR" -X POST "$IDP/api/auth/oauth2/consent" \
    -H 'content-type: application/json' \
    -d "{\"request_id\":\"$rid\",\"csrf_token\":\"$csrf\",\"approved\":true}") || { echo "$resp"; fail "consent"; }
  rurl=$(jq -r '.redirect_url // empty' <<<"$resp")
fi
[ -n "$rurl" ] || { echo "$resp"; fail "no redirect_url after consent"; }
echo "  → RP callback: ${rurl:0:80}…"

echo "→ [RP] complete callback…"
cbcode=$(curl -s -b "$RPJAR" -c "$RPJAR" -o "$TMP/cb.out" -w '%{http_code}' "$rurl")
echo "  callback HTTP $cbcode"
if [ "$cbcode" -ge 400 ]; then echo "  body: $(cat "$TMP/cb.out")"; tail -8 "$TMP/rp.log"; fail "callback"; fi

echo "→ [RP] verify session…"
sess=$(curl -s -b "$RPJAR" "$RP/api/auth/session")
got=$(jq -r '.user.email // empty' <<<"$sess" 2>/dev/null)
[ -n "$got" ] || { echo "session resp: $sess"; tail -8 "$TMP/rp.log"; fail "session"; }
got=$(jq -r '.user.email // empty' <<<"$sess")
[ "$got" = "$EMAIL" ] || { echo "$sess"; cat "$TMP/rp.log"; fail "session email=$got want=$EMAIL"; }

echo
echo "✅ SSO round-trip OK — RP session is $got (linked via the IdP, no password shared)."
