# Milestone 3: `private_key_jwt` client authentication (RFC 7523) + discovery doc

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone closes the cross-trust-domain story. External clients can register a public key (or `jwks_uri`) and authenticate to the token endpoint with a signed JWT assertion instead of a shared `client_secret`. The discovery doc grows to advertise asymmetric algs and `private_key_jwt` so well-behaved OAuth clients auto-detect it.

### What must work:

1. `yauth_oauth2_clients` schema gains two nullable columns: `public_key_pem TEXT NULL` and `jwks_uri TEXT NULL`. Both registered via the schema definition in `crates/yauth-migration/src/plugin_schemas/` so `cargo yauth generate` produces the matching diesel/sqlx/seaorm migration. **Do not write a runtime migration** — yauth no longer ships migrations (see CLAUDE.md, `generate-not-migrate` plan).
2. Dynamic Client Registration (RFC 7591) accepts `token_endpoint_auth_method`, `public_key_pem`, and `jwks_uri` in the create-client request. Validation: if `token_endpoint_auth_method = "private_key_jwt"`, exactly one of `public_key_pem` / `jwks_uri` must be present.
3. Token endpoint accepts the assertion form per RFC 7523 §2.2:
   - `client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
   - `client_assertion = <JWT>`
   - When present, these REPLACE `client_secret` (rejecting requests that supply both).
4. Assertion validation per RFC 7523 §3:
   - `iss` and `sub` must both equal the registered `client_id`.
   - `aud` must equal the absolute URL of the token endpoint (`https://<issuer>/api/auth/oauth/token` — derive from request scheme/host or `state.config.issuer_url`).
   - `exp` required and in the future. `iat`/`nbf` (when present) honored.
   - `jti` required; record + reject reuse for the assertion's lifetime (use existing revocations repo with a `client_assertion:` prefix to avoid colliding with access-token JTIs).
   - Signature verified against the client's `public_key_pem` (parsed once at registration and cached on `state` keyed by `client_id`) or the key fetched from `jwks_uri` (with a 5s timeout, max 16 KB body, in-memory TTL cache — 5 min default — with `Cache-Control: max-age` honored when present).
5. On successful assertion, the rest of the token endpoint flow is identical to today's `client_secret` path: scope check, mint token, return. The issued token uses the server's `signing_algorithm` (M2) — independent from the client's assertion alg.
   - **Audit**: write an audit_log row for every assertion-validated mint with event_type `oauth2_token_issued` and `metadata = { client_id, grant_type: "client_credentials", auth_method: "private_key_jwt", scope, assertion_jti }`. Mirrors the existing `client_secret` path at `oauth2_server.rs:2093`. Also audit `oauth2_assertion_failed` on rejection (bad signature / aud / replay) with `metadata = { client_id, reason }` — these are real attack signals.
6. `/.well-known/oauth-authorization-server` discovery doc adds:
   - `id_token_signing_alg_values_supported`: array of algs the server is configured to issue (`["HS256"]` by default; `["RS256"]` etc. when M2 is configured).
   - `token_endpoint_auth_methods_supported`: `["client_secret_post", "client_secret_basic", "private_key_jwt"]` (drop the last when `asymmetric-jwt` is off — clients shouldn't see a method that can't validate).
   - `token_endpoint_auth_signing_alg_values_supported`: algs accepted on `client_assertion` (`["RS256", "ES256"]` when `asymmetric-jwt` is on; absent otherwise).
   - `jwks_uri`: the absolute URL — already advertised by oidc; verify it appears here too.
7. TS client + OpenAPI: register-client request shape grows three fields. Run `bun generate` and commit `openapi.json` + `packages/client/src/generated.ts`.

### After building, prove it works:

Start `docker compose up -d`. Run all of:

- `cargo fmt --check`
- `cargo clippy --features full,all-backends -- -D warnings`
- `cargo test --features full,all-backends --test pentest`
- `cargo test --features full,all-backends --test repo_conformance` — must still pass; the new columns are nullable so no behavior changes for existing methods.
- `cargo test --features full,all-backends --test diesel_integration`
- `bun validate:ci` — fails if `openapi.json` or `packages/client/src/generated.ts` is out of date.
- New integration test (the headline test): register a client with `token_endpoint_auth_method=private_key_jwt` + a test RSA `public_key_pem`. Sign an assertion with the matching private key. POST to `/api/auth/oauth/token` with `grant_type=client_credentials` + `client_assertion_type` + `client_assertion`. Expect 200 + token. Hit a protected route with the token → 200 with `MachineCaller` populated.
- New integration test: same flow but assertion's `aud` is wrong → 401, `error=invalid_client`.
- New integration test: same flow but assertion's `jti` is replayed within the lifetime → 401.
- New integration test: client registered with `client_secret` only — assertion request is rejected (`error=invalid_client`, "client not configured for private_key_jwt"). Conversely, a private_key_jwt client supplying `client_secret` is rejected.
- New integration test: `jwks_uri` path — spin up a tiny in-test HTTP server serving a JWK, register the client with `jwks_uri=http://127.0.0.1:<port>/jwks.json`, mint via assertion, validate. Assert the JWKS fetch is cached (second mint within TTL doesn't re-hit the server).
- New integration test: `jwks_uri` returns >16 KB body → registration (or first fetch) fails cleanly with a typed error, no OOM.
- Discovery doc test: `GET /.well-known/oauth-authorization-server` with `asymmetric-jwt` on returns `private_key_jwt` in `token_endpoint_auth_methods_supported`. With it off, `private_key_jwt` is absent.

### Test strategy:

Reuse the test fixture keys from M2 (commit a second pair if you need a "wrong key" for negative tests). For `jwks_uri` tests, stand up a `tokio::net::TcpListener` + a hand-rolled minimal HTTP/1.1 responder OR a `hyper`-based test server inline — don't add a new test-dep on a full mock framework if a 30-line inline server works. Same shared-runtime / `OnceLock` pattern as M1 + M2.

After M3 lands, run `cargo yauth generate --check -f yauth.toml` (CI command) to confirm the generated migration matches the schema. The repo's release pipeline will surface a diff if you forgot to regenerate.

### Known pitfalls:

1. **`aud` must be the token endpoint URL, not the issuer**: RFC 7523 §3 is explicit — assertion `aud` is the token endpoint. A common bug: comparing against `state.config.issuer_url` directly (which usually omits `/api/auth/oauth/token`). Build the comparison URL from the issuer + the literal endpoint path. Reject if the request's actual host differs from the configured issuer (someone is replaying an assertion meant for another server).

2. **Replay protection scope**: the assertion's `jti` is short-lived but reuse must still be blocked within the assertion's lifetime. Reuse `state.repos.revocations` but key with a prefix (`client_assertion:<jti>`) so cleanup of access-token JTIs doesn't sweep assertion JTIs and vice versa. Set TTL = assertion `exp - iat` + a small skew buffer.

3. **Don't fetch `jwks_uri` synchronously inside the request handler without a timeout**: it blocks the token endpoint for arbitrary external slowness. Use `reqwest` (already in workspace? confirm — if not, use `hyper` directly to avoid a new dep) with a 5s connect+read timeout, max body 16 KB, and reject on TLS errors. Cache for 5 min; honor `Cache-Control: max-age`. **Do not** auto-refresh on every request.

4. **Schema change requires regenerating migrations for ALL three ORMs**: diesel, sqlx, seaorm. `cargo yauth generate` produces all of them when `yauth.toml` lists them. CI's `bun validate:ci` won't catch this — there's a separate Rust check. Run `cargo yauth generate --check` in `.github/workflows/` and verify it passes locally before opening the PR.

5. **`jwks_uri` SSRF risk**: a client could register `jwks_uri=http://169.254.169.254/...` to probe cloud metadata. Defaults: require HTTPS scheme (reject `http://` unless `allow_insecure_jwks_uri: bool` is set), block private/loopback/link-local IPs (reject 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7) unless `allow_private_jwks_uri: bool` is set. Both flags default false. Validate at registration time AND at fetch time (DNS may resolve to a different IP later). Don't ship M3 without these — it's a real attack class and pentest will flag it.

6. **Algorithm allow-list for assertions**: accept only `RS256` and `ES256` for assertions. Reject `none`, `HS*` (HS256 with the public key as secret = trivial forgery), and anything else. `jsonwebtoken::Validation::new(alg)` enforces this — pass the configured allow-list, not the assertion header's claimed alg.

7. **PEM parsing at registration time, not request time**: parse `public_key_pem` when the client registers and reject bad PEMs immediately. If you defer to first-token-request, every assertion request will re-parse — wasteful and inconsistent error timing. Cache the parsed `RsaPublicKey` / `p256::PublicKey` on `state`, keyed by client_id, with a load-on-miss fallback for newly-registered clients.

8. **Discovery doc emits a different shape across feature combos**: write a unit test that snapshots the discovery JSON for each meaningful feature combo (`oidc on/off × asymmetric-jwt on/off`). It catches regressions where someone removes a key or shifts an alg.

9. **`cargo yauth generate` migration column types**: make sure both new columns are TEXT (not VARCHAR with a length limit). PEMs and JWKS URIs vary in length; don't risk truncation on MySQL.

10. **Pentest suite must learn `private_key_jwt`**: add cases for "assertion with future `iat`", "assertion with `exp` in the past", "assertion with non-matching `iss`/`sub`", "assertion signed with a different client's key" (must fail), "RS256 assertion against an ES256-registered client" (must fail). Without these, a regression that accepts forged assertions ships silently.

11. **`bun generate` requires running yauth first**: the OpenAPI spec is generated from the running binary's introspection. After M3's struct changes, run the generate flow exactly as documented in `crates/yauth/CLAUDE.md`'s "Generated TypeScript Client" section. CI's `bun generate:check` will fail your PR if you skip this.
