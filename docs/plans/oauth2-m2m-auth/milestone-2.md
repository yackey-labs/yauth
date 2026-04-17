# Milestone 2: Asymmetric signing (RS256 / ES256) + populated JWKS

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone adds asymmetric signing on the **issuance** side and populates `/.well-known/jwks.json` so resource servers in other trust domains can validate yauth tokens without holding the shared HS256 secret. HS256 stays the default and unchanged for every existing deployment. No client-auth changes here — those are M3.

### What must work:

1. New feature flag `asymmetric-jwt` in `crates/yauth/Cargo.toml` (off by default, included in `full`). Enables the new `rsa` + `p256` deps and the asymmetric code paths. With the flag off, `BearerConfig` looks identical to today and JWKS keeps returning empty.
2. `BearerConfig` (gated on `asymmetric-jwt`) gains:
   - `signing_algorithm: SigningAlgorithm` — enum `Hs256 | Rs256 | Es256`, defaults to `Hs256`.
   - `signing_key_pem: Option<String>` — required when `signing_algorithm != Hs256`, ignored otherwise. Loaded from PEM by the user (file, env, secrets manager — yauth doesn't read paths). Builder-time validation: parse the PEM at config-load via `rsa::RsaPrivateKey::from_pkcs8_pem` / `p256::SecretKey::from_pkcs8_pem` and fail fast on bad input — do not defer to first-token-issued.
   - `kid: Option<String>` — defaults to the RFC 7638 thumbprint of the public key. Set explicitly if the user is rotating keys and wants stable IDs.
3. Token issuance (both user JWTs in `bearer.rs` and client_credentials JWTs in `oauth2_server.rs`) honors `signing_algorithm` and sets the JWT header's `alg` and `kid` accordingly. HS256 path = identical bytes to today; only the header changes when alg differs.
4. `validate_jwt_as_user` and `validate_jwt_as_client` (from M1) read the JWT header (`jsonwebtoken::decode_header`) and dispatch by `alg`. HS256 → `DecodingKey::from_secret(jwt_secret)`. RS256/ES256 → `DecodingKey::from_rsa_pem` / `from_ec_pem` over the public component of the configured signing key. Unknown `alg` → reject. `kid` mismatch (when configured) → reject.
5. `auth/jwks.rs::generate_jwks` returns the populated key set when `asymmetric-jwt` is on and `signing_algorithm != Hs256`:
   - RS256 → JWK with `kty=RSA`, `alg=RS256`, `use=sig`, `kid`, `n` and `e` base64url-encoded (no padding) from the parsed `RsaPublicKey`.
   - ES256 → JWK with `kty=EC`, `alg=ES256`, `crv=P-256`, `use=sig`, `kid`, `x` and `y` base64url-encoded (no padding) from the uncompressed point of the `p256::PublicKey`.
   - HS256 stays an empty key set.
6. `/.well-known/jwks.json` is reachable when **either** `oidc` or `asymmetric-jwt` is enabled. Today it's only mounted by the `oidc` plugin (`crates/yauth/src/plugins/oidc.rs:39`). Move the route registration so it's mounted whenever `asymmetric-jwt` is on, even without `oidc`. Keep the existing `oidc` mount working unchanged.
7. Discovery doc updates are deferred to M3 (they pair naturally with `token_endpoint_auth_methods_supported`).

### After building, prove it works:

Start `docker compose up -d`. Run all of:

- `cargo fmt --check`
- `cargo clippy --features full,all-backends -- -D warnings`
- `cargo clippy --features bearer,oauth2-server,asymmetric-jwt,memory-backend -- -D warnings` — strict feature combo to catch missing cfgs
- `cargo clippy --no-default-features --features memory-backend -- -D warnings` — confirm `asymmetric-jwt`-off path still compiles cleanly
- `cargo test --features full,all-backends --test pentest`
- `cargo test --features full,all-backends --test memory_backend`
- `cargo test --features full,all-backends --test repo_conformance` — unchanged
- New unit test in `auth/jwks.rs`: configure RS256 with a known test PEM (commit a deterministic test key under `tests/fixtures/`), call `generate_jwks`, assert `kty=RSA`, `alg=RS256`, and that `n` + `e` round-trip to the same `RsaPublicKey`. Repeat for ES256.
- New integration test: configure server with RS256, mint a user JWT, hit a protected route → 200. Mint a client_credentials JWT, hit a scope-protected route → 200. Verify the JWT's `alg` header is `RS256` and `kid` matches the JWKS entry.
- New integration test (the cross-trust-domain proof): configure server with RS256, mint a token. Spin up a tiny in-test "external resource server" (raw `jsonwebtoken` + the JWKS JSON fetched from the running yauth, no shared secret) and have it validate the token successfully. This is the headline proof that JWKS publication works end-to-end.
- New integration test: token signed with one alg but `BearerConfig::signing_algorithm` configured for another → 401, no panic.
- New integration test: HS256 deployment (default config) is byte-for-byte unchanged — repeat M1's tests against the same fixture; bytes of issued tokens (modulo `iat`/`jti`/`exp`) match.

### Test strategy:

Test fixture keys: generate two PEM pairs (one RSA-2048, one P-256) with `openssl genpkey` and commit under `crates/yauth/tests/fixtures/`. **These are test-only keys** — add a top-of-file comment in each PEM explaining that and confirming they're not used anywhere outside `tests/`. The pentest reviewer will catch a leaked-secret false positive otherwise.

Use the same shared-runtime / `OnceLock<Runtime>` pattern as M1 and the conformance suite.

### Known pitfalls:

1. **`kid` derivation must be deterministic**: use the RFC 7638 JWK thumbprint over the canonical-form JWK (alphabetic key order, no whitespace, base64url-no-pad SHA-256). If you hash a Rust struct's `Debug` output or the unordered JSON, the kid will change between runs and JWKS lookups will fail intermittently. Use `serde_json::to_value` then sort keys yourself.

2. **Don't publish the private key in JWKS**: `Jwk` is the public key set only. The `n`/`e` (RSA) or `x`/`y` (EC) come from the public key derived from the private key — never from the private key's PKCS#8 directly. The `rsa` crate exposes `.to_public_key()` on `RsaPrivateKey`; use that.

3. **Algorithm confusion attack**: a token signed with HS256 using the PUBLIC RSA key as the secret can sometimes be accepted by naive validators. `jsonwebtoken@10`'s `Validation::new(alg)` constrains the accepted alg, but **only if you set the validation alg from your config, not from the token header**. Read the header's alg, check it equals the configured alg (or is in a configured allow-list — for now, exactly one), THEN construct the `Validation` with that alg. Never pass the token's header alg through directly.

4. **`jsonwebtoken@10` PEM parsing rejects PKCS#1 RSA keys silently in some configs**: prefer PKCS#8 PEMs (`-----BEGIN PRIVATE KEY-----`). If the user supplies `-----BEGIN RSA PRIVATE KEY-----`, fail at config-load with a clear "convert to PKCS#8" message — don't accept it and crash later.

5. **Feature flag coverage**: `asymmetric-jwt` requires `bearer`. Make `asymmetric-jwt = ["bearer"]` in Cargo.toml so a user can't enable it standalone and end up with broken builds. Mirror how `oidc = ["bearer", "oauth2-server"]` is structured.

6. **JWKS endpoint duplication**: `oidc` plugin currently owns the route. When `asymmetric-jwt` is on without `oidc`, mount the route from a new lightweight place (e.g., `auth/jwks.rs::router()`). When BOTH are on, only mount once — Axum panics on duplicate routes at runtime. Add a debug-build assertion or use a single conditional registration in `state.rs` / `lib.rs` instead of in two plugins.

7. **`record_error` on PEM parse failure**: surface a typed error from the builder, not a panic. The builder is async (`build()` returns `Result<YAuth, RepoError>`) — add a new variant or reuse a config-error variant. Users running on Kubernetes will mount the PEM as a secret; bad ConfigMap → pod crashloop with an actionable error, not a stack trace.

8. **Don't expose `signing_key_pem` in any serialized state**: `BearerConfig` derives `Serialize` and `Deserialize`. Confirm the new `signing_key_pem` field has `#[serde(skip_serializing)]` (or that the whole struct is never serialized in production paths). Telemetry attributes must never include the PEM. Add a clippy/grep CI check or a unit test that serializes a config with a key set and asserts the PEM bytes do NOT appear.

9. **`base64::Engine` import gotcha**: the `base64` crate's `URL_SAFE_NO_PAD` engine requires `use base64::Engine` to be in scope to call `.encode(...)`. It's been broken between PRs in this repo before — write a tiny helper in `auth/jwks.rs` and import it consistently.

10. **`p256::PublicKey` to JWK coords**: use `EncodedPoint::from(public_key).coordinates()` (or `.x()` + `.y()` on the encoded point) to get raw bytes. Don't convert via DER and re-parse — that round-trip drops leading zeros and breaks JWK validators that expect exactly 32 bytes per coord.

11. **`oauth2_server.rs` issuance path**: today's `handle_client_credentials_grant` hard-codes `Algorithm::HS256` and `EncodingKey::from_secret`. It must now go through a shared helper (e.g., `bearer::sign_jwt(claims, &state.bearer_config) -> Result<String>`) so HS256 / RS256 / ES256 are handled in one place. Same for the user-token issuance in `bearer.rs`. **Do not** copy-paste the alg dispatch into both; that's how skew bugs ship.

12. **HS256-bytes-stable regression**: the M2 verification claim "HS256 byte-for-byte unchanged" depends on the new `sign_jwt` helper producing exactly the same JWT header as today. `jsonwebtoken::Header::new(Algorithm::HS256)` produces `{"alg":"HS256","typ":"JWT"}`. If you start always emitting `kid` (even when `None`), the header gains a field and the bytes change — breaking any external system that hashes the JWT for cache-busting. Only emit `kid` when `signing_algorithm != Hs256` OR `BearerConfig::kid` is explicitly set. Add a unit test that snapshots the HS256 header bytes against the current main branch.
