# Milestone 1: Validate Client Credentials JWTs in `auth_middleware` (HS256, in-trust-domain M2M)

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone closes the validation gap for tokens already mintable today. After this ships, an internal service can mint a `client_credentials` token via `POST /api/auth/oauth/token`, send it as `Authorization: Bearer <jwt>` to any yauth-protected route, and the request reaches the handler with `MachineCaller` in the request extensions. **Phase 1 is independently shippable** — Phase 2 (M2 + M3) is purely additive.

### What must work:

1. New types exposed from `crates/yauth/src/middleware.rs`: `MachineCaller { client_id, scopes, audience, jti, auth_method, custom_claims }`, `MachineAuthMethod` (single variant `ClientCredentials` for now), and `Authenticated` enum (`User(AuthUser) | Machine(MachineCaller)`).
2. `auth_middleware`'s Bearer arm dispatches on the JWT's claim shape, **not** on the error returned by user validation: decode the token's payload once into a `serde_json::Value`, branch on `client_id` present + `email` absent → `validate_jwt_as_client`, otherwise → `validate_jwt_as_user` (existing behavior). On success it inserts `MachineCaller` (or `AuthUser`) into request extensions and calls `next.run(req)`. See pitfall #1.
3. `Authenticated::from_extensions(req)` helper — handlers that need to distinguish call this; handlers that only care "someone authenticated" keep matching `Extension<AuthUser>`.
4. `require_scope("...")` works for both human and machine callers — it pulls scopes from whichever extension is present and 403s with `insufficient_scope` if the required scope isn't in the list.
5. JTI revocation: client_credentials tokens go through the same `state.repos.revocations.is_token_revoked(jti)` check as user JWTs. Revoked → 401.
6. **Optional sub-task (do this — it's recommended in the issue and unblocks ghostline's resource-binding pattern)**: `handle_client_credentials_grant` accepts `extra_claims: Option<Map<String, Value>>` from the request body, validates each key against the registered client's `allowed_extra_claims` allow-list (new optional column on `yauth_oauth2_clients` — but rather than schema change in M1, store it inside the existing `metadata` JSON column if one exists; otherwise gate this sub-task on M3 schema work), and merges them into the issued JWT. `validate_jwt_as_client` surfaces them on `MachineCaller.custom_claims`. **If the allow-list cannot be stored without a schema change, ship M1 without `extra_claims` and add it as a follow-up — do not block M1.**
7. `AuthUser` semantics unchanged. Every existing test that asserts on `Extension<AuthUser>` still passes.
8. Telemetry: `record_auth_user_on_span` gets a sibling `record_machine_caller_on_span` that sets `client.id`, `yauth.auth_method = "client_credentials"`, scopes joined by space. **Never set `user.id` or `user.email` for machine callers** — they are not users.

### After building, prove it works:

Start `docker compose up -d`. Run all of the following — every one must pass with no warnings:

- `cargo fmt --check`
- `cargo clippy --features full,all-backends -- -D warnings`
- `cargo test --features full,all-backends --test repo_conformance` — all conformance tests still pass (no behavior change to repos)
- `cargo test --features full,all-backends --test pentest` — OWASP suite passes
- `cargo test --features full,all-backends --test diesel_integration` — passes
- `cargo test --features full,all-backends --test memory_backend` — passes
- New integration test (memory + diesel_pg, both): register an oauth2 client with `grant_types: ["client_credentials"]` and `scopes: ["inbox.write"]`, mint a token via the token endpoint, call a route protected by `auth_middleware` + `require_scope("inbox.write")`, expect 200 with `MachineCaller` in extensions and `client_id` matching the registered client.
- New integration test: same flow but with `scopes: ["other"]` registered → token endpoint returns 200 (scope not requested), call route requiring `inbox.write` → 403 `insufficient_scope`.
- New integration test: mint a token, revoke its JTI via `state.repos.revocations.revoke(jti)`, replay → 401.
- New integration test: mint a token with `aud=A`, configure `BearerConfig::audience = Some("B")`, replay → 401.
- New integration test: mint a token, wait until `exp` passes (use a 1-second `access_token_ttl` in the test config), replay → 401.
- **Regression test (highest-priority, do this first)**: a user JWT issued before this change still validates — register a user, log in, hit a protected route → 200 with `Extension<AuthUser>`. The dispatcher change must not break the human-caller path. Run this against memory backend AND diesel_pg.
- bun side: no TS client regeneration is required for M1 (no new public HTTP shapes). If you DO add `extra_claims` to the request body, run `bun generate` and commit `openapi.json` + `packages/client/src/generated.ts`.

### Test strategy:

Tests live in `crates/yauth/tests/` next to the existing oauth2 work. Use the **shared-runtime pattern** (`OnceLock<tokio::runtime::Runtime>` + `#[test]` + `block_on`) — do NOT use `#[tokio::test]` with shared pools (see CLAUDE.md). Schema setup is raw SQL via the existing helpers in `tests/helpers/`. Cover memory backend (always) plus diesel_pg (skip if `DATABASE_URL` unset, the conformance suite pattern).

For the optional `extra_claims` work: if you ship it in M1, add a test that the allow-list rejects un-registered claim keys with a 400 `invalid_request`.

### Known pitfalls:

1. **Don't double-decode the JWT**: `jsonwebtoken::decode::<Claims>` fails fast if the struct doesn't match — but doing two full `decode` calls is wasteful and creates a confusing error story. Decode the header (`decode_header`) + the claims as `serde_json::Value` once, then branch: presence of `client_id` (and absence of `email`) → client path; presence of `email` + `role` → user path. Verify the signature in the chosen-path `decode::<TypedClaims>` call. **Do not** decide based on `find_by_id` failing — a deleted user looks identical to a machine token by that signal.

2. **JTI revocation is currently per-user-token**: confirm `state.repos.revocations.is_token_revoked(jti)` doesn't filter by `user_id`. If it does, generalize the repo method (no schema change — the column is already nullable or a generic string).

3. **Telemetry pitfall**: `crate::otel::set_attribute("user.id", ...)` is a PII-adjacent attribute and must NOT be set for machine callers. Add `client.id` + `yauth.auth_method = "client_credentials"` only. Honeycomb dashboards filter on `user.id IS NOT NULL` to count human sessions — leaking client_id into `user.id` would skew them.

4. **`require_scope` ordering**: the existing impl returns 401 if no `AuthUser` extension is found. After the change, it must check `MachineCaller` first (or `Authenticated` if you wire that up), then fall through to `AuthUser`, and only 401 if neither is present. Don't accidentally invert the order so machine callers always 401.

5. **`validate_aud` quirk in `jsonwebtoken`**: when `BearerConfig::audience` is `None`, `Validation::validate_aud` is set to `false` to allow tokens without an `aud`. For client_credentials tokens this is fine — but if a token *has* an `aud` and the server config has `audience = Some("X")`, the audience must match. Mirror the existing pattern in `validate_jwt` exactly; don't roll your own audience check.

6. **Don't silently accept missing `client_id` claim**: a malformed user token with no `email` could theoretically fall through to the client path and pass shape validation. Require `client_id` in `ClientCredentialsClaims` (no `Option<String>`) and require it equal `sub`. Reject if either is missing.

7. **`AuthMethod::Bearer` overload**: today, `AuthMethod::Bearer` means "user authenticated via JWT". Don't add a `Bearer` variant for machine callers on `AuthUser` — keep them strictly separate. `MachineAuthMethod::ClientCredentials` lives only on `MachineCaller`.

8. **Conformance suite**: M1 changes no repository traits — the 65 conformance tests should pass unmodified. If they don't, you've changed something in `repo/` that you shouldn't have. Revert and re-scope the change.

9. **Feature gating**: `MachineCaller` and `Authenticated` MUST be defined unconditionally in `middleware.rs` (they're public types other crates may want to reference). The `validate_jwt_as_client` function and the `auth_middleware` fall-through arm are gated on `#[cfg(all(feature = "bearer", feature = "oauth2-server"))]` since both crates are required. The token-issuance side already requires `bearer` + `oauth2-server` — match that.

10. **Don't add a `from_pool`-style new constructor to BearerConfig**: existing `BearerConfig` is a plain struct users build directly. Don't introduce a builder for M1 (none of the M1 fields are added). M2 will revisit this when `signing_algorithm` and `signing_key_pem` arrive.
