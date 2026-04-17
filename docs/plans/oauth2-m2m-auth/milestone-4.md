# Milestone 4: Admin surface + audit enrichment for M2M (when both `admin` and `oauth2-server` are enabled)

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone closes the operational gap M1–M3 opens: once machine callers are real, admins need a kill switch for compromised clients and a queryable audit trail. **Conditionally compiled** — every route, column, and check in this milestone is gated on `#[cfg(all(feature = "admin", feature = "oauth2-server"))]`. Builds without `admin` are byte-for-byte unchanged.

### What must work:

1. **OAuth2 client management routes** under `/admin/oauth2/clients` (mounted from `admin.rs`, layered with the existing `require_admin` middleware):
   - `GET /admin/oauth2/clients` — paginated list (mirrors `list_users` shape: `page`, `per_page`, `search` by `client_id` / `client_name`).
   - `GET /admin/oauth2/clients/{id}` — full client record minus `client_secret_hash`.
   - `DELETE /admin/oauth2/clients/{id}` — hard delete, cascades to authorization_codes / consents / device_codes per existing FKs.
   - `POST /admin/oauth2/clients/{id}/ban` — sets `banned=true`, body `{ reason: Option<String> }`. Banned clients are rejected at the token endpoint (both `client_secret` and `private_key_jwt` paths) with `error=invalid_client`, "Client is suspended".
   - `POST /admin/oauth2/clients/{id}/unban` — sets `banned=false`, clears `banned_reason` / `banned_at`.
   - `POST /admin/oauth2/clients/{id}/rotate-secret` — generates a new `client_secret`, updates `client_secret_hash`, returns the new plaintext secret in the response (same one-shot pattern as user API key creation). Refuse if the client is registered for `private_key_jwt` only.
   - `POST /admin/oauth2/clients/{id}/rotate-public-key` (gated on M3 + `asymmetric-jwt`) — body `{ public_key_pem: String }` or `{ jwks_uri: String }`. Validates the new key parses (RSA or P-256), then atomically swaps. Existing assertions signed by the old key continue to work until they expire (no global revocation — admins can issue a separate "revoke all client tokens" if needed; out of scope here).

2. **Schema additions to `yauth_oauth2_clients`** (in `crates/yauth-migration/src/plugin_schemas.rs::oauth2_server_schema`):
   - `banned BOOLEAN NOT NULL DEFAULT false`
   - `banned_reason VARCHAR NULL`
   - `banned_at DATETIME NULL`
   The token endpoint (both grant paths) reads `banned` after `lookup_client` and rejects before issuing.

3. **`require_admin` parity for machine callers — opt-in only.**
   - New field `AdminConfig::allow_machine_callers: bool` (default `false`).
   - When `false` (default): `require_admin` returns 403 for `MachineCaller` extensions, 200 only for `AuthUser` with `role == "admin"`. Existing behavior unchanged.
   - When `true`: `require_admin` accepts a `MachineCaller` if it carries scope `admin` (literal — not `admin:*` patterns; keep the surface small for M4). Document loudly in `docs/configuration.md` that this dramatically expands attack surface and should only be enabled for ops automation.
   - Telemetry: when admin allows a machine caller, emit a span event `admin_machine_call` with `client.id` so misuse is queryable.

4. **Audit log enrichment** — extend `yauth_audit_log` (in `crates/yauth-migration/src/core.rs::audit_log_table`):
   - Add `actor_client_id UUID NULL` with FK to `yauth_oauth2_clients(id)` `ON DELETE SET NULL` (mirroring the `user_id → users` pattern).
   - **Discriminator is implicit**: exactly one of `user_id` / `actor_client_id` is set per row. Both null = system event (e.g., scheduled cleanup) — already happens today.
   - Update `state.write_audit_log(...)` signature OR add a sibling `write_audit_log_for_client(...)`. Pick whichever causes less call-site churn — likely a new param `actor: Option<AuditActor>` enum.
   - Backfill: not required (column is nullable). Existing rows have `actor_client_id IS NULL` and the implicit user/system semantics apply unchanged.

5. **Audit-log every new admin action.** Each new admin route writes an audit_log row (mirrors the existing pattern at `admin.rs:287, 340, 425, 485`). Event types and metadata:
   - `oauth2_client_banned` — `{ target_client_id, reason }`
   - `oauth2_client_unbanned` — `{ target_client_id }`
   - `oauth2_client_deleted` — `{ target_client_id, client_name }`
   - `oauth2_client_secret_rotated` — `{ target_client_id }` (NEVER log the new secret)
   - `oauth2_client_public_key_rotated` — `{ target_client_id, key_source: "pem" | "jwks_uri" }`
   - `admin_machine_call_allowed` — `{ route, scopes }` written when `allow_machine_callers=true` accepts a `MachineCaller` for an admin route — high-signal for misuse detection.
   For each row, populate `user_id` from the calling `AuthUser` (or `actor_client_id` from the calling `MachineCaller` when `allow_machine_callers=true`), demonstrating the new `actor_client_id` column end-to-end.
6. Also audit at the **token-endpoint ban check**: when a banned client attempts to mint, write `oauth2_token_denied_banned` with `{ client_id }`. This is the data ops needs to detect "compromised credentials being actively reused after ban".
7. **TS client + OpenAPI**: new admin endpoints + new request/response shapes. Run `bun generate`, commit `openapi.json` and `packages/client/src/generated.ts`.

### After building, prove it works:

Start `docker compose up -d`. Run all of:

- `cargo fmt --check`
- `cargo clippy --features full,all-backends -- -D warnings`
- `cargo clippy --features bearer,oauth2-server,memory-backend -- -D warnings` — confirms admin-off path still compiles cleanly (no leaked admin types).
- `cargo test --features full,all-backends --test repo_conformance` — passes; nullable column on existing table is non-breaking.
- `cargo test --features full,all-backends --test pentest`
- `cargo test --features full,all-backends --test diesel_integration`
- `bun validate:ci`
- New integration test: register client → admin bans it → token endpoint rejects with `invalid_client` "suspended". Admin unbans → token endpoint succeeds again.
- New integration test: admin rotates secret → old secret rejected, new secret accepted. JWTs already issued under the old secret continue to validate until they expire (rotating the client secret does NOT invalidate outstanding JWTs — that's a separate "revoke all tokens" operation; document this).
- New integration test (M3-gated): admin rotates `public_key_pem` for a `private_key_jwt` client → assertions signed with the new key pass, with the old key fail. Old PEM not parseable → 400 with a typed error.
- New integration test: with `allow_machine_callers=false` (default), client_credentials token with scope `admin` → 403 on `/admin/users`. With `allow_machine_callers=true` AND scope `admin` → 200. Without scope `admin` → 403 in both modes.
- New audit-log integration test: machine caller hits a route that writes audit (e.g., banning another client via M4 itself when `allow_machine_callers=true`); query `yauth_audit_log` and assert `actor_client_id IS NOT NULL`, `user_id IS NULL`, `event_type = "oauth2_client_banned"`, and `metadata.target_client_id` matches.
- New audit-log integration test: human admin bans a client; assert `user_id IS NOT NULL`, `actor_client_id IS NULL`, same event_type. Both cases coexist in the table.
- New audit-log integration test: banned client attempts to mint a token; assert an `oauth2_token_denied_banned` row exists with `actor_client_id` set to the banned client's id.
- Generate-not-migrate gate: `cargo yauth generate --check -f yauth.toml` passes locally before opening the PR.

### Test strategy:

Same shared-runtime / `OnceLock` pattern. Memory backend tests + diesel_pg tests minimum. Reuse the M1 oauth2-client fixtures. For the rotate-public-key test, reuse the M2 test fixture PEMs.

For the `allow_machine_callers` test, build two `YAuth` instances side-by-side in the same test file with different `AdminConfig` — both use their own pool / schema (or the memory backend) so they don't interact.

### Known pitfalls:

1. **`banned` check ordering at the token endpoint**: the check must run AFTER client lookup but BEFORE secret/assertion verification. Otherwise an attacker brute-forcing a banned client's secret learns the ban status from timing. Place it as the first post-lookup check, returning the same `invalid_client` error code for ban + bad-secret + bad-assertion (different `error_description` is fine — pentest already accepts that pattern).

2. **`rotate-secret` for `private_key_jwt` clients**: refuse with 400 `invalid_request` ("Client is configured for private_key_jwt; use rotate-public-key instead"). Otherwise admins create a hybrid state where both a secret AND a public key are valid, doubling the attack surface.

3. **`actor_client_id` FK behavior**: use `OnDelete::SetNull` so deleting an OAuth2 client doesn't cascade-delete years of audit history. Mirrors the existing `user_id` FK behavior on the same table — be consistent.

4. **`admin` scope literal**: don't be clever with patterns. `admin:users:write` etc. is a future ticket. Pitfall: the OAuth2 server's scope-check today does literal string compare against `registered_scopes`. Adding wildcard semantics here would require updating that path too — out of scope.

5. **Audit-log writer drift**: there will be ~20+ call sites of `write_audit_log` across the codebase. If you change its signature, you must update every caller in one PR. If that's too churny, add `write_audit_log_for_client` as a sibling and use it only from the new code paths — leave existing callers alone. Pick whichever produces a smaller diff.

6. **`AdminConfig` may not exist yet**: if there's no `AdminConfig` struct in `config.rs`, create one (gated on `admin` feature) with the single field `allow_machine_callers: bool`. Add it to `YAuthConfig` and `YAuthBuilder::with_admin(config)`. Default-off.

7. **Telemetry PII rule still applies**: when a machine caller hits an admin route under `allow_machine_callers=true`, set `client.id` on the span — NOT `user.id`. The `record_machine_caller_on_span` from M1 already does this; just confirm it runs on admin routes.

8. **Pentest must learn the ban check**: add cases — banned client mints token (must 401), banned client validates an outstanding token (must 401 — yes, ban also rejects existing tokens at validation time; this is a deliberate choice for the kill switch to actually kill). Wire the ban check into both `validate_jwt_as_client` (M1) and the token endpoint. Without ban-on-validation, the kill switch only stops new mints.

9. **Schema diff order**: `yauth_oauth2_clients` already exists. The diff engine produces an `ALTER TABLE ADD COLUMN` migration. SQLite's `ALTER TABLE` is limited — verify the generated SQLite migration uses table-rebuild if the diff engine doesn't already handle it (check `generate-not-migrate` plan's history for prior precedent). Run `cargo yauth generate` against all three dialects and inspect the diff.

10. **Don't expose `client_secret_hash` from any admin endpoint**: response types must omit it. Easiest path: a dedicated `AdminClientInfo` serialization struct (mirroring `AdminUserInfo`), not a passthrough of the entity row.
