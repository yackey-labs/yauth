# Milestone 3: Migrate all plugin logging to OTel span events

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

### What must work:
1. All `tracing::error!()` calls in request-handling code across all plugin files become `crate::otel::record_error()` — attached as span events with error status
2. All `tracing::warn!()` calls in request-handling code become `crate::otel::add_event()` — attached as span events without error status
3. All `tracing::info!()` / `tracing::debug!()` calls that carry meaningful request context become `crate::otel::add_event()` span events
4. Operational messages not in request context (if any) use `log::info!()` / `log::warn!()`
5. Example server (`examples/server.rs`) fully migrated from `tracing` to `log` + `env_logger`
6. Zero `use tracing` imports remain anywhere in `crates/yauth/src/` or examples
7. `tracing` and `tracing-subscriber` fully removed from `Cargo.toml` workspace dependencies and crate dependencies
7. `cargo test --features full` passes
8. `cargo clippy --features full -- -D warnings` passes
9. `bun validate` passes (TypeScript packages unaffected but verify)

### Files to migrate (all in `crates/yauth/src/plugins/`):
- `email_password.rs` (~24 tracing calls)
- `passkey.rs` (~29 tracing calls)
- `oauth.rs` (~24 tracing calls)
- `oauth2_server.rs` (~23 tracing calls)
- `mfa.rs` (~22 tracing calls)
- `admin.rs` (~20 tracing calls)
- `account_lockout.rs` (~19 tracing calls)
- `bearer.rs` (~10 tracing calls)
- `magic_link.rs` (~10 tracing calls)
- `api_key.rs` (~5 tracing calls)
- `mod.rs` (~2 tracing calls)
- `stores/postgres.rs` (~3 tracing calls)
- `auth/email.rs` (~1 tracing call)

### After building, prove it works:
- **Full grep**: `grep -rn "use tracing\|tracing::" crates/yauth/src/` returns zero results.
- **Error visibility in traces**: Login with wrong password. Verify the server span in Honeycomb has an error event like `"login_failed"` with relevant attributes — not just a 401 status code.
- **MFA flow events**: Enable MFA, attempt login. Verify the span has events for `"mfa_required"`, `"mfa_pending_session_created"` etc.
- **Passkey flow events**: Register a passkey. Verify span events for each step of the WebAuthn ceremony.
- **No telemetry build**: `cargo check --features "email-password,passkey,mfa,bearer,api-key,admin"` compiles. All `crate::otel::*` calls compile to no-ops.
- **Full test suite**: `cargo test --features full` passes.

### Test strategy:
- `cargo test --features full` — all tests pass
- `cargo clippy --features full -- -D warnings` — clean
- `cargo check` — default features compile
- `cargo check --features "email-password,passkey,mfa,bearer,api-key,admin,oauth,account-lockout,magic-link,webhooks"` — everything except telemetry compiles
- `grep -rn "use tracing" crates/yauth/` returns nothing

### Known pitfalls:
1. **Event naming convention**: Use lowercase snake_case event names matching the operation: `"db_error"`, `"session_created"`, `"mfa_setup_failed"`, `"passkey_registration_error"`. These become queryable fields in Honeycomb. Consistent naming enables `GROUP BY event.name` queries.
2. **Error events need both event + status**: When converting `tracing::error!(...)`, use `crate::otel::record_error(name, &err)` which should call both `span.add_event(name, [KeyValue::new("error.message", err)])` AND `span.set_status(Status::error(err))`. Warnings only add events, no error status.
3. **Structured attributes on events**: Where the current code uses structured fields like `tracing::error!(session_id = %s.id, "mismatch")`, convert to span event attributes: `add_event("session_mismatch", &[KeyValue::new("session.id", s.id.to_string())])`. Don't lose the structured fields — they're high-cardinality dimensions Honeycomb can query.
4. **Don't add events for trivial debug logs**: If a `tracing::debug!()` just says "entering function" with no useful attributes, drop it rather than converting. Only convert logs that carry meaningful request context or error information.
5. **Plugin feature gating**: Some plugins are behind their own feature flags (`passkey`, `mfa`, `oauth`, etc.). The `crate::otel` helpers work regardless of which plugin features are enabled because they're gated on `telemetry`, not on plugin features. No cross-feature issues.
6. **Bulk migration strategy**: Work file by file. For each file: remove `use tracing::*`, add `use crate::otel`, convert each call. Compile-check after each file. Don't batch — a single typo in a batch breaks the entire build.
