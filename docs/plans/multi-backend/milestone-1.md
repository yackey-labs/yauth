# Milestone 1: Repository Traits + Domain Types

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

Define the trait layer, domain types, and error types that all backends will implement. No existing code is moved yet — this milestone adds new modules alongside the current code.

### What must work:
1. A `src/domain/` module with ORM-agnostic types for every entity currently in `db/models.rs` — `Debug, Clone, Serialize, Deserialize` with standard field types (Uuid, NaiveDateTime, String, etc.). No Diesel derives. No backend dependencies.
2. A `src/repo/` module with sealed repository traits for every aggregate, feature-gated to match their plugin, with methods covering every DB operation currently performed inline in plugins and `state.rs`
3. A `RepoFuture<'a, T>` type alias: `Pin<Box<dyn Future<Output = Result<T, RepoError>> + Send + 'a>>`. All repository trait methods return `RepoFuture<'_, T>`. This is required for object safety — `Arc<dyn XxxRepository>` won't work with `-> impl Future` (RPITIT makes traits non-dyn-compatible).
4. A `RepoError` enum in `src/repo/` using `thiserror::Error` with `Conflict(String)`, `NotFound`, and `Internal(Box<dyn Error + Send + Sync>)` variants. Implements `std::error::Error` + `Display`.
5. A `From<RepoError> for ApiError` conversion so plugin handlers can use `?` on repo calls
6. A sealed trait module (`repo::sealed`) — repository traits require `sealed::Sealed` as a supertrait so only in-crate backends can implement them
7. A `DatabaseBackend` trait in `src/repo/mod.rs` — NOT sealed (consumers may implement custom backends). Uses `BoxFuture` for `migrate()`. Returns `Repositories` from `repositories()`.
8. A `Repositories` struct holding all `Arc<dyn XxxRepository>` trait objects, feature-gated per field
9. An `EnabledFeatures` struct built from compile-time `cfg!()` macros (not runtime config)
10. All new code compiles with `cargo check --features full` without modifying any existing code

### After building, prove it works:
Start by running the full test suite to confirm nothing is broken.

- Run `cargo check --features full` — must compile with zero errors
- Run `cargo check` (default features only) — must compile, feature-gated repos excluded
- Run `cargo test --features full` — all existing tests pass unchanged
- Run `cargo clippy --features full -- -D warnings` — no new warnings
- Inspect the new trait definitions: every `diesel::insert_into`, `diesel::update`, `diesel::delete`, and query in every plugin file (`plugins/*.rs`), `state.rs`, and `db/mod.rs` must have a corresponding trait method. Verify by grepping for `diesel::` and `sql_query` usage and confirming coverage.
- Verify the sealed pattern works: confirm that implementing a repository trait outside of `src/backends/` produces a compile error about `Sealed` not being satisfied

### Test strategy:
No new tests in this milestone — it's pure type definitions. Compilation is the test. The existing test suite must continue to pass since no existing code is modified.

### Known pitfalls:
1. **Missing trait methods**: The single most likely failure mode. Every Diesel query scattered across 13 plugins needs a corresponding trait method. Systematically grep for `diesel::insert_into`, `diesel::update`, `diesel::delete`, `.filter(`, `.find(`, `sql_query` in `plugins/`, `state.rs`, and `db/mod.rs`. Each one maps to a repository method. Missing one means M2 can't eliminate the direct Diesel usage.
2. **Feature-gate alignment**: Repository traits must be gated with exactly the same `#[cfg(feature = "...")]` as their corresponding plugins. If `PasskeyRepository` isn't gated behind `passkey`, it'll pull in types that don't exist without the feature. Mirror the gates from `plugins/mod.rs` and `db/models.rs`.
3. **Domain type field parity**: Domain types must have the exact same fields as the Diesel model structs. Don't accidentally drop nullable fields or change types. The Diesel backend's `into_domain()` / `from_domain()` methods (in M2) will fail to compile if fields diverge — which is the desired outcome.
4. **`RepoError` must cover all current error patterns**: Plugins currently pattern-match on `DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)` → maps to `RepoError::Conflict`. Plugins use `OptionalExtension` for not-found → repo methods return `RepoFuture<'_, Option<T>>` (not a `NotFound` variant for lookups). The `NotFound` variant is for cases where the handler expects a result to exist and wants to `?` into a 404. Make sure the error type is ergonomic for both patterns.
5. **Trait doc comments must specify domain invariants**: Repository traits are the *specification* for what yauth requires from a backend. Every method must document the behavioral contract that all implementations must uphold — not just the signature. Key invariants to document:
   - **`UserRepository::create`** — MUST reject duplicate emails (case-insensitive). Under concurrent callers with the same email, exactly one succeeds, others return `RepoError::Conflict`. This is a safety net for race conditions — OAuth and magic-link flows check `find_by_email` first and only call `create` for genuinely new users. The account-linking flow depends on `find_by_email` discovering existing users, NOT on `create` failing.
   - **`UserRepository::find_by_email`** — MUST be case-insensitive. This is the mechanism for account linking: OAuth callback and magic-link verify both look up by email first, and if a user exists, they link/login to the existing account rather than creating a new one.
   - **Expiration on read** — methods like `find_password_reset_by_token`, `find_magic_link_by_token`, `find_unused_magic_link` MUST return `None` if the token is expired. Postgres does this via WHERE clause; in-memory does it at read time. The invariant is the same.
   - **Cascade on user delete** — deleting a user MUST cascade to passwords, sessions, OAuth accounts, passkeys, MFA secrets, API keys, and all other related entities. Postgres does this via FK constraints; other backends must implement it explicitly.
   - **Uniqueness constraints** beyond email — API key names per user, OAuth provider+provider_id pairs, WebAuthn credential IDs, etc. Document which fields have uniqueness invariants.
6. **Don't conflate M1 and M2 scope**: This milestone only ADDS `src/domain/` and `src/repo/` modules. The existing `db/`, `state.rs`, `plugins/`, and `lib.rs` must remain unchanged and fully functional. M2 is where the builder signature changes, `build()` becomes async, and plugins are rewired. Mixing addition and migration in one step makes failures hard to diagnose.
7. **`Repositories` struct feature gates must compile in all flag combinations**: The struct has `#[cfg(...)]` fields. Ensure it compiles with `--features full`, with default features only, and with individual features enabled. The `DatabaseBackend::repositories()` method must construct it correctly regardless of which features are active.
8. **Don't forget the OAuth state and OIDC nonce tables**: `yauth_oauth_states` (used by OAuth plugin for CSRF state) and `yauth_oidc_nonces` (used by OIDC plugin) need repository traits. These are easy to miss because they're not "user data" — they're flow-management tables. But they're Diesel-queried in the plugins and must be covered.
9. **`BoxFuture` is required for object safety**: Do NOT use `-> impl Future + Send` on repository trait methods — this makes the trait non-dyn-compatible and `Arc<dyn XxxRepository>` won't compile. Use `-> RepoFuture<'_, T>` (which is `Pin<Box<dyn Future<...> + Send + '_>>`). Implementations use `Box::pin(async move { ... })`. The heap allocation per call is negligible for DB operations.
10. **`RepoFuture` lifetime parameter**: The `'a` lifetime in `RepoFuture<'a, T>` ties the future to `&self` — this is needed so implementations can borrow from `self` (e.g., the connection pool) without requiring `'static`. Trait methods should use `-> RepoFuture<'_, T>` to elide the lifetime to `&self`.
