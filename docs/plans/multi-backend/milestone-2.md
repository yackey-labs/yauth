# Milestone 2: Diesel Backend + Plugin Migration

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

Move all existing Diesel code behind the repository traits. Plugins switch from inline Diesel queries to calling `state.repos.xxx.method()`. The Diesel backend is the first (and initially only) implementation of `DatabaseBackend`.

### What must work:
1. A `DieselPgBackend` struct in `src/backends/diesel/` implements `DatabaseBackend`, constructing all repository impls from a connection pool
2. All `DieselPgBackend` constructors return `Result<Self, RepoError>` — pool creation, schema validation, and instrumentation setup are fallible. `DieselPgBackend::new(url)`, `DieselPgBackend::with_schema(url, schema)`, `DieselPgBackend::from_pool(pool)` (infallible), `DieselPgBackend::from_pool_with_schema(pool, schema)`
3. `DieselPgBackend` construction sets up Diesel query instrumentation (`QueryTracing` + `set_default_instrumentation`) internally — only active when using the Diesel backend
4. `DieselPgBackend::migrate()` runs the existing feature-gated SQL migrations (same code, relocated to `backends/diesel/migrations.rs`)
5. `DieselPgBackend::postgres_pool_for_stores()` returns the pool so Postgres ephemeral stores can use it
6. Diesel-annotated models are private to `backends/diesel/models.rs` with `into_domain()` / `from_domain()` conversion methods (not `From`/`Into` trait impls)
7. Each Diesel repo struct implements `sealed::Sealed` + its repository trait, using `Box::pin(async move { ... })` for all methods
8. Every plugin handler calls repository trait methods via `state.repos.xxx.method()` instead of using Diesel DSL directly
9. `YAuthState.db: DbPool` is replaced by `YAuthState.repos: Repositories`
10. `YAuthBuilder::new()` accepts `impl DatabaseBackend + 'static` instead of `DbPool`
11. `YAuthBuilder::build()` is now `async fn build(self) -> Result<YAuth, RepoError>` — runs migrations, resolves store backend (auto-detect from `postgres_pool_for_stores()` unless explicitly overridden), then builds state
12. Diesel-annotated models, `diesel::table!` schema, and migration SQL runner move to `src/backends/diesel/` (behind `#[cfg(feature = "diesel-backend")]`)
13. Diesel types are no longer re-exported from the crate root; they live in `backends::diesel`
14. The old `db/` module is removed (or reduced to re-exports pointing at `domain/` and `backends::diesel/` for one release cycle)
15. The `create_pool()` free function is removed — replaced by `DieselPgBackend::new(url)`
16. Existing store traits (`SessionStore`, `ChallengeStore`, `RateLimitStore`, `RevocationStore`) migrated from `#[async_trait]` to manual `BoxFuture` (`Pin<Box<dyn Future<...> + Send + '_>>`) for consistency
17. `async_trait` removed as a dependency
18. The full pentest suite passes (255+ cases, 0 FAIL)
19. All existing unit and integration tests pass

### After building, prove it works:
This is the critical milestone. Every auth flow must work identically after the migration.

- Run `cargo test --features full` — all tests pass
- Run `cargo clippy --features full -- -D warnings` — clean
- Run `cargo fmt --check` — clean
- Run `bun validate` — TypeScript packages unaffected
- Run `bun generate:check` — OpenAPI spec and generated client unchanged
- Start the example server: `cargo run --example server --features full` with a Postgres instance
- Run the full pentest suite: `bash pentest/pentest-yauth.sh` — 0 FAIL across all 255+ cases
- Grep for `diesel::` in `plugins/` and `state.rs` — should return ZERO matches (all Diesel usage moved to `backends/diesel/`)
- Grep for `use diesel` in `plugins/` — should return ZERO matches
- Grep for `state.db` in `plugins/` and `state.rs` — should return ZERO matches (replaced by `state.repos`)
- Grep for `async_trait` across the crate — should return ZERO matches
- Verify `DieselPgBackend::with_schema("postgres://...", "auth")` works: create a test database with a non-public schema, run migrations, confirm tables are created in the correct schema
- Verify store auto-detection: build with `DieselPgBackend` and no explicit `with_store_backend()` — ephemeral stores should use Postgres (since pool is available)
- Verify fallible construction: `DieselPgBackend::new("invalid://url")` returns `Err`, not panic

### Test strategy:
Existing tests are the primary validation — they exercise every auth flow. The pentest suite is the integration test. The diesel integration test (`tests/diesel_integration.rs`) must be updated to use `DieselPgBackend` instead of raw pool construction. No new test files needed — the migration is validated by existing tests passing.

### Known pitfalls:
1. **Unique violation semantics**: Plugins currently match `Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _))` for conflict detection (email taken, API key name duplicate, etc.). The Diesel repo impl must catch these and return `RepoError::Conflict(message)`. Map ALL `DatabaseErrorKind` variants the code currently matches — don't just catch the common ones.
2. **Optional extension pattern**: Many queries use `.first().await.optional()` to return `Option<T>` instead of erroring on not-found. Repository methods should return `RepoFuture<'_, Option<T>>` (e.g., `find_by_email` returns a future resolving to `Result<Option<User>, RepoError>`). Don't use `RepoError::NotFound` for lookups — that variant is for handlers to construct when a required entity is missing.
3. **Transaction boundaries**: Some plugin operations need multiple queries in a transaction (e.g., create user + create password in email-password registration). The Diesel backend should handle transactions internally in composite repository methods. Don't expose transaction primitives in the trait — that's backend-specific.
4. **Raw SQL queries**: Several operations use `diesel::sql_query()` for complex operations (rate limiting upserts, challenge store operations, migration introspection). These map to specific repository methods — the trait doesn't care that the impl uses raw SQL. Make sure every `sql_query` callsite is accounted for.
5. **`state.db.get().await` pattern replacement**: Every handler currently does `let mut conn = state.db.get().await.map_err(...)`. After migration, handlers call `state.repos.users.find_by_email(email).await?` directly — no connection management visible in handlers. Don't leave any `state.db` references anywhere.
6. **Diesel re-exports removal**: Consumer apps (freshstrings, vault, nexus, etc.) import `yauth::DieselPool`, `yauth::AsyncPgConnection`, etc. These move to `yauth::backends::diesel::*`. This is a breaking change — document it. The `DieselPgBackend` struct is the new public entry point for Diesel users.
7. **Telemetry attribute continuity**: Current plugins call `crate::otel::set_attribute("yauth.auth_method", ...)` etc. These calls stay in the plugin handlers (they're auth-domain, not DB-domain). Only the DB query tracing (`QueryTracing`) moves into the backend. Don't accidentally move OTel calls that belong in handlers.
8. **Store backend interaction**: The `StoreBackend` enum for ephemeral stores (sessions, challenges, rate limits, revocation) remains **separate** from `DatabaseBackend`. A user might use `DieselPgBackend` + `StoreBackend::Redis`. The Postgres store implementations in `stores/postgres.rs` get the pool via `backend.postgres_pool_for_stores()`. The builder auto-detects: if no explicit `with_store_backend()` and `postgres_pool_for_stores()` returns `Some`, use Postgres stores; otherwise use memory stores. If the user explicitly sets `StoreBackend::Postgres` but the backend returns `None` from `postgres_pool_for_stores()`, `build()` returns an error.
9. **Plugin constructor changes**: Some plugins are constructed in `build()` and access `self.db` (e.g., passkey plugin uses state for WebAuthn init). After migration, the builder has `self.backend` and `repos` instead. Trace through the entire `build()` method carefully — especially the passkey plugin which needs a partial state ref during construction.
10. **Store trait migration from `async_trait` to `BoxFuture`**: Migrating `SessionStore`, `ChallengeStore`, `RateLimitStore`, `RevocationStore` from `#[async_trait]` to manual `Pin<Box<dyn Future<...> + Send + '_>>` is a breaking change for any consumers who implement custom store backends. All three existing implementations (memory, postgres, redis) must be updated — each `async fn method(...)` becomes `fn method(...) -> Pin<Box<...>> { Box::pin(async move { ... }) }`. Batch this with the other breaking changes into one major version bump.
11. **`default` feature must include `diesel-backend`**: For backward compatibility, the `default` features list should include `diesel-backend` so existing consumers who don't specify features continue to compile. The `diesel-backend` feature gates all Diesel-specific code in `backends/diesel/`.
12. **Private Diesel model conversions**: Diesel models in `backends/diesel/models.rs` use `into_domain()` and `from_domain()` methods, NOT `From`/`Into` trait impls. This keeps the conversion private, avoids orphan rule issues, and prevents Diesel types from leaking via trait bounds. If a conversion is wrong, it's a compile error in one file, not a mysterious type mismatch elsewhere.
13. **`telemetry::init()` must stop calling `set_default_instrumentation`**: Currently `telemetry::init()` (line 114 of `telemetry/mod.rs`) registers Diesel's `QueryTracing` instrumentation globally. After the refactor, this is the Diesel backend's responsibility — `DieselPgBackend::new()` calls `set_default_instrumentation` during construction. `telemetry::init()` must be reduced to pure OTel SDK setup: exporter, provider, propagator. Without this change, `telemetry::init()` will panic or silently fail when Diesel isn't compiled in (e.g., `memory-backend` only).
