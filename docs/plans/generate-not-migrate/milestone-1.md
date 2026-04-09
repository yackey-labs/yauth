# Milestone 1: Remove migrate() and accept pools only

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This is the breaking change. After this milestone, yauth has no runtime migration system. Backends accept pools, not URLs. All tests pass.

### What must work:

1. `DatabaseBackend` trait has only `fn repositories(&self) -> Repositories` — no `migrate()` method
2. Every backend constructor accepts only a pool/connection (`from_pool()`, `from_connection()`, `from_db()`). No `new(url: &str)` constructors exist.
3. The `Box<dyn DatabaseBackend>` blanket impl is updated to match the simplified trait
4. `YAuthBuilder::new()` and `build()` work without any migration step
5. All 65 conformance tests pass — each backend's test setup creates schema via raw SQL before constructing the backend
6. All pentest and integration tests pass with the same raw-SQL-first pattern
7. The in-memory backend continues to work unchanged (its migrate was already a no-op)

### After building, prove it works:

Start `docker compose up -d` for Postgres + MySQL + Redis. Run these:

- `cargo test --features full,all-backends --test repo_conformance` — all 65 tests pass across all backends
- `cargo test --features full,all-backends --test pentest` — OWASP pentest passes
- `cargo test --features full,all-backends --test diesel_integration` — Diesel PG integration passes
- `cargo test --features full,all-backends --test diesel_mysql_integration` — Diesel MySQL integration passes
- `cargo fmt --check` — no formatting issues
- `cargo clippy --features full,all-backends -- -D warnings` — no warnings

### Test strategy:

The key challenge is test setup. Every test that previously called `backend.migrate()` must now set up schema itself. Pattern:

```rust
// Before
let backend = DieselPgBackend::from_pool(pool.clone());
backend.migrate(&EnabledFeatures::from_compile_flags()).await?;

// After  
setup_schema_raw(&pool).await; // raw SQL: CREATE TABLE IF NOT EXISTS ...
let backend = DieselPgBackend::from_pool(pool.clone());
```

Create a shared test helper (e.g., `tests/helpers/schema.rs`) that generates and runs CREATE TABLE statements for all enabled features. This helper can use `yauth-migration` types since it's test code, not library code.

### Known pitfalls:

1. **SeaORM backends had validate_schema, not migrate**: Their `migrate()` actually just validated tables exist. Removing it means tests must create tables before validation. Use raw SQL in test setup, not SeaORM's schema builder (which would add a runtime dependency on sea-orm-migration).

2. **diesel_pg migrations.rs has `run_declarative_migrations_with_schema()`**: This handles custom PG schema names (e.g., `SET search_path TO auth`). After removal, the test helper must replicate the search_path logic for PG schema tests. The library no longer needs it — the user's Diesel migration handles their own schema name.

3. **sqlx backends reuse diesel_migrations/ SQL via include_str!()**: In M1, remove the migrate() methods and their callers (the `migrations.rs` files). The `diesel_migrations/` SQL files on disk become dead code — M2 deletes the directory entirely.

4. **Conformance tests use OnceLock<Runtime> pattern**: Don't convert to `#[tokio::test]`. Keep the shared runtime pattern. The schema setup helper must work within `block_on()`.

5. **The `EnabledFeatures` struct is still used outside migrate()**: Don't delete it. It's used by the builder and plugin system. Just remove it from the `DatabaseBackend` trait signature.

6. **`from_pool()` on diesel backends is already infallible**: Good — no API change needed. But `with_schema()` on DieselPgBackend returns `Result` because it validates the schema name. Keep that variant but rename it to something like `from_pool_with_schema()` (it may already exist — check).

7. **diesel_integration.rs has `diesel_run_migrations_creates_tables` test**: This test specifically tests the migration system. Delete it — it's testing removed functionality. Keep any non-migration integration tests in the file.

8. **`examples/server.rs` and `examples/e2e_test.rs` likely call migrate()**: Check both examples and update them to assume tables exist (or add a comment saying "run diesel migration run first").
