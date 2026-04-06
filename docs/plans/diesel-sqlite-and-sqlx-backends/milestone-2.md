# Milestone 2: Entity crate + diesel native SQLite backend

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

## What must work:
1. Domain types live in `yauth-entity` with conditional ORM derives — compiles with just `--features diesel` (no sqlx) or just `--features sqlx` (no diesel) or neither (plain types)
2. Diesel `table!` macros are generated from the declarative schema by `yauth-migration`, replacing the hand-written `schema.rs` files in each diesel backend
3. A new `DieselSqliteBackend` uses vanilla SQLite via diesel's built-in `SqliteConnection` + `SyncConnectionWrapper` — register a user, log in, check session, all auth flows work
4. All 64 conformance tests pass for the new diesel-sqlite backend (added to `test_backends()`)
5. The existing diesel-pg, diesel-mysql, and diesel-libsql backends work identically after switching to generated `table!` macros
6. `cargo yauth init --dialect sqlite` generates SQLite-dialect migration SQL
7. All integration tests (pentest, diesel_integration, diesel_mysql_integration, libsql_integration, memory_backend), examples (server, e2e_test), and the OpenAPI generation pipeline updated to import domain types from `yauth-entity`
8. CI runs `cargo yauth generate --check` to verify generated `table!` macros match the declarative schema

## After building, prove it works:
- Run `cargo test --features full,all-backends --test repo_conformance` with `SQLITE_DATABASE_URL=/tmp/yauth_test.db` — all 64 tests pass for diesel-sqlite alongside memory, diesel-pg, diesel-mysql, diesel-libsql
- Build a minimal Axum app with `DieselSqliteBackend::new(":memory:")` — register via email/password, log in, GET /session returns the user, POST /logout invalidates
- Run `cargo test --features full,diesel-sqlite-backend` without other backends — compiles and passes in isolation
- Run `cargo test --features full,diesel-libsql-backend` — still works independently
- Run `cargo test --features full,diesel-pg-backend` — existing backends still pass with generated `table!` macros
- Compile `yauth-entity` with `--features diesel` only, then `--features sqlx` only — each compiles without pulling the other ORM
- Run `cargo test --features full,all-backends --test pentest` — pentest suite passes with new import paths

## Test strategy:
All 64 conformance tests in `repo_conformance.rs` — add diesel-sqlite to `test_backends()` gated on `SQLITE_DATABASE_URL` env var. The shared runtime pattern (`OnceLock<Runtime>` + `#[test]` + `block_on`) is mandatory — never use `#[tokio::test]` with shared pools.

## Known pitfalls:
1. **SyncConnectionWrapper Send bounds**: diesel's SQLite bind collector borrows data (non-Send). `SyncConnectionWrapper` materializes results into owned `Vec`s via `spawn_blocking`. All query building and execution must happen inside the blocking closure — never hold diesel query builder types across an await point.
2. **SQLite single-writer + WAL**: `:memory:` databases need pool max_size=1 (one connection = one database). File databases need `PRAGMA journal_mode=WAL` and pool size 4-8. Follow the `diesel-libsql` backend's existing pool config pattern.
3. **Generated table! macro drift**: if someone edits the declarative schema but forgets to regenerate, diesel queries will silently compile against stale types. CI runs `cargo yauth generate --check` (regenerate + git diff, fail if dirty) — dogfooding the CLI, same pattern as the existing `bun generate:check` for the TS client.
4. **diesel sqlite feature activation**: the workspace `Cargo.toml` currently only enables `postgres_backend` on diesel. The new `diesel-sqlite-backend` feature must add `diesel/sqlite` to get `SqliteConnection` and SQLite type mappings. Don't add it to the workspace default — only activate when the feature flag is on.
5. **RETURNING clause**: diesel's SQLite backend does NOT support `RETURNING` (unlike Postgres and libSQL). Insert-then-select pattern required. Check how the diesel-mysql backend handles this — it has the same limitation.
6. **Update all imports — no re-exports**: breaking changes are fine. Update all tests, examples, and internal code to import domain types directly from `yauth_entity`. Don't add `pub use` re-exports for backwards compat — clean imports only.
7. **OpenAPI generation pipeline**: the `generate_openapi_spec` test in `crates/yauth/tests/generate_client.rs` must be updated to import domain types from `yauth-entity`. The `bun generate` script uses `-p yauth` — verify this still targets the right crate after workspace changes.
8. **Redis caching layer + diesel-sqlite**: the `redis` feature wraps repository traits as a caching decorator. Verify `DieselSqliteBackend` works with `with_redis()` — the `Send + Sync` bounds on `SyncConnectionWrapper` must hold through the redis layer.
9. **`libsqlite3-sys` version conflict**: diesel's `sqlite` feature and `diesel-libsql` both pull `libsqlite3-sys`. If they require incompatible versions, cargo will refuse to build with both enabled. Test `--features diesel-sqlite-backend,diesel-libsql-backend` early. If they conflict, pin via workspace `[patch]` or `[dependencies]`.
