# Milestone 1: SeaORM PostgreSQL Backend

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

### What must work:
1. A user can add `yauth = { features = ["full", "seaorm-pg-backend"] }` to their Cargo.toml and get a working auth backend powered by SeaORM
2. `SeaOrmPgBackend::new(url)` connects to PostgreSQL, `migrate()` validates schema exists (does not run DDL), `repositories()` returns all trait implementations
3. All 27 repository traits (7 core + 20 feature-gated) are implemented using SeaORM queries
4. SeaORM entity modules are publicly exported — users can import entities via the backend (e.g., `yauth::backends::seaorm_pg::entities::users::Entity`) and use them in their own SeaORM queries. Entities live in a shared `seaorm_common` module, re-exported by each per-dialect backend.
5. `cargo yauth generate --orm seaorm` emits SeaORM entity files and optionally a `sea-orm-migration` crate skeleton from the same `TableDef` source of truth
6. All 65+ conformance tests pass for the `seaorm_pg` backend

### After building, prove it works:
Start PostgreSQL via `docker compose up -d`. Run these scenarios:

- Run `cargo test --features full,seaorm-pg-backend --test repo_conformance` with `DATABASE_URL` set. All 65+ tests must pass with the `seaorm_pg` backend appearing in output. No tests may be silently skipped.
- Run `cargo yauth init --orm seaorm --dialect postgres --plugins email-password,passkey,mfa` in a temp directory. Verify it generates SeaORM entity files (one `.rs` per yauth table) with `DeriveEntityModel`, `Relation`, and `ActiveModelBehavior` for every table. Verify the generated code compiles when added to a minimal Cargo project with `sea-orm` as a dependency.
- Build the existing `server` example but swap the backend: create a minimal example that uses `SeaOrmPgBackend` instead of `DieselPgBackend`, starts the server, and responds to `GET /session` (should return 401 unauthenticated). Verify the auth middleware works end-to-end.
- Run `cargo test --features full,all-backends --test repo_conformance` with both `DATABASE_URL` and `MYSQL_DATABASE_URL` set. Verify seaorm_pg runs alongside diesel_pg, sqlx_pg, and memory backends without conflicts.
- Run `cargo clippy --features full,seaorm-pg-backend -- -D warnings` — zero warnings.
- Run `cargo fmt --check` — no formatting issues.

### Test strategy:
- Conformance suite (`crates/yauth/tests/repo_conformance.rs`) is the primary verification — add `seaorm_pg` to `test_backends()` with the same `OnceCell` + `shared_seaorm_pg_repos()` pattern used by other backends
- Use `#[test]` with `shared_runtime().block_on()` — never `#[tokio::test]` (shared pool pattern)
- Unit tests for `into_domain()` / `from_domain()` conversions if any field mapping is non-trivial (e.g., JSON columns, nullable timestamps)

### Known pitfalls:
1. **SeaORM 2.0, not 1.x**: Training data likely contains 1.x patterns. The build agent MUST use 2.0 APIs: import `ExprTrait` for expression methods, use `exec_with_returning` (not `exec_with_returning_many`), use `execute_raw` for raw SQL (not `execute`). Read the migration guide: https://www.sea-ql.org/blog/2026-01-12-sea-orm-2.0/
2. **Entity struct must be named `Model`**: SeaORM's `DeriveEntityModel` expects the struct name `Model` inside each entity module. The `Column` enum, `PrimaryKey` enum, `Relation` enum, and `ActiveModelBehavior` impl are siblings in the same module. Don't try to rename `Model` to `SeaOrmUser` — it won't compile.
3. **Sealed trait**: Every repo struct needs `impl sealed::Sealed for SeaOrmUserRepo {}`. The `sealed` module is `pub(crate)` in `repo/mod.rs`. Missing this causes compile errors about trait bounds.
4. **RepoFuture lifetime**: All repository trait methods return `RepoFuture<'a, T>` which is `Pin<Box<dyn Future<...> + Send + 'a>>`. Clone any borrowed args into owned values before the `async move` block — same pattern as Diesel backends.
5. **Case-insensitive email lookup**: The diesel_pg backend uses `ilike` for `find_by_email`. SeaORM equivalent: use `Expr::col(Column::Email).like(&email.to_lowercase())` after lowercasing, or use the `LOWER()` function via `Func::lower()`. Check how the conformance test asserts this.
6. **UUIDv7**: yauth uses `Uuid::now_v7()` for all IDs. SeaORM entities must use `uuid::Uuid` as the column type with `#[sea_orm(column_type = "Uuid")]`. Don't let SeaORM default to auto-increment integers.
7. **`yauth_` table prefix**: SeaORM has no runtime prefix mechanism (unlike Toasty's `table_name_prefix`). Every entity needs the full prefixed name: `#[sea_orm(table_name = "yauth_users")]` etc. The existing `TableDef` definitions in `yauth-migration` are the source of truth for table names.
8. **Schema validation in `migrate()`**: Query `information_schema.tables` and `information_schema.columns` to verify expected tables/columns exist. Return a descriptive `RepoError::Internal("missing table yauth_users — run SeaORM migrations first")` on failure. Do NOT issue any DDL.
9. **`all-backends` feature**: Add `seaorm-pg-backend` to the `all-backends` list in `Cargo.toml` (MySQL/SQLite SeaORM backends are added in M2, Toasty in M3). Check for symbol conflicts with existing sqlx backends — SeaORM uses sqlx internally, so version alignment matters. Both use sqlx 0.8 currently, which should be compatible.
10. **Repositories construction**: The `repositories()` method must populate ALL fields of the `Repositories` struct, including every `#[cfg(feature = "...")]`-gated field. Copy the pattern exactly from `diesel_pg/mod.rs` — missing a field causes a compile error only when that feature is enabled, which CI catches but local dev might miss.
11. **Conformance test schema setup**: The `migrate()` method only validates — it doesn't create tables. But conformance tests need tables to exist. In the `shared_seaorm_pg_repos()` init, use SeaORM's `Schema::create_table_from_entity()` to generate `CREATE TABLE` DDL from entity definitions and execute it against the test database. This is self-contained (no dependency on Diesel migrations) and validates that the entity definitions match the expected schema. Toasty's equivalent is `db.push_schema()` (covered in M3).
