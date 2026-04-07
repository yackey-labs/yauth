# Milestone 3: Toasty Backends

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

**Prerequisite:** Rust toolchain >= 1.94 (Toasty's MSRV).

### What must work:
1. A user can add `yauth = { features = ["full", "toasty-pg-backend"] }` (or `toasty-mysql-backend`, `toasty-sqlite-backend`) and get a working auth backend powered by Toasty
2. `ToastyPgBackend::new(url)` connects to PostgreSQL via `toasty::Db::builder().table_name_prefix("yauth_").models(toasty::models!(...)).connect(url)`, validates schema, and returns all repository trait implementations
3. All 27 repository traits implemented using Toasty's query API (`Model::get_by_id()`, `Model::filter_by_*()`, `toasty::create!()`, etc.). Models and repo implementations are shared in `toasty_common/` (same pattern as SeaORM). Per-dialect backends only contain pool setup and schema validation.
4. Toasty model definitions are publicly exported so users can use them alongside their own Toasty models
5. `cargo yauth generate --orm toasty` emits `#[derive(toasty::Model)]` Rust files from the `TableDef` source of truth
6. All 65+ conformance tests pass for `toasty_pg`, `toasty_mysql`, and `toasty_sqlite` backends
7. Toasty backends are marked experimental with `#[doc = "Experimental: Toasty is pre-1.0. API may change."]`

### After building, prove it works:
Start PostgreSQL and MySQL via `docker compose up -d`.

- Run `cargo test --features full,toasty-pg-backend --test repo_conformance` with `DATABASE_URL` set. All 65+ tests must pass for `toasty_pg`.
- Run `cargo test --features full,all-backends --test repo_conformance` with all database URLs set. Verify Toasty backends appear alongside all other backends in output and all pass.
- Run `cargo yauth init --orm toasty --dialect postgres --plugins email-password,passkey,mfa` in a temp directory. Verify generated files contain `#[derive(toasty::Model)]` structs with correct `#[key]`, `#[table = "users"]` (prefix applied at runtime), `#[belongs_to]`, `#[has_many]` attributes. Verify the generated code compiles.
- Run `cargo clippy --features full,all-backends -- -D warnings` with zero warnings.
- Run `cargo fmt --check` — no formatting issues.

### Test strategy:
- Add `toasty_pg`, `toasty_mysql`, `toasty_sqlite` to `test_backends()` in `crates/yauth/tests/repo_conformance.rs`
- Toasty backends need schema setup before tests. Use `db.push_schema()` in the `OnceCell` init (acceptable for test environments)
- Same `shared_runtime().block_on()` pattern as all other backends

### Known pitfalls:
1. **Toasty is pre-1.0 with sparse docs**: The build agent MUST read the guide links in `dependencies.md` before implementing. The primary reference is the GitHub guide at https://github.com/tokio-rs/toasty/tree/main/docs/guide/src and the API docs at https://docs.rs/toasty/0.3.0/toasty/
2. **`table_name_prefix` on Db::builder**: Toasty natively supports `Db::builder().table_name_prefix("yauth_")`. Use this instead of hardcoding `#[table = "yauth_users"]` on every model. Set `#[table = "users"]` on the model and let the prefix do the work. Verify the conformance tests see `yauth_users` in the actual database.
3. **Toasty `#[auto]` for UUIDs defaults to v7**: `#[auto]` on a `uuid::Uuid` field generates UUID v7 by default. This matches yauth's convention. No special config needed.
4. **Toasty query API is different from SeaORM**: Toasty uses `Model::get_by_id(&mut db, &id)` (immediate), `Model::filter_by_email("x").get(&mut db)` (builder), and `toasty::create!(Model { ... }).exec(&mut db)`. Don't confuse with SeaORM's `Entity::find_by_id(id).one(&db)` pattern.
5. **Toasty takes `&mut db`**: All Toasty operations take `&mut db` or `&mut tx`. The backend struct needs `Arc<tokio::sync::Mutex<toasty::Db>>` since `Db` owns the connection pool internally and repo methods need shared mutable access.
6. **Toasty migration for tests**: Use `db.push_schema()` to create tables in test setup. For the `migrate()` validation in production, query `information_schema` (PG/MySQL) or `sqlite_master` (SQLite) same as SeaORM backends.
7. **Toasty relationship attributes**: `#[belongs_to(key = user_id, references = id)]` requires explicit key and references. Toasty doesn't infer foreign key columns. Map every `ForeignKey` from `TableDef` to the correct `belongs_to` attribute.
8. **Missing Toasty features**: Toasty may not support all SQL operations yauth needs (e.g., `ILIKE` for case-insensitive email, `ON CONFLICT` for upserts, complex JSON operations). For unsupported operations, use Toasty's raw query escape hatch or implement in application code. Document any workarounds. Note: if workarounds are dialect-specific (e.g., PG `ILIKE` vs MySQL case-insensitive collation vs SQLite default case-insensitivity), they may need to live in the per-dialect backend rather than `toasty_common`, breaking the fully-shared pattern.
9. **`all-backends` update**: Add all three toasty backends to `all-backends`. Toasty uses its own driver crates (not sqlx), so no symbol conflicts with SeaORM or sqlx backends expected.
