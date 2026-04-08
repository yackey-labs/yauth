# Milestone 3: Toasty Backends (separate `yauth-toasty` crate)

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

**Prerequisite:** Rust toolchain >= 1.94 (Toasty's MSRV).

**Architecture change:** Toasty backends live in a separate `crates/yauth-toasty` crate (not inside the `yauth` crate) because `toasty-driver-sqlite`'s `rusqlite` dependency uses `libsqlite3-sys 0.37` which conflicts with sqlx's `libsqlite3-sys 0.30` via Cargo's `links = "sqlite3"` check. The separate crate avoids the conflict — it depends on `yauth` (for repo traits) and `toasty`, but doesn't pull in sqlx or diesel.

Users install it via git (not crates.io, since Toasty is experimental):
```toml
yauth = { version = "0.8", features = ["full"] }
yauth-toasty = { git = "https://github.com/yackey-labs/yauth", features = ["postgresql"] }
```

### What must work:
1. `crates/yauth-toasty/` is a new workspace member with features: `postgresql`, `mysql`, `sqlite`
2. Each feature enables the corresponding toasty driver (`toasty/postgresql`, `toasty/mysql`, `toasty/sqlite`)
3. The crate depends on `yauth` (path dep) for `DatabaseBackend`, `Repositories`, all repo traits, domain types, and `RepoError`
4. Three backend structs: `ToastyPgBackend`, `ToastyMysqlBackend`, `ToastySqliteBackend` — each implementing `DatabaseBackend`
5. Per-dialect entities + repo implementations (same pattern as seaorm backends — PG uses native UUID, MySQL/SQLite use String)
6. `Db::builder().table_name_prefix("yauth_")` for the table prefix
7. `migrate()` validates schema only (same as SeaORM backends)
8. `create_tables()` method for test setup (uses `db.push_schema()`)
9. All Toasty backends marked experimental: `#[doc = "Experimental: Toasty is pre-1.0. API may change."]`
10. All 65+ conformance tests pass for each Toasty backend

### Crate structure:
```
crates/yauth-toasty/
  Cargo.toml          # depends on yauth (path), toasty; features: postgresql, mysql, sqlite
  src/
    lib.rs            # feature-gated pub mod pg/mysql/sqlite
    pg/
      mod.rs          # ToastyPgBackend
      entities/       # #[derive(toasty::Model)] with Uuid fields
      *_repo.rs       # repo implementations using Toasty query API
    mysql/
      mod.rs          # ToastyMysqlBackend (String UUIDs)
      entities/
      *_repo.rs
    sqlite/
      mod.rs          # ToastySqliteBackend (String UUIDs, String JSON)
      entities/
      *_repo.rs
```

### After building, prove it works:
Start PostgreSQL and MySQL via `docker compose up -d`.

- Run `cargo test -p yauth-toasty --features postgresql -- --test-threads=1` with `DATABASE_URL` set. All 65+ tests must pass for `toasty_pg`.
- Run `cargo test -p yauth-toasty --features mysql -- --test-threads=1` with `MYSQL_DATABASE_URL` set. All 65+ tests pass for `toasty_mysql`.
- Run `cargo test -p yauth-toasty --features sqlite -- --test-threads=1`. All 65+ tests pass for `toasty_sqlite` (in-memory).
- Run `cargo clippy -p yauth-toasty --features postgresql,mysql,sqlite -- -D warnings` — zero warnings.
- Run `cargo fmt --check` — no formatting issues.
- Verify the main `yauth` crate still compiles and tests pass without `yauth-toasty` in the feature set.

### Test strategy:
- The `yauth-toasty` crate has its OWN conformance test file (not shared with `yauth`'s `repo_conformance.rs`) because it's a separate crate
- Copy the test structure from `crates/yauth/tests/repo_conformance.rs` into `crates/yauth-toasty/tests/conformance.rs`
- Use `#[test]` with a shared tokio runtime (same `OnceLock<Runtime>` pattern)
- Toasty `&mut db` requires `Arc<tokio::sync::Mutex<Db>>` in backend structs

### Known pitfalls:
1. **Toasty is pre-1.0 with sparse docs**: Read the guide links in `dependencies.md` before implementing. Primary reference: https://github.com/tokio-rs/toasty/tree/main/docs/guide/src and https://docs.rs/toasty/0.3.0/toasty/
2. **`table_name_prefix` on Db::builder**: Use `Db::builder().table_name_prefix("yauth_")`. Set `#[table = "users"]` on models, prefix applied at runtime. Verify conformance tests see `yauth_users` in the actual database.
3. **Toasty `#[auto]` for UUIDs defaults to v7**: Matches yauth's convention.
4. **Toasty query API differs from SeaORM**: `Model::get_by_id(&mut db, &id)` (immediate), `Model::filter_by_email("x").get(&mut db)` (builder), `toasty::create!(Model { ... }).exec(&mut db)`.
5. **Toasty takes `&mut db`**: All operations need `&mut db` or `&mut tx`. Backend struct wraps `Db` in `Arc<tokio::sync::Mutex<toasty::Db>>`.
6. **Schema setup for tests**: Use `db.push_schema()` to create tables in test init.
7. **Toasty relationship attributes**: `#[belongs_to(key = user_id, references = id)]` requires explicit key/references.
8. **Missing Toasty features**: Toasty may lack ILIKE, ON CONFLICT, complex JSON operations. Use raw query escape hatch or application-level workarounds. Dialect-specific workarounds may need to live in per-dialect backends.
9. **`yauth-toasty` depends on `yauth` for traits only**: It re-exports `yauth::repo::DatabaseBackend` etc. The `yauth` dep should use `default-features = false` to avoid pulling in any default backend.
10. **Separate conformance tests**: The test file lives in `crates/yauth-toasty/tests/`, not in `crates/yauth/tests/`. It imports repo traits from `yauth` and backend structs from `yauth-toasty`.
