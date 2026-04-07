# Milestone 2: SeaORM MySQL + SQLite Backends

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

### What must work:
1. A user can add `yauth = { features = ["full", "seaorm-mysql-backend"] }` or `yauth = { features = ["full", "seaorm-sqlite-backend"] }` and get working auth backends
2. `SeaOrmMysqlBackend::new(url)` and `SeaOrmSqliteBackend::new(path)` connect, validate schema, and return all repository trait implementations
3. SeaORM entity definitions are shared across all three SeaORM backends (entities are database-agnostic) — only pool/connection setup and schema validation differ per dialect
4. All 65+ conformance tests pass for both `seaorm_mysql` and `seaorm_sqlite` backends
5. `cargo yauth generate --orm seaorm` emits the same database-agnostic entity files regardless of dialect. The optional `--dialect` flag only affects the `sea-orm-migration` scaffold (DDL syntax).

### After building, prove it works:
Start PostgreSQL and MySQL via `docker compose up -d`.

- Run `cargo test --features full,all-backends --test repo_conformance` with `DATABASE_URL` and `MYSQL_DATABASE_URL` set. All backends (diesel_pg, diesel_mysql, diesel_sqlite, sqlx_pg, sqlx_mysql, sqlx_sqlite, seaorm_pg, seaorm_mysql, seaorm_sqlite, memory) must appear in output and pass all tests.
- For SQLite: conformance tests should create a temp file or use `:memory:` — verify no leftover database files after test run.
- Run `cargo clippy --features full,all-backends -- -D warnings` — zero warnings across all backends compiled together.
- Run `cargo fmt --check` — no formatting issues.
- Run `cargo test --features full,seaorm-mysql-backend --test repo_conformance` in isolation with only `MYSQL_DATABASE_URL` set. Verify seaorm_mysql runs without requiring PostgreSQL.

### Test strategy:
- Add `seaorm_mysql` and `seaorm_sqlite` to `test_backends()` in `crates/yauth/tests/repo_conformance.rs`
- MySQL backend uses `MYSQL_DATABASE_URL` env var (same as diesel_mysql)
- SQLite backend creates a temp database per test run (same pattern as diesel_sqlite)

### Known pitfalls:
1. **Shared entities AND repo implementations**: SeaORM's `DatabaseConnection` is database-agnostic, so entity modules AND repository trait implementations all live in `backends/seaorm_common/` (established in M1). Each per-dialect backend (`seaorm_mysql/mod.rs`, `seaorm_sqlite/mod.rs`) only contains the backend struct, pool setup, `DatabaseBackend` impl, and schema validation — it re-exports entities and repo types from `seaorm_common`.
2. **MySQL schema validation**: MySQL uses `information_schema` differently from PostgreSQL. The `migrate()` validator must query `information_schema.TABLES` and `information_schema.COLUMNS` with the correct database name (extracted from URL), not schema name.
3. **SQLite schema validation**: SQLite has no `information_schema`. Use `PRAGMA table_info(yauth_users)` and `SELECT name FROM sqlite_master WHERE type='table'` instead.
4. **MySQL UUID storage**: MySQL has no native UUID type. SeaORM stores UUIDs as `CHAR(36)`. The conformance tests already verify UUID round-trips — ensure the entity uses `#[sea_orm(column_type = "Char(Some(36))")]` for UUID columns on MySQL, or let SeaORM handle this via `with-uuid` feature mapping.
5. **SQLite datetime precision**: SQLite stores datetimes as TEXT. SeaORM's chrono integration handles this, but verify the conformance test's datetime precision assertions pass.
6. **`all-backends` feature update**: Add `seaorm-mysql-backend` and `seaorm-sqlite-backend` to `all-backends` in Cargo.toml. Watch for symbol conflicts — SeaORM's sqlx dependency must align with yauth's existing sqlx version.
