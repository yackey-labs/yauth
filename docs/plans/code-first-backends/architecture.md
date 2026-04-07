# Architecture

## No Data Model Changes
No new tables or columns. The SeaORM and Toasty backends implement the same schema that already exists — they're alternative ORM layers over the same `yauth_` tables.

## Patterns

### SeaORM shared common module
SeaORM's entities AND `DatabaseConnection` are both database-agnostic. All three SeaORM backends share `backends/seaorm_common/` which contains:
- `entities/` — one file per table (Loco-style) with `Model`, `Column`, `PrimaryKey`, `Relation`, `ActiveModel`, `ActiveModelBehavior`
- Repository trait implementations (e.g., `user_repo.rs`) — use `&DatabaseConnection` which works across PG/MySQL/SQLite

Each per-dialect backend (`seaorm_pg`, `seaorm_mysql`, `seaorm_sqlite`) only contains:
- Backend struct with pool/connection setup
- `DatabaseBackend::migrate()` with dialect-specific schema validation
- Re-exports of `seaorm_common` entities and repo types

Entity modules are `pub` — users can import them for custom SeaORM queries.

Conversion functions: `Model::into_domain(self) -> crate::domain::X` and `ActiveModel::from_domain(input) -> Self` — same pattern as Diesel's `models.rs` but on SeaORM types.

### Toasty shared common module
Toasty's models, `Db` handle, and query API are all database-agnostic (like SeaORM). All Toasty backends share `backends/toasty_common/` which contains:
- `models/` — `#[derive(toasty::Model)]` structs, one per table. Models use `#[table = "users"]` (without prefix); `Db::builder().table_name_prefix("yauth_")` applies the prefix at runtime.
- Repository trait implementations — use `&mut toasty::Db` (via `Arc<tokio::sync::Mutex<Db>>`)

Each per-dialect backend (`toasty_pg`, `toasty_mysql`, `toasty_sqlite`) only contains:
- Backend struct with `Db::builder().connect(url)` setup
- `DatabaseBackend::migrate()` with dialect-specific schema validation
- Re-exports of `toasty_common` models and repo types

Conversion to/from `yauth-entity` domain types follows the same `into_domain()`/`from_domain()` pattern.

### Toasty `&mut db` requires Mutex
Toasty's `Db` handle requires `&mut self` for all operations. The backend struct wraps it in `Arc<tokio::sync::Mutex<toasty::Db>>` so repository trait methods (which take `&self`) can acquire mutable access. This adds per-operation lock overhead but is unavoidable given Toasty's API.

### Schema validation instead of migration execution
For code-first backends, `DatabaseBackend::migrate()` queries the database's information schema to verify all expected yauth tables and columns exist. Returns `RepoError::Internal("missing table yauth_users — run your ORM's migration tool")` on failure. No DDL executed.

### Feature flag pattern
```toml
# Per-dialect features (what users enable)
seaorm-pg-backend = ["dep:sea-orm", "sea-orm/sqlx-postgres", "sea-orm/runtime-tokio-rustls", "sea-orm/macros", "sea-orm/with-chrono", "sea-orm/with-uuid", "sea-orm/with-json"]
seaorm-mysql-backend = ["dep:sea-orm", "sea-orm/sqlx-mysql", "sea-orm/runtime-tokio-rustls", "sea-orm/macros", "sea-orm/with-chrono", "sea-orm/with-uuid", "sea-orm/with-json"]
seaorm-sqlite-backend = ["dep:sea-orm", "sea-orm/sqlx-sqlite", "sea-orm/runtime-tokio-rustls", "sea-orm/macros", "sea-orm/with-chrono", "sea-orm/with-uuid", "sea-orm/with-json"]
toasty-pg-backend = ["dep:toasty", "toasty/postgresql"]
toasty-mysql-backend = ["dep:toasty", "toasty/mysql"]
toasty-sqlite-backend = ["dep:toasty", "toasty/sqlite"]
```

Shared common modules are gated in `backends/mod.rs` with `cfg(any(...))`:
```rust
#[cfg(any(feature = "seaorm-pg-backend", feature = "seaorm-mysql-backend", feature = "seaorm-sqlite-backend"))]
pub(crate) mod seaorm_common;

#[cfg(any(feature = "toasty-pg-backend", feature = "toasty-mysql-backend", feature = "toasty-sqlite-backend"))]
pub(crate) mod toasty_common;
```
The common modules are `pub(crate)` — users access entities/models via the per-dialect backend's re-exports.
All added to `all-backends`. Toasty DynamoDB is out of scope (yauth's schema is relational).

### cargo-yauth / yauth-migration extensions
- `Orm` enum gains `SeaOrm` and `Toasty` variants
- `generate_seaorm_files()`: generates SeaORM entity `.rs` files from `TableDef` source of truth + optionally a `sea-orm-migration` crate skeleton with `SchemaManager` calls
- `generate_toasty_files()`: generates `#[derive(toasty::Model)]` Rust files from `TableDef`
- `cargo yauth init --orm seaorm` and `--orm toasty` work end-to-end

## Cross-Milestone Dependencies
- **M1 → M2**: SeaORM PG establishes the shared entity module and validation pattern. MySQL/SQLite backends reuse entities, only adding dialect-specific pool/connection code.
- **M1 → M3**: Toasty backends follow the same structural pattern (models module, into_domain/from_domain, validation-only migrate) but with Toasty's derive macros instead of SeaORM's.
- **M3 → M4**: The yauth skill update depends on all backends being implemented so the documentation is complete and accurate.
