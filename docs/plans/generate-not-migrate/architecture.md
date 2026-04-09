# Architecture

## What Changes

### DatabaseBackend trait (crates/yauth/src/repo/mod.rs)

Before:
```rust
pub trait DatabaseBackend: Send + Sync {
    fn migrate(&self, features: &EnabledFeatures) -> Pin<Box<...>>;
    fn repositories(&self) -> Repositories;
}
```

After:
```rust
pub trait DatabaseBackend: Send + Sync {
    fn repositories(&self) -> Repositories;
}
```

`EnabledFeatures` struct stays — it's used elsewhere for feature detection at runtime. But it's no longer passed to any backend method.

### Backend constructors

Before: `new(url: &str)` creates pool internally, `from_pool()` accepts existing pool.
After: Only `from_pool()` (or `from_connection()` for SeaORM, `from_db()` for Toasty). No URL-accepting constructors.

### yauth-migration decoupling

Before: `yauth` depends on `yauth-migration` at runtime. `crates/yauth/src/schema/mod.rs` re-exports types. Backend `migrations.rs` files use `include_str!()` for SQL and call schema collection functions.

After: `yauth-migration` is a dependency of `cargo-yauth` only. The `schema` module in `yauth` is removed entirely. `YAuth::schema()` and `YAuth::generate_ddl()` are removed — schema introspection is `cargo-yauth`'s job, not the library's. The `plugin.rs` trait's `fn schema()` method is removed — plugins no longer carry schema metadata at runtime.

### Files deleted

Per backend, delete:
- `backends/*/migrations.rs` — runtime migration logic
- `diesel_migrations/` directory — embedded SQL files deleted entirely (cargo-yauth generates fresh SQL from plugin schemas in yauth-migration, these pre-written files are redundant)

In schema module:
- `crates/yauth/src/schema/mod.rs` — remove yauth-migration re-exports
- `crates/yauth/src/schema/postgres_runtime.rs` — runtime DDL generation

### cargo-yauth generate additions

New output for `--orm sqlx`:
- `.sql` query files per repository operation (e.g., `find_user_by_email.sql`, `create_session.sql`)
- Placed in a user-configurable directory (default: `queries/`)
- Each file contains a single parameterized SQL query with comments documenting parameters and return types

## Patterns

- **User owns the pool**: yauth never creates connections. The user creates their pool with their config and hands it to yauth. This is how every mature Rust library works (sqlx, sea-orm, deadpool all expect the caller to own the pool).
- **User owns the schema lifecycle**: yauth generates files. The user applies them with their ORM's CLI. yauth assumes tables exist at runtime.
- **Generated files are plain, idiomatic**: Diesel migrations look like any other Diesel migration. sqlx queries look like any other sqlx query file. SeaORM entities look like any other SeaORM entity. No yauth-specific abstractions in generated output.

## Cross-Milestone Dependencies

- **M1 → M2**: M1 removes migrate() and URL constructors. M2 removes the yauth-migration dependency. M2 can't happen first because the migration code uses yauth-migration types.
- **M2 → M3**: M3 (sqlx query gen) is purely cargo-yauth work and technically independent of M2. But sequencing after M2 ensures a clean separation — all schema/generation logic lives in cargo-yauth before adding new generation features to it.
- **M3 → M4**: M4 (docs/skill/example updates) depends on the API being finalized in M1-M3.

## Scope of External Repos

- `~/fj/skills/plugins/yauth/` — Skill SKILL.md rewritten to reflect no-migrate, pool-first, generate-only workflow
- `~/fj/yauth-toasty-example/` — Example updated: verify no yauth migrate() call exists (it already uses Toasty's `push_schema()`), update README to reflect generate-not-migrate workflow
- `~/fj/yauth/README.md` — Rewrite quick-start and backend sections
- `~/fj/yauth/CLAUDE.md` — Update architecture section, remove migration references
