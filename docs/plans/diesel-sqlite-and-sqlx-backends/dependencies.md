# Dependencies

## Existing
- `diesel 2.3` — ORM for Postgres, MySQL, libSQL backends. Will also be used for native SQLite via its `sqlite` feature (currently only `postgres_backend` enabled in workspace)
- `diesel-async 0.8` — async connection wrappers for diesel. Will use its `sqlite` feature for `SyncConnectionWrapper<SqliteConnection>` (runs sync SQLite on `spawn_blocking`)
- `diesel-libsql 0.1.4` — third-party diesel backend for Turso/libSQL. Stays as-is for remote Turso use cases
- `serde`, `serde_json`, `uuid`, `chrono`, `thiserror` — shared domain types, will move to `yauth-entity`
- `sha2` — used in `yauth` for HIBP password checking AND in schema hash tracking. The schema hash usage moves to `yauth-migration`; `sha2` remains a dep of both crates.

## To Add
- `sqlx 0.8` — async, pure-Rust database driver with compile-time checked queries via `query!()` macro. Supports pg, mysql, sqlite. Alternative: `sea-orm` (too heavy, adds another ORM layer). [docs.rs/sqlx](https://docs.rs/sqlx)
- `toml 0.8` — parse/write `yauth.toml` config files. Alternative: `serde_yaml` (TOML is more standard for Rust tooling). [docs.rs/toml](https://docs.rs/toml)
- `clap 4` — CLI argument parsing for `cargo-yauth`. Alternative: `argh` (less ecosystem support). [docs.rs/clap](https://docs.rs/clap)
- `dialoguer` — interactive prompts for `cargo yauth init`. Alternative: `inquire` (either works, dialoguer is more established). [docs.rs/dialoguer](https://docs.rs/dialoguer)
- `similar` — text diffing for showing SQL migration diffs in `cargo yauth add-plugin` / `remove-plugin` output. Alternative: `diff` crate (similar has better color output support). [docs.rs/similar](https://docs.rs/similar)
- `assert_cmd` (dev) — integration testing for the `cargo-yauth` CLI binary. [docs.rs/assert_cmd](https://docs.rs/assert_cmd)

## Approach Decisions
- **Native SQLite driver**: diesel's built-in `SqliteConnection` via `SyncConnectionWrapper` (not a new `diesel-libsql` variant) because it uses vanilla SQLite (`libsqlite3-sys`), has no third-party deps, and matches what most diesel users expect. `diesel-libsql` stays for Turso users.
- **sqlx query style**: `query!()` / `query_as!()` macros (compile-time checked) with offline mode (`.sqlx/` cache committed to repo), NOT runtime `query()` strings. Gives downstream users compile-time SQL safety. Each backend has dialect-specific query modules since SQL differs (`$1` vs `?`, `RETURNING` vs not, `ILIKE` vs `LOWER() LIKE`).
- **Migration ownership**: `yauth-migration` is a code generator that writes files into the user's project in their ORM's format (diesel `up.sql`/`down.sql`, sqlx numbered `.sql`). The user's ORM owns tracking (`__diesel_schema_migrations` or `_sqlx_migrations`). yauth does NOT run its own migration tracker at runtime.
- **Config file**: `yauth.toml` in the user's project root stores ORM choice, dialect, migrations directory, table prefix, PG schema, and enabled plugins. All CLI commands read this file — no heuristic detection.
- **Table prefix**: Fully configurable via `yauth.toml` (`table_prefix = "auth_"` produces `auth_users`, `auth_sessions`, etc.). Default remains `yauth_`.
- **`libsqlite3-sys` version alignment**: diesel's `sqlite` feature and `diesel-libsql` both pull in `libsqlite3-sys` transitively. If they require different semver-incompatible versions, cargo will fail. Pin to a single version in `[patch]` or workspace deps if needed. Test that `diesel-sqlite-backend` and `diesel-libsql-backend` can be enabled simultaneously.
