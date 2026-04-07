# Architecture

## Crate Structure

Current: single `yauth` crate with everything.

Target: three library crates + one CLI binary, all workspace members.

```
crates/
  yauth-migration/    # lib — schema types, DDL gen, diff engine, migration file gen. Zero ORM deps.
  yauth-entity/       # lib — domain types + conditional ORM derives (diesel/sqlx feature-gated). No dep on yauth-migration.
  yauth/              # lib — backends, plugins, builder, middleware. Depends on both above.
  cargo-yauth/        # bin — CLI. Depends only on yauth-migration + toml + clap + dialoguer.
```

- `yauth-migration` and `yauth-entity` are **independent** — domain types (`User`, `Session`) don't need schema types (`TableDef`, `ColumnType`). They share no dependency.
- `yauth` depends on both — it uses entities for runtime data and migration for schema generation.
- `cargo-yauth` is a **separate crate published to crates.io** (`cargo install cargo-yauth`). It depends only on `yauth-migration` — no diesel, no sqlx, no axum. Lightweight install for anyone who just needs the migration tooling.
- Cargo discovers it as a subcommand automatically (binary named `cargo-yauth` → invoked as `cargo yauth`).

Future: when compile times / disk space warrant it, extract each backend into its own crate (`yauth-diesel-pg`, `yauth-sqlx-pg`, etc.). Module boundaries built here make that mechanical.

## Feature Flag Redesign

Split `full` into composable groups so users don't compile every ORM and database driver:

```toml
# All auth plugins — this is what "full" means to users
full = ["email-password", "passkey", "mfa", "oauth", "bearer",
        "api-key", "magic-link", "admin", "status", "oauth2-server",
        "account-lockout", "webhooks", "oidc", "telemetry", "openapi"]

# Backends — pick one per app
diesel-pg-backend = [...]
diesel-mysql-backend = [...]
diesel-sqlite-backend = [...]
diesel-libsql-backend = [...]
sqlx-pg-backend = [...]
sqlx-mysql-backend = [...]
sqlx-sqlite-backend = [...]
memory-backend = []

# CI-only — every backend + redis, for conformance testing
all-backends = ["diesel-pg-backend", "diesel-mysql-backend",
                "diesel-sqlite-backend", "diesel-libsql-backend",
                "memory-backend", "sqlx-pg-backend", "sqlx-mysql-backend",
                "sqlx-sqlite-backend", "redis"]
```

Real apps use `full` + one backend (e.g., `yauth = { features = ["full", "diesel-pg-backend"] }`). `all-backends` exists only for CI conformance testing — never recommended for production. CI runs `--features full,all-backends`.

## Data Model Changes

No schema changes — same tables, same columns. The change is WHERE schema definitions live (extracted to `yauth-migration`) and HOW migrations are delivered (generated files in user's project, not runtime auto-apply).

## Key Patterns

### yauth.toml config file
```toml
[migration]
orm = "diesel"                  # "diesel" | "sqlx"
dialect = "postgres"            # "postgres" | "mysql" | "sqlite"
migrations_dir = "migrations"
schema = "public"               # PG schema (optional)
table_prefix = "yauth_"        # fully configurable

[plugins]
enabled = ["email-password", "passkey", "mfa"]
```

Created by `cargo yauth init`. Read by all CLI commands. The diff engine compares `[plugins].enabled` against previously generated state to produce incremental migrations.

**No secrets in config:** `yauth.toml` intentionally has no `database_url` field. Database URLs come from environment variables only (`DATABASE_URL`, `SQLX_PG_DATABASE_URL`, etc.). This means `yauth.toml` is always safe to commit — no risk of leaking production connection strings. The CLI reads env vars for any command that needs a database connection (e.g., `cargo yauth generate` for sqlx offline caches).

All CLI commands accept `-f <path>` to specify a config file (default: `yauth.toml`). This supports:
- **Multiple environments**: `yauth.dev.toml` (sqlite), `yauth.prod.toml` (postgres)
- **CI per-backend checks**: `cargo yauth generate --check -f yauth-sqlx-pg.toml`
- **yauth repo itself**: one config per backend dialect for generating/checking all artifacts. The yauth repo fully dogfoods the CLI — conformance tests use generated migrations, not the runtime `backend.migrate()` auto-migrator. If the CLI generates broken migrations, tests fail.

**Tooling benefit:** Any tool that reads `yauth.toml` (the CLI, CI, Claude Code skills) immediately knows the ORM, dialect, enabled plugins, table prefix, and migrations directory — no project exploration needed. A yauth-aware Claude Code skill can skip irrelevant suggestions (no sqlx advice for diesel users), use the correct table names in SQL snippets, and only surface docs for enabled plugins.

### CLI + Skill integration
The CLI and a Claude Code skill serve complementary roles:
- **CLI** handles schema/migration generation — works standalone for any developer, no AI required.
- **Skill** handles app code integration — adds yauth to `Cargo.toml`, wires up `YAuthBuilder`, adds middleware to the router, sets up config with sensible defaults based on codebase context.

The skill calls the CLI under the hood. All interactive CLI prompts (`--orm`, `--dialect`, `--plugins`, `--prefix`) have flag equivalents so the skill can pre-fill answers from codebase analysis (reads `Cargo.toml` for ORM, `DATABASE_URL` for dialect, user intent for plugins) and run `cargo yauth init` non-interactively. Interactive `dialoguer` prompts are only for humans running the CLI directly.

### Schema diff engine
Compares two `YAuthSchema` snapshots (previous plugins vs current) and produces:
- `CREATE TABLE` for newly enabled plugins
- `DROP TABLE` for removed plugins
- `ALTER TABLE ADD/DROP COLUMN` for schema evolution
- Dialect-specific SQL using the existing DDL generators

### Migration file generation
Same diff, different output formats:
- **diesel**: `up.sql` / `down.sql` pairs in timestamped directories
- **sqlx**: sequentially numbered `.sql` files

### SyncConnectionWrapper for diesel SQLite
`diesel-async` has no native async SQLite. `SyncConnectionWrapper<SqliteConnection>` wraps diesel's sync `SqliteConnection` and runs queries via `spawn_blocking`. All query building must happen inside the blocking closure. Pool via `deadpool`.

### sqlx compile-time queries with offline mode
Each sqlx backend has its own query module with dialect-specific SQL. `cargo yauth generate` runs `cargo sqlx prepare` internally for each sqlx backend, generating the `.sqlx/` offline cache (committed to repo). Crate compiles without a live database. Downstream users get `query!()` safety by running yauth migrations against their DB then `cargo sqlx prepare` in their own project.

### Generated diesel table! macros
`yauth-migration` generates diesel `table!` macro definitions as **Rust source text** (string-based code generation) from the declarative schema, replacing hand-written `schema.rs` per backend. Maps `ColumnType` to diesel type strings per dialect (`Uuid` → `"diesel::sql_types::Uuid"` for pg, `"diesel::sql_types::Text"` for sqlite). This is code gen, not compilation — `yauth-migration` has zero diesel dependency. The output is a `.rs` file that the diesel backend crates include.

## Versioning

All new crates (`yauth-migration`, `yauth-entity`, `cargo-yauth`) must be added to `knope.toml` for unified versioning. They share the same version as `yauth` and are published to crates.io in dependency order: `yauth-migration` → `yauth-entity` → `yauth` → `cargo-yauth`.

## Cross-Milestone Dependencies

- **M1 → M2**: `yauth-migration` must be extracted and working before diesel backends can switch to generated `table!` macros (M2 uses `yauth-migration`'s code gen for `table!` output)
- **M1 → M3**: sqlx backends depend on `yauth-migration` for DDL generation and the CLI for `cargo yauth generate` (sqlx offline caches)
- **M2 → M3**: `yauth-entity` with conditional sqlx derives must exist before sqlx backends can use `query_as!()` with domain types
- **Entity and migration crates are independent**: `yauth-entity` has no dependency on `yauth-migration` and vice versa. However, M2 (which extracts `yauth-entity` AND builds diesel-sqlite) depends on M1 because the new backend uses generated `table!` macros from `yauth-migration`.
