# Declarative Schema + Consumer-Owned Migrations

Replace yauth's baked-in `include_str!()` SQL migrations with a declarative schema system. Plugins declare tables/columns as Rust data, the library merges them into a canonical schema, and backends generate dialect-specific DDL. Consumers own the migration lifecycle.

**Stack:** Rust (yauth crate). No new dependencies — schema definitions are plain structs/enums. DDL targets Postgres, SQLite, and MySQL. `diesel-libsql` crate (published separately) for the libSQL/Turso backend.

Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.

## Milestone 1: Declarative schema + Postgres DDL + tracking

### What must work:
1. Plugins declare their schema needs via `fn schema() -> Vec<TableDef>` on `YAuthPlugin` (default empty)
2. Core tables (users, sessions, audit_log) defined in a `core_schema()` function — always included
3. Schema collector merges core + all plugin schemas into a single `YAuthSchema`, topologically sorted by FK deps
4. Postgres DDL generator produces `CREATE TABLE IF NOT EXISTS` statements matching the existing SQL migration output exactly
5. Migration diff introspects existing tables via `information_schema` and generates `ALTER TABLE ADD COLUMN` for new columns (additive only)
6. `yauth_schema_migrations` tracking table records a deterministic hash of the applied schema — second run is a no-op
7. `DieselBackend::migrate()` uses the declarative system instead of `include_str!()` SQL files
8. Consumer can call `YAuth::schema()` to inspect the merged schema and `YAuth::generate_ddl(Dialect::Postgres)` to export DDL

### After building, prove it works:
Start a fresh Postgres database. Build with `--features full`.

- Run the example server with `DieselBackend` — all tables created automatically
- `cargo test --features full --lib` — 150 unit tests pass
- `cargo test --features full --test diesel_integration` — integration tests pass
- `cargo test --features full --test pentest_memory` — 13 memory pentest tests pass
- Compare generated DDL against existing SQL files — tables, columns, types, constraints, FKs must match exactly
- Build with only `email-password` feature — only core + email-password tables created
- Run migrations twice — second run is a no-op (tracking table prevents re-application)
- Add a column to a plugin's schema def, run migrations — ALTER TABLE adds column without dropping data

## Milestone 2: SQLite dialect + diesel-libsql backend

### What must work:
1. SQLite DDL generator maps abstract types correctly (UUID→TEXT, DateTime→TEXT, Json→TEXT, no TIMESTAMPTZ)
2. `DieselLibsqlBackend` implements `DatabaseBackend` using the `diesel-libsql` crate — connects to local file or Turso remote URL
3. All repository traits implemented for diesel-libsql (reuses Diesel query builder with SQLite-compatible queries)
4. `DieselLibsqlBackend::migrate()` uses SQLite DDL + tracking table adapted for SQLite
5. Full auth flows work end-to-end against libSQL: register, login, session, logout, duplicate email → 409
6. `diesel-libsql-backend` feature flag (opt-in, not in `default`)
7. Example server supports `YAUTH_BACKEND=libsql DATABASE_URL=file:yauth.db`
8. MySQL DDL generator also available (`Dialect::Mysql` — VARCHAR(255), DATETIME, JSON, InnoDB, CHAR(36) for UUIDs)

### After building, prove it works:
- `generate_sqlite_ddl()` output loads into an in-process SQLite database without errors
- Start example server with `YAUTH_BACKEND=libsql DATABASE_URL=file:yauth.db` — register, login, session, logout all work
- `cargo test --features full --test libsql_integration` — auth flows pass against temp SQLite file
- Duplicate email registration returns 409 Conflict (SQLite UNIQUE constraint)
- `YAuth::generate_ddl(Dialect::Mysql)` produces valid MySQL 8 DDL (loads into testcontainer without errors)
- `YAuth::generate_ddl(Dialect::Sqlite)` output matches what `DieselLibsqlBackend::migrate()` actually runs

## Known pitfalls — address these during build:

1. **Column type mapping is lossy**: `ColumnType` enum must be abstract (DateTime, Uuid, Json) — each dialect maps it. Don't represent backend-specific types (TIMESTAMPTZ, JSONB) in the schema definition. Postgres gets TIMESTAMPTZ+UUID+JSONB, SQLite gets TEXT for all three, MySQL gets DATETIME+CHAR(36)+JSON.

2. **ALTER capability varies by backend**: Stock SQLite only supports ADD COLUMN and RENAME COLUMN. Postgres and MySQL support full ALTER. libSQL/Turso extends SQLite with ALTER COLUMN. The diff system should detect backend capabilities and use richer ALTER statements when available — but ADD COLUMN must always work everywhere.

3. **FK ordering**: Tables must be created in dependency order. The schema collector must topologically sort by FK references. A cycle is a schema definition bug — fail with a clear error.

4. **Schema hash stability**: The tracking table stores a hash of the applied schema. Use deterministic serialization (sorted keys, canonical format) — if the hash changes between compilations due to HashMap ordering or feature flag differences, migrations re-run unnecessarily.

5. **diesel-libsql uses `diesel-async` with a custom backend**: The `diesel-libsql` crate provides `AsyncLibSqlConnection` (native async, no `spawn_blocking`) and `deadpool::Pool` — same pattern as `diesel-async` with Postgres. The `DieselLibsqlBackend` pool type is `diesel_libsql::deadpool::Pool`, not `deadpool::Pool<AsyncPgConnection>`. Repo implementations can reuse the same Diesel query builder code from the Postgres backend but the connection type and pool type differ. Use a shared generic or duplicate the repo files with the different connection type — don't try to make one repo generic over both backends (Diesel's type system makes this painful).
