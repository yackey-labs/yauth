# Milestone 3: sqlx backends with compile-time query checking

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

## What must work:
1. Three new backends — `SqlxPgBackend`, `SqlxMysqlBackend`, `SqlxSqliteBackend` — each implementing all 20+ repository traits with `query!()` / `query_as!()` macros for compile-time SQL checking
2. `.sqlx/` offline cache committed to the repo — crate compiles without a live database when `SQLX_OFFLINE=true`
3. A downstream developer can run yauth migrations via `sqlx migrate run`, write `query_as!()` against yauth tables in their own app, and get compile-time type checking
4. All 64 conformance tests pass for all three sqlx backends
5. Any combination of diesel + sqlx backends can be enabled simultaneously without compile conflicts
6. `cargo yauth init` with `orm = "sqlx"` generates correctly formatted sqlx migration files

## After building, prove it works:
- Run `cargo test --features full,all-backends --test repo_conformance` with all 8 backends (memory, diesel-pg, diesel-mysql, diesel-sqlite, diesel-libsql, sqlx-pg, sqlx-mysql, sqlx-sqlite) — all 64 tests pass for every backend
- Set `SQLX_OFFLINE=true`, unset all `DATABASE_URL` vars — `cargo check --features full,sqlx-pg-backend` succeeds using offline cache alone
- Create a fresh Axum project, run `cargo yauth init` with orm=sqlx dialect=postgres plugins=email-password,mfa, run `sqlx migrate run`, write `query_as!(YauthUser, "SELECT * FROM yauth_users WHERE email = $1", email)` in the app — compiles with full type checking
- Run `cargo test --features full,sqlx-sqlite-backend` in isolation — compiles without diesel in the dependency tree
- Compile `--features full,all-backends` — no conflicts across all 8 backends (CI-only combo)
- Compile `--features full,sqlx-pg-backend` — verify a real-world feature combo works without pulling in diesel or other backends

## Test strategy:
All 64 conformance tests — add sqlx-pg, sqlx-mysql, sqlx-sqlite to `test_backends()`. Env vars: `SQLX_PG_DATABASE_URL`, `SQLX_MYSQL_DATABASE_URL`, `SQLX_SQLITE_DATABASE_URL`. Same shared runtime pattern. CI runs `cargo yauth generate --check` to verify offline caches and generated artifacts are up to date.

## Known pitfalls:
1. **Dialect-specific query modules are mandatory**: each sqlx backend needs its own SQL files. Postgres uses `$1` placeholders + `RETURNING` + `ILIKE` + native UUID. MySQL uses `?` + INSERT-then-SELECT + `LIKE` + CHAR(36) UUIDs. SQLite uses `?` + RETURNING (3.35+) + `LIKE` + TEXT UUIDs. Do NOT share query strings across backends — the `query!()` macro validates against one dialect at a time.
2. **sqlx offline cache must cover all features**: `cargo sqlx prepare` only captures queries for currently enabled features. Run with `--features full,all-backends` so every feature-gated query across all sqlx backends is cached. Feature `#[cfg]` gates ensure only relevant queries compile for the user's enabled features — unused cached entries are inert.
3. **Feature flag isolation**: `sqlx` must be fully optional — gated behind `dep:sqlx` syntax. `cargo check --features memory-backend` must compile with zero sqlx AND zero diesel in the dependency tree. `cargo check --features full,sqlx-pg-backend` must compile with zero diesel. Test both in CI.
4. **UUID encode/decode per backend**: sqlx-postgres has native `Uuid` support (enable `sqlx/uuid`). sqlx-mysql encodes as `String` (CHAR(36)). sqlx-sqlite encodes as `String` (TEXT). Each backend needs explicit `From`/`Into` conversions in its query modules — don't rely on a single `FromRow` derive working across all three.
5. **Per-backend config files for sqlx offline caches**: the yauth repo has one `yauth.toml` per sqlx dialect (e.g., `yauth-sqlx-pg.toml`, `yauth-sqlx-mysql.toml`, `yauth-sqlx-sqlite.toml`). CI sets `DATABASE_URL` per step and runs `cargo yauth generate --check -f <config>` for each. `DATABASE_URL` always comes from env vars, never from the config file (no secrets in `yauth.toml`). The CLI runs `cargo sqlx prepare` internally, and all caches land in the same `.sqlx/` directory (sqlx disambiguates by query hash).
6. **Redis caching layer compatibility**: the existing `redis` feature wraps repository traits as a caching decorator. sqlx backends must work with `with_redis()` — verify the trait bounds match. The redis layer calls repository methods and caches results; it doesn't care about the underlying driver, but the `Send + Sync` bounds must hold for sqlx connection types.
