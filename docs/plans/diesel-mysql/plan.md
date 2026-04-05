# MySQL/MariaDB Backend for yauth

Add `DieselMysqlBackend` to yauth so MySQL and MariaDB are first-class database backends. The backend architecture, repository traits, domain types, and MySQL DDL generation (`schema/mysql.rs`) already exist. This project implements the concrete backend module, wires it into the build, and creates a cross-backend repository conformance test suite.

**Stack:** Rust, diesel 2.3 (mysql_backend feature), diesel-async 0.8 (mysql + deadpool features), testcontainers 0.27

**Reference implementations:** `backends/diesel_pg/` (PostgreSQL, uses RETURNING) and `backends/diesel_libsql/` (SQLite, uses raw SQL + String-typed UUIDs/DateTimes). The MySQL backend should follow the **libsql pattern** — String-typed model fields with converter functions, raw `sql_query()` for inserts (no RETURNING), `QueryableByName` variants for result mapping.

## Milestone 1: Backend skeleton + core repos

### What must work:
1. `diesel-mysql-backend` feature flag compiles independently (no PG or SQLite deps pulled)
2. `DieselMysqlBackend::new(url)` creates an async connection pool to MySQL 8+ or MariaDB 10.6+
3. `backend.migrate()` creates all yauth tables using DDL from the existing `schema/mysql.rs` generator, tracked via `yauth_schema_migrations` hash table
4. Core repository traits fully implemented: UserRepository, SessionRepository, AuditLogRepository, ChallengeRepository, RateLimitRepository, RevocationRepository, SessionOpsRepository
5. `diesel_common::PoolAccess` extended for MySQL pool; `diesel_conflict_mysql()` error mapper added
6. MySQL 8.0 added to `docker-compose.yml` as a test service

### After building, prove it works:
Start MySQL via `docker compose up -d`. Run these against the MySQL backend directly (not HTTP):

- Create a user with `UserRepository::create()`, read it back with `find_by_id()` and `find_by_email()`. Verify all fields round-trip correctly — especially UUID (CHAR(36) → Uuid), display_name, and timestamps.
- Create a duplicate user with the same email. Verify `RepoError::Conflict` is returned (not a panic or generic Internal error).
- Create a session, validate it, delete it. Verify the deleted session returns `None` on subsequent validate.
- Insert a rate limit entry, increment it to the limit, verify the next increment returns `RateLimitExceeded`. Wait for the window to expire (or use a short window), verify the counter resets.
- Run `cargo test --features diesel-mysql-backend,email-password,memory-backend --test diesel_mysql_integration` — all pass.
- Run `cargo build --features diesel-mysql-backend --no-default-features` — compiles without PG or SQLite deps.

## Milestone 2: Conformance test suite + all plugin repos

### What must work:
1. All feature-gated repository traits implemented for MySQL: Password, Passkey, Totp, BackupCode, OauthAccount, OauthState, ApiKey, RefreshToken, MagicLink, AccountLock, UnlockToken, Webhook, WebhookDelivery, and OAuth2 server repos
2. New `tests/repo_conformance.rs` with a `test_backends()` helper that returns `Vec<(&str, Repositories)>` for every available backend (memory always, PG/libsql/MySQL if env vars set)
3. Conformance tests for every repository trait method — parameterized across all backends with identical assertions
4. MySQL-specific edge case tests in conformance suite: UUID round-trip, boolean storage, datetime fractional seconds, JSON serialization, case-insensitive email uniqueness
5. Pentest suite updated: MySQL added to `test_envs()` and `RoleSetter` enum
6. MySQL added to `full` feature flag
7. CI updated: MySQL service in GitHub Actions, conformance + pentest run against all backends

### After building, prove it works:
- Run `cargo test --features full --test repo_conformance -- --test-threads=1` with all database URLs set. Every test passes on memory, PG, libsql, AND MySQL with identical results.
- Verify UUID round-trip: create a user on MySQL, read it back, confirm the UUID string representation matches exactly (no case changes, no trimming).
- Verify datetime precision: create a session with a specific expiry time including microseconds, read it back, confirm the microseconds are preserved.
- Verify JSON round-trip: store a complex JSON object (nested, with arrays), read it back, confirm structural equality.
- Verify case-insensitive email: create user with "Test@Example.com", look up with "test@example.com", confirm it's found.
- Run `cargo test --features full --test pentest -- --test-threads=1` with MySQL URL set. All 20+ OWASP tests pass against all three database backends.
- Run the same pentest suite against MariaDB 10.6 (swap docker-compose image). All tests pass.

## Known pitfalls — address these during build:

1. **No RETURNING on MySQL 8.x**: MySQL lacks `RETURNING` (MariaDB has it but we target both). Every INSERT must be followed by a SELECT to fetch the inserted row. Follow the libsql pattern: use `diesel::sql_query()` with explicit INSERT SQL, then SELECT by the known primary key (UUID generated in Rust before insert). Never use `get_result()` or `.returning()` in the MySQL backend.

2. **UUID/DateTime as Strings in Diesel models**: MySQL stores UUIDs as CHAR(36) and DateTimes as DATETIME. Copy the libsql converter pattern exactly (`uuid_to_str`, `str_to_uuid`, `dt_to_str`, `str_to_dt` in `models.rs`). The `str_to_uuid` fallback to `Uuid::nil()` on parse failure is intentional — don't change it. Create `QueryableByName` model variants for `sql_query` result mapping, same as libsql's `LibsqlUserByName` pattern.

3. **MySQL conflict error format differs from PG and SQLite**: PG returns `DatabaseError(UniqueViolation, _)`, SQLite sometimes returns string-based "UNIQUE constraint failed". MySQL returns `DatabaseError(UniqueViolation, _)` but the detail message format differs. Create `diesel_conflict_mysql()` in `diesel_common` that handles both the typed variant AND string matching on "Duplicate entry" (the MySQL error text). Test with actual duplicate inserts — don't assume the error shape matches PG.

4. **ALTER TABLE ADD COLUMN IF NOT EXISTS**: The migration system uses ALTER TABLE to add columns for schema evolution. MySQL 8.0 does NOT support `ADD COLUMN IF NOT EXISTS` (MariaDB 10.0+ does). The migration runner must either catch "column already exists" errors silently, or query `information_schema.columns` before altering. Don't use MariaDB-specific syntax — it breaks MySQL.

5. **Testcontainers MySQL setup**: The `testcontainers` crate (0.27) has MySQL support via `testcontainers-modules`. Use `Mysql::default()` with tag `"8.0"`. MySQL takes longer to initialize than PG — ensure the health check waits for readiness. The connection URL format is `mysql://root:password@127.0.0.1:{port}/yauth_test`. Create the test database explicitly before running migrations (MySQL doesn't auto-create databases from connection URLs like PG testcontainers do).
