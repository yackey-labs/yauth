# Milestone 3: sqlx query file generation

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

After this milestone, `cargo yauth generate --orm sqlx` produces `.sql` query files alongside migration SQL. These are the queries yauth's sqlx backends execute — now available as files users can use with `sqlx::query_file!()` in their own code.

### What must work:

1. `cargo yauth generate --orm sqlx --dialect postgres` produces a `queries/` directory (path configurable in yauth.toml) containing `.sql` files for every repository operation
2. Each `.sql` file contains a single parameterized query with `$1`, `$2` parameter placeholders
3. Each file has a comment header: what the query does, parameter types, return columns, which plugin it belongs to. Tone is factual and direct (e.g., "-- Finds a user's active session. Returns NULL if expired or revoked." not "-- As you probably know, sessions track logged-in users...")
4. Core queries always generated: `find_user_by_id.sql`, `find_user_by_email.sql`, `create_user.sql`, `update_user.sql`, `delete_user.sql`, `create_session.sql`, `validate_session.sql`, `delete_session.sql`, `delete_expired_sessions.sql`, `create_audit_entry.sql`, `check_rate_limit.sql`, `increment_rate_limit.sql`
5. Plugin queries generated per enabled plugin (e.g., email-password adds `find_password_by_user.sql`, `create_password.sql`, `verify_email.sql`, etc.)
6. `cargo yauth generate --check` verifies query files are fresh alongside migration SQL
7. Dialect-aware: Postgres queries use `$1` params and `RETURNING`; MySQL uses `?` params; SQLite uses `?` params and no `RETURNING`
8. `--orm diesel` and `--orm seaorm` and `--orm toasty` are unaffected by this change
9. All `cargo yauth` commands that generate files print guided next-step instructions: what was created, what to run next, and why. This applies to `init`, `generate`, `add-plugin`, and `remove-plugin` across all ORMs — not just sqlx.
10. All generated SQL (migrations for Diesel and sqlx) includes short comments on each table — factual, not tutorial (e.g., "-- Hashed passwords. One row per user." not "-- This important table stores passwords which should always be hashed because...")

### After building, prove it works:

- `cargo yauth init --orm sqlx --dialect postgres --plugins email-password,passkey,mfa` in a temp directory
- CLI prints clear next-step instructions: "Created migrations/... — run `sqlx migrate run` to apply. Created queries/... — use with `sqlx::query_file!()` in your handlers."
- Verify `migrations/` contains the migration SQL file with auth-context comments on each table
- Verify `queries/` contains `.sql` files for core + email-password + passkey + mfa operations
- Each query file has a human-readable comment explaining what it does (not just column names)
- Each query file is valid SQL (no template variables, no broken syntax)
- `cargo yauth generate --check` passes when files are fresh
- Modify yauth.toml to add `bearer` plugin, run `cargo yauth add-plugin bearer`, verify new query files appear and CLI explains what was added
- `cargo yauth generate --check` still passes

### Test strategy:

Add tests to `crates/cargo-yauth/tests/cli_tests.rs` that:
- Run `init` with `--orm sqlx` for each dialect
- Verify expected query files exist
- Verify query SQL is syntactically valid (at minimum: contains SELECT/INSERT/UPDATE/DELETE, has parameter placeholders, no template markers)
- Run `generate --check` and verify it passes on fresh output

### Known pitfalls:

1. **Query count is large**: Each repository trait method maps to 1+ queries. With all plugins enabled, expect 60-80 query files. Keep filenames consistent: `<entity>_<operation>.sql` (e.g., `session_create.sql`, `session_validate.sql`, `password_find_by_user.sql`).

2. **Dialect differences in parameters**: Postgres uses `$1, $2, $3`. MySQL and SQLite use `?`. The generator must dispatch on dialect. Don't use named parameters — they're not universally supported.

3. **RETURNING clause**: Postgres supports `RETURNING *`. MySQL doesn't — INSERT then SELECT. SQLite added RETURNING in 3.35 but sqlx-sqlite support varies. Generate dialect-appropriate patterns.

4. **UUID handling differs**: Postgres uses native UUID type. MySQL stores as CHAR(36). SQLite stores as TEXT. The generated queries must use appropriate casts/types per dialect.

5. **These queries are for the USER, not for yauth internals**: The sqlx backends in yauth itself continue using inline `sqlx::query()` calls. The generated `.sql` files are a convenience for users who want to write custom queries against yauth tables using `query_file!()`. Don't confuse the two audiences.

6. **yauth.toml needs a new field**: Add `queries_dir = "queries"` (or similar) to the `[migration]` section. Default to `queries/` relative to project root.
