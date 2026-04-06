# Milestone 1: Migration CLI — users can add yauth to an existing project

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

## What must work:
1. A developer with an existing diesel or sqlx app runs `cargo yauth init`, answers prompts (ORM, dialect, plugins), and gets migration files in their `migrations/` directory — ready to apply with their normal `diesel migration run` or `sqlx migrate run`
2. Running `cargo yauth add-plugin mfa` shows the exact SQL diff via `similar` ("CREATE TABLE yauth_totp_secrets ..."), adds the migration file, and updates `yauth.toml`
3. Running `cargo yauth remove-plugin passkey` shows the DROP statements and generates the removal migration
4. Setting `table_prefix = "auth_"` in `yauth.toml` produces `auth_users`, `auth_sessions` — all generated SQL respects the configured prefix
5. `cargo yauth status` shows which plugins are enabled and what migrations exist
6. `cargo yauth generate` regenerates migration SQL files from current `yauth.toml` config. The `generate` command grows across milestones: M1 = migration SQL only, M2 adds diesel `table!` macro generation, M3 adds sqlx offline cache generation. `cargo yauth generate --check` verifies all generated artifacts are fresh (used in CI).
7. Feature flags redesigned: `full` = all auth plugins (user-facing), `all-backends` = every ORM + DB combo (CI-only). Real apps use `full` + one backend. CI uses `full,all-backends`.
8. Workspace restructured: `yauth-migration` and `cargo-yauth` extracted as new crates, workspace `Cargo.toml` updated with new members, `knope.toml` updated with new crates
9. All existing tests pass after extraction — only `schema/` imports change (migration types moved to `yauth-migration`); domain type imports are untouched until M2
10. `CLAUDE.md` and `README.md` updated to reflect new crate structure, feature flags, and migration workflow

## After building, prove it works:
Start with a fresh diesel + axum project that has one existing migration (a `posts` table).

- Run `cargo yauth init` interactively — select diesel, postgres, email-password + passkey. Verify `yauth.toml` is created with correct values and 3 migration directories appear in `migrations/`
- Run `cargo yauth init --orm diesel --dialect postgres --plugins email-password,passkey` non-interactively on a fresh project — same result, no prompts (this is the path a Claude Code skill would use)
- Run `cargo yauth init -f yauth.dev.toml --orm sqlx --dialect sqlite --plugins email-password` — creates a separate config for a dev environment alongside the main `yauth.toml`
- Inspect the `up.sql` files — valid Postgres DDL with `yauth_` prefixed tables, proper FK references, correct column types
- Run `diesel migration run` — all yauth tables created alongside `posts`, tracked in `__diesel_schema_migrations`
- Run `cargo yauth add-plugin mfa` — see the diff output showing `CREATE TABLE yauth_totp_secrets` and `CREATE TABLE yauth_backup_codes`, then a new migration directory appears
- Run `diesel migration run` — mfa tables created
- Run `cargo yauth remove-plugin passkey` — see diff showing DROP statements, removal migration generated
- Run `cargo yauth status` — shows core, email-password, mfa enabled; passkey removed
- Start a fresh project, set `table_prefix = "auth_"` in `yauth.toml`, run `cargo yauth init` — all SQL uses `auth_users`, `auth_sessions`, etc.
- Start a fresh sqlx project, run `cargo yauth init` with orm=sqlx — generates numbered `.sql` files, `sqlx migrate run` applies them successfully
- Back in the yauth repo: run `cargo test --features full,all-backends --test repo_conformance` — all 64 conformance tests still pass after the `yauth-migration` extraction
- Run `cargo test --features full,all-backends --test pentest` — pentest suite still passes
- Run `cargo yauth generate --check -f yauth-diesel-pg.toml` — verify CLI-generated migration SQL matches the declarative schema (CI step, dogfooding the CLI)

## Test strategy:
Unit tests for the schema diff engine — given schema A (email-password) and schema B (email-password + mfa), assert the diff produces exactly the expected CREATE/ALTER statements. Test all three dialects. Test table prefix substitution. Use `cargo test` in the `yauth-migration` crate. Integration test for the `cargo-yauth` CLI using `assert_cmd`. Run `cargo fmt --check` and `cargo clippy -- -D warnings` on all new crates.

## Known pitfalls:
1. **diesel migration directory naming**: diesel expects `YYYY-MM-DD-HHMMSS_name/up.sql` format. The timestamp must be unique and monotonically increasing. Use the current UTC time with a counter suffix if generating multiple migrations in one `init` call.
2. **sqlx migration numbering**: sqlx expects `NNNNNNNN_name.sql` (zero-padded sequential). Must scan the existing `migrations/` dir to find the next number, not start from 0.
3. **Table prefix in FK references**: when prefix is customized, FK references must also use the prefix (`auth_sessions.user_id REFERENCES auth_users(id)`, not `yauth_users`). The DDL generators already use `TableDef.name` — ensure the prefix is applied to table names BEFORE passing to the generators, not after.
4. **`yauth-migration` must have zero ORM deps**: it's a pure code generator. If diesel or sqlx types leak in, downstream CLI users who don't use those ORMs will pull unnecessary dependencies. Guard with `cargo tree -p yauth-migration` checks in CI.
5. **Dogfood in the yauth repo**: the yauth repo validates the CLI via `cargo yauth generate --check -f <config>` in CI — if the generated migration SQL doesn't match the declarative schema, CI fails. Conformance tests continue using `backend.migrate()` for setup (since they test multiple backends/dialects simultaneously), but both paths read from the same declarative schema source of truth. The CLI and the runtime migrator are tested separately but validated against the same expected output.
