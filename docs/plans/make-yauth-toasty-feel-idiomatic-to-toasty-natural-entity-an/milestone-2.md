# Milestone 2: Toasty Migration System

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

This milestone delivers the production migration story for yauth-toasty. After this milestone, a library consumer can call `yauth_toasty::apply_migrations(&db).await?` at startup to create or update the schema — no CLI installation, no manual SQL, no `push_schema()` in production. Developers evolving the yauth-toasty models generate migrations via a thin dev binary that wraps `toasty-cli`.

**Toasty version: 0.4** (the target for this entire plan; M1 upgrades from 0.3 → 0.4 as part of entity rewrite).

---

## Goal

Replace the test-only `push_schema()` approach with toasty's snapshot-anchored migration chain. Ship embedded migrations inside the crate so library consumers get schema management from a single function call. Provide a developer workflow for generating new migrations when models change.

---

## Deliverables

### 1. `Toasty.toml` Configuration

Add `crates/yauth-toasty/Toasty.toml`:

```toml
[migration]
# Where migration artifacts live (relative to crate root)
path = "toasty"

# Sequential numeric prefix: 0000_, 0001_, 0002_, ...
# Chosen over timestamp for deterministic ordering in embedded builds.
prefix_style = "Sequential"

# Insert `-- #[toasty::breakpoint]` comments between DDL statements.
# Required for the migration applier to split multi-statement files per-driver.
statement_breakpoints = true

# SHA-256 checksum stored in history.toml for each migration file.
# Detects accidental edits to already-applied migrations.
checksums = true

[schema]
# All yauth tables are always present regardless of plugin features.
# Feature-gated models are always compiled into the dev binary (via --features full).
# Unused plugin tables remain empty at runtime — this matches diesel/sqlx backends.
table_name_prefix = "yauth_"
```

**Design decisions:**

- `prefix_style = "Sequential"` — deterministic ordering in `include_dir!` traversal. Timestamps would depend on generation time and complicate embedded iteration order.
- `checksums = true` — catches accidental edits to committed migration files. The applier rejects mismatches at runtime with a clear error message.
- `statement_breakpoints = true` — SQLite requires one statement per `execute()`; the breakpoint markers let the applier split without fragile semicolon parsing.
- `path = "toasty"` — short, conventional (matches toasty's default).

### 2. Dev CLI Binary

Create `crates/yauth-toasty/src/bin/toasty-dev.rs`:

```rust
//! Dev-only CLI for generating toasty migrations from yauth-toasty models.
//!
//! This binary is NOT shipped to consumers (not included in published crate).
//! It exists so developers can generate migration diffs after model changes.
//!
//! Usage:
//!   cargo run -p yauth-toasty --bin toasty-dev --features full,sqlite -- migration generate --name add_passkey_fields
//!   cargo run -p yauth-toasty --bin toasty-dev --features full,postgresql -- migration status

use toasty_cli::{Config, ToastyCli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;  // reads Toasty.toml from crate root

    // Build Db with ALL yauth models — --features full ensures all entity modules
    // are compiled. No database connection needed for `migration generate`.
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .register_models(toasty::models!(yauth_toasty::entities::*))
        .build()?;

    let cli = ToastyCli::with_config(db, config);
    cli.parse_and_run().await?;
    Ok(())
}
```

**Wiring in `Cargo.toml`:**

```toml
[[bin]]
name = "toasty-dev"
path = "src/bin/toasty-dev.rs"
required-features = ["full"]
# Not published — dev-only
publish = false

[build-dependencies]
# toasty-cli needed for the dev binary only
toasty-cli = { version = "0.4", optional = true }
anyhow = { version = "1", optional = true }

[features]
# Add to existing feature set:
dev-cli = ["dep:toasty-cli", "dep:anyhow"]
```

The `dev-cli` feature keeps `toasty-cli` out of the consumer dependency tree.

### 3. Developer Workflow: Generating Migrations

When a developer changes entity models:

```bash
# 1. Make model changes in src/entities/*.rs

# 2. Generate the migration diff:
cargo run -p yauth-toasty --bin toasty-dev --features full,sqlite,dev-cli -- \
    migration generate --name describe_the_change

# 3. Review the generated files:
#    toasty/migrations/NNNN_describe_the_change.sql  (DDL statements with breakpoints)
#    toasty/snapshots/NNNN_snapshot.toml            (full schema state after this migration)
#    toasty/history.toml                             (updated migration chain + checksums)

# 4. Commit all three files alongside the model changes.
git add crates/yauth-toasty/toasty/ crates/yauth-toasty/src/entities/
git commit -m "feat: add passkey last_used_at tracking"
```

**Rename detection:** When renaming a column or table, toasty-cli's `migration generate` produces a `DROP + CREATE` by default (it can't infer renames). The developer must manually edit the generated `.sql` to use `ALTER TABLE ... RENAME COLUMN` instead. This is documented in the generated file's header comment. Future toasty versions may add `--rename-hint` support.

### 4. Committed Migration Output Tree

After initial generation, the crate gains:

```
crates/yauth-toasty/
  toasty/
    history.toml              # Migration chain metadata (order, checksums, timestamps)
    migrations/
      0000_initial.sql        # Full schema DDL (all 27 tables, indexes, constraints)
    snapshots/
      0000_snapshot.toml      # Complete schema state at migration 0000
```

**`history.toml` shape:**

```toml
[[migrations]]
name = "0000_initial"
checksum = "sha256:abc123..."
created_at = "2026-04-22T00:00:00Z"

# After future migrations:
# [[migrations]]
# name = "0001_add_magic_link_fields"
# checksum = "sha256:def456..."
# created_at = "2026-05-01T00:00:00Z"
```

**`0000_initial.sql` excerpt:**

```sql
-- Generated by toasty-cli 0.4.x from yauth-toasty models
-- DO NOT EDIT — regenerate with: cargo run --bin toasty-dev --features full,sqlite,dev-cli -- migration generate

CREATE TABLE yauth_users (
    id TEXT NOT NULL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'user',
    banned INTEGER NOT NULL DEFAULT 0,
    banned_reason TEXT,
    banned_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE TABLE yauth_sessions (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES yauth_users(id),
    token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX idx_yauth_sessions_user_id ON yauth_sessions(user_id);
-- #[toasty::breakpoint]
-- ... remaining 25 tables, indexes, FKs ...
```

**`0000_snapshot.toml` shape:**

```toml
# Schema snapshot after migration 0000_initial
# Used by toasty-cli to compute diffs for subsequent migrations

[[tables]]
name = "yauth_users"
columns = [
    { name = "id", type = "text", primary_key = true, nullable = false },
    { name = "email", type = "text", nullable = false, unique = true },
    # ...
]

[[tables]]
name = "yauth_sessions"
columns = [
    { name = "id", type = "text", primary_key = true, nullable = false },
    { name = "user_id", type = "text", nullable = false, foreign_key = "yauth_users.id" },
    # ...
]
indexes = [
    { name = "idx_yauth_sessions_user_id", columns = ["user_id"] },
]

# ... all 27 tables
```

### 5. Consumer-Facing `apply_migrations()` Public API

Create `crates/yauth-toasty/src/migrations.rs`:

```rust
//! Embedded migration system for yauth-toasty.
//!
//! Library consumers call `apply_migrations(&db)` once at startup.
//! This reads committed migration files (embedded at compile time via `include_dir!`)
//! and applies any that haven't been run yet.

use include_dir::{include_dir, Dir};
use yauth::repo::RepoError;

/// Embedded migration directory from the committed `toasty/` tree.
static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/toasty");

/// Apply all pending yauth-toasty migrations to the database.
///
/// This function:
/// 1. Creates the `__yauth_toasty_migrations` tracking table if it doesn't exist
/// 2. Reads embedded migration files in sequential order
/// 3. Skips migrations already recorded in the tracking table
/// 4. Validates checksums of previously-applied migrations (rejects edits)
/// 5. Executes pending migrations inside a transaction per statement-breakpoint block
///
/// # Errors
///
/// Returns `RepoError::Internal` if:
/// - A migration file's checksum doesn't match the recorded checksum (tampering detected)
/// - A SQL statement fails to execute
/// - The database connection is unavailable
///
/// # Example
///
/// ```rust
/// let db = toasty::Db::builder()
///     .table_name_prefix("yauth_")
///     .register_models(yauth_toasty::all_models!())
///     .connect("postgres://localhost/myapp")
///     .await?;
///
/// // Apply schema migrations — idempotent, safe to call on every startup
/// yauth_toasty::apply_migrations(&db).await?;
/// ```
pub async fn apply_migrations(db: &toasty::Db) -> Result<(), RepoError> {
    // Implementation strategy:
    //
    // If toasty 0.4 exposes `db.apply_migrations_from(dir)`:
    //   Use it directly — it handles tracking table, checksums, ordering.
    //
    // If not, implement manually (~80 lines):
    //   1. CREATE TABLE IF NOT EXISTS __yauth_toasty_migrations (
    //        name TEXT PRIMARY KEY,
    //        checksum TEXT NOT NULL,
    //        applied_at TEXT NOT NULL
    //      );
    //   2. Read history.toml from MIGRATIONS_DIR to get ordered migration list
    //   3. For each migration in order:
    //      a. Check if already in tracking table
    //      b. If yes: validate checksum matches, error if mismatch
    //      c. If no: read .sql file, split on breakpoint markers, execute each block
    //      d. Record in tracking table
    //
    // Both paths produce the same outcome. The manual path is straightforward
    // because toasty's Db exposes raw SQL execution for DDL.

    let history = read_history(&MIGRATIONS_DIR)?;
    let mut handle = db.handle().await
        .map_err(|e| RepoError::Internal(format!("db connection: {e}").into()))?;

    ensure_tracking_table(&mut handle).await?;
    let applied = get_applied_migrations(&mut handle).await?;

    for migration in &history.migrations {
        if let Some(recorded) = applied.get(&migration.name) {
            // Verify checksum
            if recorded.checksum != migration.checksum {
                return Err(RepoError::Internal(
                    format!(
                        "migration '{}' checksum mismatch: expected {}, found {}. \
                         Do not edit committed migration files.",
                        migration.name, migration.checksum, recorded.checksum
                    ).into()
                ));
            }
            continue; // Already applied
        }

        // Read and execute the migration SQL
        let sql_path = format!("migrations/{}.sql", migration.name);
        let sql_content = MIGRATIONS_DIR
            .get_file(&sql_path)
            .ok_or_else(|| RepoError::Internal(
                format!("embedded migration file not found: {sql_path}").into()
            ))?
            .contents_utf8()
            .ok_or_else(|| RepoError::Internal("migration file is not UTF-8".into()))?;

        // Split on breakpoints and execute each block
        for block in sql_content.split("-- #[toasty::breakpoint]") {
            let trimmed = block.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            handle.execute_raw(trimmed).await
                .map_err(|e| RepoError::Internal(
                    format!("migration '{}' failed: {e}", migration.name).into()
                ))?;
        }

        // Record as applied
        record_migration(&mut handle, &migration.name, &migration.checksum).await?;
    }

    Ok(())
}
```

**Public API surface in `lib.rs`:**

```rust
pub mod migrations;
pub use migrations::apply_migrations;
```

### 6. `include_dir` Dependency

Add to `Cargo.toml`:

```toml
[dependencies]
include_dir = "0.7"
```

The `include_dir!` macro embeds the `toasty/` directory tree at compile time. This means:
- Consumers don't need the migration files on disk at runtime
- The crate is self-contained — `cargo add yauth-toasty` gives you schema management
- Migration files are baked into the binary, matching the compiled model definitions

### 7. Relationship to `push_schema()` (Test Fast Path)

`push_schema()` remains available and is the **recommended approach for tests**:

```rust
// Test setup — fast, no migration tracking overhead
db.push_schema().await.unwrap();

// Production startup — tracked, checksummed, incremental
yauth_toasty::apply_migrations(&db).await?;
```

Backend `create_tables()` doc comments are updated to clarify:

```rust
impl ToastyPgBackend {
    /// Create all yauth tables using `push_schema()`.
    ///
    /// **For tests only.** This drops and recreates tables without tracking.
    /// For production, use `yauth_toasty::apply_migrations(&db).await?` instead.
    pub async fn create_tables(&self) -> Result<(), RepoError> { ... }
}
```

---

## File-by-File Changes

| File | Change |
|------|--------|
| `crates/yauth-toasty/Toasty.toml` | **New.** Migration configuration (path, prefix_style, checksums, breakpoints). |
| `crates/yauth-toasty/Cargo.toml` | Add `include_dir = "0.7"` dep. Add `toasty-cli = { version = "0.4", optional = true }`, `anyhow = { version = "1", optional = true }` build deps. Add `dev-cli` feature. Add `[[bin]]` section for `toasty-dev`. |
| `crates/yauth-toasty/src/bin/toasty-dev.rs` | **New.** Thin CLI binary wrapping `toasty-cli` with yauth model registration. |
| `crates/yauth-toasty/src/migrations.rs` | **New.** `apply_migrations()` public function with embedded migration reading, checksum validation, breakpoint splitting, tracking table management. |
| `crates/yauth-toasty/src/lib.rs` | Add `pub mod migrations; pub use migrations::apply_migrations;` |
| `crates/yauth-toasty/toasty/history.toml` | **New (generated).** Migration chain metadata. |
| `crates/yauth-toasty/toasty/migrations/0000_initial.sql` | **New (generated).** Full initial schema DDL for all 27 tables. |
| `crates/yauth-toasty/toasty/snapshots/0000_snapshot.toml` | **New (generated).** Schema state snapshot after initial migration. |
| `crates/yauth-toasty/src/pg/mod.rs` | Update `create_tables()` doc comment to clarify test-only usage. |
| `crates/yauth-toasty/src/mysql/mod.rs` | Update `create_tables()` doc comment to clarify test-only usage. |
| `crates/yauth-toasty/src/sqlite/mod.rs` | Update `create_tables()` doc comment to clarify test-only usage. |

---

## Removal of Hand-Rolled Per-Backend SQL

After this milestone, the `pg/`, `mysql/`, `sqlite/` backend modules:

- **Remain** as thin backend structs implementing `DatabaseBackend` (they construct `Db` with the correct driver and delegate to `common::build_repositories()`).
- **No longer contain any schema-creation SQL.** Their `create_tables()` method delegates to `db.push_schema()` (test-only) — no hand-written DDL.
- **No separate `schema.sql` files.** If any `pg/schema.sql`, `mysql/schema.sql`, `sqlite/schema.sql` files exist, they are deleted. Toasty generates dialect-specific DDL at migration generation time from one set of model definitions.

The `toasty/migrations/0000_initial.sql` is the **single source** of schema DDL. It uses Toasty's dialect-agnostic SQL generation (Toasty selects the right SQL syntax based on the connected driver at apply time) or, if toasty requires per-dialect migration files, the `toasty-dev` binary is run once per dialect and the output stored under `toasty/migrations/{dialect}/`.

**Decision: single-file vs per-dialect migrations.** If toasty 0.4's migration system generates a single SQL file that works across all dialects (using portable SQL), use that. If it requires per-dialect output, store as:

```
toasty/
  migrations/
    0000_initial/
      postgres.sql
      mysql.sql
      sqlite.sql
  snapshots/
    0000_snapshot.toml
  history.toml
```

The `apply_migrations()` function reads the dialect from the `Db` instance and selects the correct file.

---

## Feature-Gated Models in the Snapshot

**Decision: All models are always present in the snapshot and migration output.**

This is the same decision made in M1 (entities always compiled) carried through to the migration system:

- The `toasty-dev` binary is **always compiled with `--features full`**. This means `toasty::models!(yauth_toasty::entities::*)` sees all 27 entity structs regardless of what features a consumer enables.
- The generated migration creates all 27 tables unconditionally.
- `apply_migrations()` creates all tables regardless of which plugin features the consumer enables.
- Unused plugin tables remain empty at runtime.

**Why not per-feature migration variants?**

1. **Combinatorial explosion.** With 11 plugin features, there are 2^11 = 2048 possible feature combinations. Each would need its own migration chain — unworkable.
2. **Snapshot inconsistency.** If the snapshot only includes feature-enabled models, adding a feature later generates a migration that creates tables from "nothing" (because they weren't in the previous snapshot). This produces correct DDL but confusing diff history.
3. **Alignment with other backends.** The diesel/sqlx backends create all `yauth_` tables regardless of enabled features. `cargo yauth generate` produces all tables. Consistency reduces surprises.
4. **Empty tables are free.** A table with 0 rows and no indexes beyond PK costs ~8KB on PG, ~16KB on MySQL, and 0 bytes on SQLite. This is negligible.

---

## Test Strategy

### Unit Tests for Migration Infrastructure

New test file: `tests/migrations.rs`

```rust
#[tokio::test]
async fn test_apply_migrations_creates_schema() {
    // 1. Create a fresh in-memory SQLite Db (no push_schema)
    let db = Db::builder()
        .table_name_prefix("yauth_")
        .register_models(toasty::models!(yauth_toasty::entities::*))
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // 2. Apply migrations
    yauth_toasty::apply_migrations(&db).await.unwrap();

    // 3. Verify tables exist by inserting a user
    // (Uses the same repo code as conformance tests)
    let backend = ToastySqliteBackend::from_db(db);
    let repos = backend.repositories();
    let user = repos.users.create(test_new_user()).await.unwrap();
    assert_eq!(user.email, "test@example.com");
}

#[tokio::test]
async fn test_apply_migrations_is_idempotent() {
    let db = fresh_sqlite_db().await;

    // Apply twice — second call should be a no-op
    yauth_toasty::apply_migrations(&db).await.unwrap();
    yauth_toasty::apply_migrations(&db).await.unwrap();

    // Verify schema is still correct
    let backend = ToastySqliteBackend::from_db(db);
    let repos = backend.repositories();
    let user = repos.users.create(test_new_user()).await.unwrap();
    assert!(user.id != uuid::Uuid::nil());
}

#[tokio::test]
async fn test_apply_migrations_detects_checksum_tampering() {
    // This test verifies that editing a committed migration file
    // causes apply_migrations to fail with a clear error.
    // (Implementation: mock a modified embedded file or test the
    //  checksum validation logic directly)
}

#[tokio::test]
async fn test_apply_migrations_then_conformance() {
    // Full integration: apply_migrations on fresh DB, then run
    // a representative subset of conformance tests against it.
    // This proves the migration-created schema matches push_schema().
    let db = fresh_sqlite_db().await;
    yauth_toasty::apply_migrations(&db).await.unwrap();

    let backend = ToastySqliteBackend::from_db(db);
    // Run the same assertions as conformance tests:
    run_user_crud_assertions(&backend).await;
    run_session_lifecycle_assertions(&backend).await;
    run_cascade_delete_assertions(&backend).await;
}
```

### Integration Tests (with real databases)

The existing conformance test suite (`tests/conformance.rs`) continues to use `push_schema()` for speed. A new test file `tests/migration_integration.rs` verifies `apply_migrations()` against real databases:

```rust
#[test]
fn test_migration_pg() {
    // Requires DATABASE_URL
    // Creates fresh schema via apply_migrations, runs conformance subset
}

#[test]
fn test_migration_mysql() {
    // Requires MYSQL_DATABASE_URL
}
```

### `push_schema()` vs `apply_migrations()` Equivalence

A CI check verifies that the schema produced by `push_schema()` matches the schema produced by `apply_migrations()`. Strategy:

1. Create two SQLite databases
2. Run `push_schema()` on one, `apply_migrations()` on the other
3. Dump both schemas (`.schema` in SQLite)
4. Assert structural equivalence (ignoring whitespace/ordering)

This catches drift between model definitions and committed migration files.

---

## Acceptance Criteria / Verification

1. `cargo build -p yauth-toasty --features full,sqlite` — compiles successfully with `migrations` module.
2. `cargo build -p yauth-toasty --bin toasty-dev --features full,sqlite,dev-cli` — dev CLI binary compiles.
3. `cargo run -p yauth-toasty --bin toasty-dev --features full,sqlite,dev-cli -- migration status` — prints migration status without error.
4. `crates/yauth-toasty/toasty/history.toml` exists and lists `0000_initial`.
5. `crates/yauth-toasty/toasty/migrations/0000_initial.sql` exists and contains DDL for all 27 `yauth_*` tables.
6. `crates/yauth-toasty/toasty/snapshots/0000_snapshot.toml` exists and describes all 27 tables.
7. `cargo test -p yauth-toasty --features full,sqlite --test migrations` — migration unit tests pass.
8. `cargo test -p yauth-toasty --features full,sqlite --test conformance` — conformance tests still pass (using `push_schema()`).
9. Schema equivalence test passes: `push_schema()` output matches `apply_migrations()` output.
10. Grep for `pub async fn apply_migrations` in `crates/yauth-toasty/src/migrations.rs` — exists.
11. Grep for `pub use migrations::apply_migrations` in `crates/yauth-toasty/src/lib.rs` — exists.
12. Grep for `include_dir` in `crates/yauth-toasty/Cargo.toml` — present.
13. No hand-rolled SQL files remain: `find crates/yauth-toasty/src/{pg,mysql,sqlite} -name "*.sql"` returns nothing.
14. The `tokio-postgres` optional dep (removed in M1) remains absent.

---

## Out of Scope

- **Applying migrations at `YAuthBuilder::build()` time.** The consumer explicitly calls `apply_migrations()` — yauth does not auto-migrate. This is consistent with how diesel/sqlx backends work (consumer runs `diesel migration run` separately).
- **Down migrations / rollback.** Toasty's migration system is forward-only. If you need to undo, write a new forward migration. This matches toasty's philosophy and avoids the complexity of reverse DDL generation.
- **Multi-tenant schema isolation.** `apply_migrations()` operates on the default schema/database. PostgreSQL schema isolation (`SET search_path`) is out of scope for M2 — it can be added as a parameter in a future milestone.
- **Migration generation in CI.** The `toasty-dev` binary is developer-facing. CI validates that committed migrations are up-to-date (via schema equivalence test), but does not generate new ones.
- **DynamoDB or non-relational support.** yauth's schema is relational; toasty migrations target SQL databases only.

---

## Known Pitfalls

1. **`toasty-cli` API stability.** Toasty 0.4's CLI API (`ToastyCli::with_config`, `Config::load()`) may differ from the shapes shown here. Check `docs.rs/toasty-cli/0.4.0` and the toasty repo's examples. If the API surface is different, adapt `toasty-dev.rs` accordingly — the important thing is that the binary generates migrations from the model types.

2. **`include_dir!` compile-time embedding.** If the `toasty/` directory doesn't exist when `cargo build` runs (e.g., fresh clone without generating migrations), compilation fails. Mitigate by committing the initial migration — it's always present. Add a `build.rs` that creates an empty `toasty/` dir if missing (to avoid hard build failure on initial setup).

3. **Dialect-specific DDL.** Toasty may generate different SQL for different drivers (TEXT vs VARCHAR, INTEGER vs BOOLEAN). If migration files must be dialect-specific, the `apply_migrations()` function needs to detect the driver and load the correct file. This adds complexity but is straightforward with toasty's `Db::driver()` introspection.

4. **Checksum format.** The checksum must be computed identically by both `toasty-dev` (at generation time) and `apply_migrations()` (at validation time). Use SHA-256 over the raw file bytes (no normalization). Document this in `history.toml` comments.

5. **Migration ordering with parallel development.** If two developers generate migrations simultaneously, they may both claim the same sequence number (e.g., both create `0002_*`). Resolution: the CI schema-equivalence check fails, forcing a rebase. The second developer runs `toasty-dev migration generate` again, which assigns `0003_*`. This is the same workflow as diesel/sqlx migrations.

6. **`include_dir` crate size.** Embedding the entire `toasty/` directory adds to compile time and binary size. For 27 tables, the initial migration SQL is ~5-10KB; snapshots ~20KB. This is negligible. Monitor if migration count grows large (>50 migrations = ~500KB embedded).

7. **`toasty::Db::handle()` for DDL.** The `apply_migrations()` function needs to execute raw DDL (CREATE TABLE, etc.). Toasty's `Db` must expose raw SQL execution for this. If toasty 0.4 doesn't provide `handle.execute_raw()`, use the underlying driver connection directly (via `db.raw_connection()` or similar). Check toasty's API surface.

8. **Tracking table name collision.** The `__yauth_toasty_migrations` table must not collide with any yauth entity table or the consumer's own tables. The double-underscore prefix + `yauth_toasty` qualifier makes collision extremely unlikely. If consumers run multiple yauth instances (unlikely), they'd need separate databases anyway.
