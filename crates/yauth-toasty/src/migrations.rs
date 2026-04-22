//! Embedded migration system for yauth-toasty.
//!
//! Library consumers call [`apply_migrations()`] once at startup.
//! This reads committed migration files (embedded at compile time via `include_dir!`)
//! and applies any that haven't been run yet.
//!
//! For test-only schema creation, use the backend's `create_tables()` method
//! which delegates to `push_schema()` — faster but untracked.

use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};
use toasty::schema::db::Migration;
use yauth::repo::RepoError;

/// Embedded migration directory from the committed `toasty/` tree.
static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/toasty");

/// A single migration entry from history.toml.
#[derive(serde::Deserialize, Debug)]
struct MigrationEntry {
    name: String,
    checksum: String,
    #[allow(dead_code)]
    created_at: String,
}

/// The history.toml structure.
#[derive(serde::Deserialize, Debug)]
struct History {
    migrations: Vec<MigrationEntry>,
}

/// Compute SHA-256 checksum of content (must match toasty-dev generation).
fn compute_checksum(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Read and parse the embedded history.toml.
fn read_history() -> Result<History, RepoError> {
    let history_file = MIGRATIONS_DIR.get_file("history.toml").ok_or_else(|| {
        RepoError::Internal("embedded history.toml not found in migration directory".into())
    })?;

    let content = history_file
        .contents_utf8()
        .ok_or_else(|| RepoError::Internal("history.toml is not valid UTF-8".into()))?;

    toml::from_str(content)
        .map_err(|e| RepoError::Internal(format!("failed to parse history.toml: {e}").into()))
}

/// Apply all pending yauth-toasty migrations to the database.
///
/// This function:
/// 1. Reads the embedded migration history (compiled into the binary)
/// 2. Checks which migrations have already been applied via Toasty's tracking
/// 3. Validates checksums of previously-applied migrations (rejects edits)
/// 4. Executes pending migrations using Toasty's native `apply_migration()` API
///
/// The migration tracking table is managed by Toasty's driver — each driver
/// creates its own internal tracking mechanism (e.g., `_toasty_migrations` table).
///
/// # Errors
///
/// Returns `RepoError::Internal` if:
/// - A migration file's checksum doesn't match the recorded checksum (tampering)
/// - A SQL statement fails to execute
/// - The database connection is unavailable
///
/// # Example
///
/// ```rust,ignore
/// let db = toasty::Db::builder()
///     .table_name_prefix("yauth_")
///     .models(toasty::models!(yauth_toasty::*))
///     .connect("sqlite:./yauth.db")  // file-backed — NOT :memory:
///     .await?;
///
/// // Apply schema migrations — idempotent, safe to call on every startup.
/// // NOTE: driver().connect() opens a new connection internally;
/// // in-memory SQLite creates a separate database per connection,
/// // so use a file-backed database to ensure migrations persist.
/// yauth_toasty::apply_migrations(&db).await?;
/// ```
pub async fn apply_migrations(db: &toasty::Db) -> Result<(), RepoError> {
    let history = read_history()?;

    if history.migrations.is_empty() {
        return Ok(());
    }

    // Get a raw driver connection for migration operations
    let mut conn = db
        .driver()
        .connect()
        .await
        .map_err(|e| RepoError::Internal(format!("driver connect: {e}").into()))?;

    // Check which migrations are already applied
    let applied = conn
        .applied_migrations()
        .await
        .map_err(|e| RepoError::Internal(format!("check applied migrations: {e}").into()))?;

    let applied_ids: std::collections::HashSet<u64> = applied.iter().map(|m| m.id()).collect();

    for (idx, entry) in history.migrations.iter().enumerate() {
        let migration_id = idx as u64;

        // Read the embedded SQL file
        let sql_path = format!("migrations/{}.sql", entry.name);
        let sql_content = MIGRATIONS_DIR
            .get_file(&sql_path)
            .ok_or_else(|| {
                RepoError::Internal(format!("embedded migration file not found: {sql_path}").into())
            })?
            .contents_utf8()
            .ok_or_else(|| RepoError::Internal("migration file is not valid UTF-8".into()))?;

        // Validate checksum
        let actual_checksum = compute_checksum(sql_content);
        if actual_checksum != entry.checksum {
            return Err(RepoError::Internal(
                format!(
                    "migration '{}' checksum mismatch: expected {}, found {}. \
                     Do not edit committed migration files.",
                    entry.name, entry.checksum, actual_checksum
                )
                .into(),
            ));
        }

        if applied_ids.contains(&migration_id) {
            continue; // Already applied
        }

        // Build a Migration from the raw SQL.
        // Toasty's apply_migration() internally calls migration.statements()
        // which splits on `-- #[toasty::breakpoint]` markers — pass the full
        // content and let the driver handle splitting.
        let migration = Migration::new_sql(sql_content.to_string());

        // Apply via Toasty's native migration API
        conn.apply_migration(migration_id, &entry.name, &migration)
            .await
            .map_err(|e| {
                RepoError::Internal(format!("migration '{}' failed: {e}", entry.name).into())
            })?;
    }

    Ok(())
}
