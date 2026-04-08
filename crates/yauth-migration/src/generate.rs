//! Migration file generators for diesel and sqlx.

use std::path::{Path, PathBuf};

use crate::config::YAuthConfig;
use crate::diff::{render_changes_sql, schema_diff};
use crate::{Dialect, YAuthSchema, collect_schema_for_plugins};

/// Result of migration file generation.
#[derive(Debug)]
pub struct GeneratedMigration {
    /// Files that were written (path -> content).
    pub files: Vec<(PathBuf, String)>,
    /// Human-readable description of what was generated.
    pub description: String,
}

/// Error from migration generation.
#[derive(Debug)]
pub enum GenerateError {
    Schema(crate::SchemaError),
    Io(std::io::Error),
    Config(String),
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::Schema(e) => write!(f, "schema error: {e}"),
            GenerateError::Io(e) => write!(f, "I/O error: {e}"),
            GenerateError::Config(msg) => write!(f, "config error: {msg}"),
        }
    }
}

impl std::error::Error for GenerateError {}

impl From<crate::SchemaError> for GenerateError {
    fn from(e: crate::SchemaError) -> Self {
        GenerateError::Schema(e)
    }
}

impl From<std::io::Error> for GenerateError {
    fn from(e: std::io::Error) -> Self {
        GenerateError::Io(e)
    }
}

/// Generate the initial migration files for a yauth.toml config.
///
/// Creates migration files for all enabled plugins from scratch (empty -> current).
pub fn generate_init(config: &YAuthConfig) -> Result<GeneratedMigration, GenerateError> {
    let dialect: Dialect = config
        .migration
        .dialect
        .parse()
        .map_err(|e: String| GenerateError::Config(e))?;

    let schema =
        collect_schema_for_plugins(&config.plugins.enabled, &config.migration.table_prefix)?;

    let from = YAuthSchema { tables: vec![] };
    let changes = schema_diff(&from, &schema);
    let (up_sql, down_sql) = render_changes_sql(&changes, dialect);

    let migrations_dir = Path::new(&config.migration.migrations_dir);
    let mut files = match config.migration.orm {
        crate::Orm::Diesel => {
            generate_diesel_files(migrations_dir, "yauth_init", &up_sql, &down_sql)?
        }
        crate::Orm::Sqlx => generate_sqlx_files(migrations_dir, "yauth_init", &up_sql)?,
        crate::Orm::SeaOrm => {
            generate_seaorm_files(migrations_dir, "yauth_init", &up_sql, &down_sql)?
        }
    };

    // For diesel ORM, also generate a schema.rs file
    if config.migration.orm == crate::Orm::Diesel {
        let schema_rs = crate::generate_diesel_schema(&schema, dialect);
        let schema_path = migrations_dir.join("schema.rs");
        files.push((schema_path, schema_rs));
    }

    // For SeaORM, also generate entity .rs files
    if config.migration.orm == crate::Orm::SeaOrm {
        let entities_dir = migrations_dir.join("entities");
        let entity_files = crate::generate_seaorm_entities(&schema, &config.migration.table_prefix);
        for (name, content) in entity_files {
            files.push((entities_dir.join(name), content));
        }
    }

    Ok(GeneratedMigration {
        files,
        description: format!(
            "Initial yauth migration with plugins: {}",
            config.plugins.enabled.join(", ")
        ),
    })
}

/// Generate migration files for adding a plugin.
///
/// Accepts pre-computed `(up_sql, down_sql)` to avoid recomputing the schema diff
/// (callers typically compute it for preview before calling this function).
pub fn generate_add_plugin(
    config: &YAuthConfig,
    plugin_name: &str,
    up_sql: &str,
    down_sql: &str,
) -> Result<GeneratedMigration, GenerateError> {
    if up_sql.trim().is_empty() {
        return Ok(GeneratedMigration {
            files: vec![],
            description: format!("No schema changes for plugin '{plugin_name}'"),
        });
    }

    let migration_name = format!("yauth_add_{}", plugin_name.replace('-', "_"));

    let migrations_dir = Path::new(&config.migration.migrations_dir);
    let files = match config.migration.orm {
        crate::Orm::Diesel => {
            generate_diesel_files(migrations_dir, &migration_name, up_sql, down_sql)?
        }
        crate::Orm::Sqlx => generate_sqlx_files(migrations_dir, &migration_name, up_sql)?,
        crate::Orm::SeaOrm => {
            generate_seaorm_files(migrations_dir, &migration_name, up_sql, down_sql)?
        }
    };

    Ok(GeneratedMigration {
        files,
        description: format!("Add plugin '{plugin_name}'"),
    })
}

/// Generate migration files for removing a plugin.
///
/// Accepts pre-computed `(up_sql, down_sql)` to avoid recomputing the schema diff
/// (callers typically compute it for preview before calling this function).
pub fn generate_remove_plugin(
    config: &YAuthConfig,
    plugin_name: &str,
    up_sql: &str,
    down_sql: &str,
) -> Result<GeneratedMigration, GenerateError> {
    if up_sql.trim().is_empty() {
        return Ok(GeneratedMigration {
            files: vec![],
            description: format!("No schema changes for removing plugin '{plugin_name}'"),
        });
    }

    let migration_name = format!("yauth_remove_{}", plugin_name.replace('-', "_"));

    let migrations_dir = Path::new(&config.migration.migrations_dir);
    let files = match config.migration.orm {
        crate::Orm::Diesel => {
            generate_diesel_files(migrations_dir, &migration_name, up_sql, down_sql)?
        }
        crate::Orm::Sqlx => generate_sqlx_files(migrations_dir, &migration_name, up_sql)?,
        crate::Orm::SeaOrm => {
            generate_seaorm_files(migrations_dir, &migration_name, up_sql, down_sql)?
        }
    };

    Ok(GeneratedMigration {
        files,
        description: format!("Remove plugin '{plugin_name}'"),
    })
}

// -- ORM-specific file generators --

/// Generate diesel migration files: `YYYYMMDDHHMMSS_name/up.sql` and `down.sql`.
fn generate_diesel_files(
    migrations_dir: &Path,
    name: &str,
    up_sql: &str,
    down_sql: &str,
) -> Result<Vec<(PathBuf, String)>, GenerateError> {
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let dir_name = format!("{}_{}", timestamp, name);
    let migration_dir = migrations_dir.join(dir_name);

    let up_path = migration_dir.join("up.sql");
    let down_path = migration_dir.join("down.sql");

    Ok(vec![
        (up_path, format!("-- Generated by cargo-yauth\n{up_sql}")),
        (
            down_path,
            format!("-- Generated by cargo-yauth\n{down_sql}"),
        ),
    ])
}

/// Generate SeaORM migration files: `mNNNNNNNNNNNNNN_name/up.sql` and `down.sql`.
///
/// SeaORM uses a `sea-orm-migration` crate with Rust-based migrations,
/// but the SQL files serve as a portable reference. Users can run them
/// via `sea-orm-cli migrate` or integrate with their own migration pipeline.
fn generate_seaorm_files(
    migrations_dir: &Path,
    name: &str,
    up_sql: &str,
    down_sql: &str,
) -> Result<Vec<(PathBuf, String)>, GenerateError> {
    // Use sea-orm-migration's `mYYYYMMDDHHMMSS_name` convention
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let dir_name = format!("m{}_{}", timestamp, name);
    let migration_dir = migrations_dir.join(dir_name);

    let up_path = migration_dir.join("up.sql");
    let down_path = migration_dir.join("down.sql");

    Ok(vec![
        (up_path, format!("-- Generated by cargo-yauth\n{up_sql}")),
        (
            down_path,
            format!("-- Generated by cargo-yauth\n{down_sql}"),
        ),
    ])
}

/// Generate sqlx migration files: `NNNNNNNN_name.sql`.
fn generate_sqlx_files(
    migrations_dir: &Path,
    name: &str,
    up_sql: &str,
) -> Result<Vec<(PathBuf, String)>, GenerateError> {
    // Scan existing migrations to find the next number
    let next_num = next_sqlx_number(migrations_dir);
    let file_name = format!("{:08}_{}.sql", next_num, name);
    let path = migrations_dir.join(file_name);

    Ok(vec![(
        path,
        format!("-- Generated by cargo-yauth\n{up_sql}"),
    )])
}

/// Find the next sequential number for sqlx migrations.
fn next_sqlx_number(migrations_dir: &Path) -> u32 {
    if !migrations_dir.exists() {
        return 1;
    }

    let max = std::fs::read_dir(migrations_dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    // Parse NNNNNNNN from the beginning
                    name.split('_').next().and_then(|n| n.parse::<u32>().ok())
                })
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);

    max + 1
}

/// Write generated migration files to disk.
pub fn write_migration(migration: &GeneratedMigration) -> Result<(), GenerateError> {
    for (path, content) in &migration.files {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::YAuthConfig;

    #[test]
    fn generate_init_diesel_postgres() {
        let config = YAuthConfig::new(
            crate::Orm::Diesel,
            "postgres",
            vec!["email-password".to_string()],
        );
        let result = generate_init(&config).unwrap();
        assert!(!result.files.is_empty());
        // Should have up.sql, down.sql, and schema.rs
        assert_eq!(result.files.len(), 3);
        let up_content = &result.files[0].1;
        assert!(up_content.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
        assert!(up_content.contains("CREATE TABLE IF NOT EXISTS yauth_passwords"));
        // schema.rs should contain diesel table! macros
        let schema_rs = &result.files[2].1;
        assert!(schema_rs.contains("diesel::table!"));
        assert!(schema_rs.contains("yauth_users (id)"));
    }

    #[test]
    fn generate_init_sqlx_sqlite() {
        let config = YAuthConfig::new(
            crate::Orm::Sqlx,
            "sqlite",
            vec!["email-password".to_string()],
        );
        let result = generate_init(&config).unwrap();
        // sqlx produces a single file
        assert_eq!(result.files.len(), 1);
        let content = &result.files[0].1;
        assert!(content.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
        // SQLite should not have UUID or TIMESTAMPTZ
        assert!(!content.contains("UUID "));
        assert!(!content.contains("TIMESTAMPTZ"));
    }

    #[test]
    fn generate_init_with_custom_prefix() {
        let mut config = YAuthConfig::new(
            crate::Orm::Diesel,
            "postgres",
            vec!["email-password".to_string()],
        );
        config.migration.table_prefix = "auth_".to_string();
        let result = generate_init(&config).unwrap();
        let up_content = &result.files[0].1;
        assert!(up_content.contains("auth_users"));
        assert!(up_content.contains("auth_passwords"));
        assert!(!up_content.contains("yauth_"));
    }

    #[test]
    fn generate_add_plugin_produces_incremental_sql() {
        use crate::collect_schema_for_plugins;
        use crate::diff::{render_changes_sql, schema_diff};

        let mut config = YAuthConfig::new(
            crate::Orm::Diesel,
            "postgres",
            vec!["email-password".to_string(), "mfa".to_string()],
        );
        config.migration.migrations_dir = "migrations".to_string();

        let previous = vec!["email-password".to_string()];
        let from = collect_schema_for_plugins(&previous, &config.migration.table_prefix).unwrap();
        let to =
            collect_schema_for_plugins(&config.plugins.enabled, &config.migration.table_prefix)
                .unwrap();
        let changes = schema_diff(&from, &to);
        let (up_sql, down_sql) = render_changes_sql(&changes, crate::Dialect::Postgres);

        let result = generate_add_plugin(&config, "mfa", &up_sql, &down_sql).unwrap();
        assert!(!result.files.is_empty());
        let up_content = &result.files[0].1;
        // Should only have mfa tables, not core or email-password
        assert!(up_content.contains("yauth_totp_secrets"));
        assert!(up_content.contains("yauth_backup_codes"));
        // Core tables should not be created, but FK references to yauth_users are expected
        assert!(!up_content.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
    }

    #[test]
    fn generate_remove_plugin_produces_drop_sql() {
        use crate::collect_schema_for_plugins;
        use crate::diff::{render_changes_sql, schema_diff};

        let config = YAuthConfig::new(
            crate::Orm::Diesel,
            "postgres",
            vec!["email-password".to_string()],
        );

        let previous = vec!["email-password".to_string(), "passkey".to_string()];
        let from = collect_schema_for_plugins(&previous, &config.migration.table_prefix).unwrap();
        let to =
            collect_schema_for_plugins(&config.plugins.enabled, &config.migration.table_prefix)
                .unwrap();
        let changes = schema_diff(&from, &to);
        let (up_sql, down_sql) = render_changes_sql(&changes, crate::Dialect::Postgres);

        let result = generate_remove_plugin(&config, "passkey", &up_sql, &down_sql).unwrap();
        assert!(!result.files.is_empty());
        let up_content = &result.files[0].1;
        assert!(up_content.contains("DROP TABLE IF EXISTS yauth_webauthn_credentials"));
    }

    #[test]
    fn generate_init_mysql_dialect() {
        let config = YAuthConfig::new(
            crate::Orm::Diesel,
            "mysql",
            vec!["email-password".to_string()],
        );
        let result = generate_init(&config).unwrap();
        let up_content = &result.files[0].1;
        assert!(up_content.contains("ENGINE=InnoDB"));
        assert!(up_content.contains("CHAR(36)"));
    }
}
