//! `yauth.toml` configuration file support.
//!
//! This file intentionally has no `database_url` field -- database URLs
//! come from environment variables only. `yauth.toml` is always safe to commit.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level yauth.toml configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YAuthConfig {
    pub migration: MigrationConfig,
    pub plugins: PluginsConfig,
}

/// Migration-related settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// ORM to generate migration files for.
    pub orm: crate::Orm,
    /// SQL dialect: "postgres", "mysql", or "sqlite".
    pub dialect: String,
    /// Directory where migration files are written.
    #[serde(default = "default_migrations_dir")]
    pub migrations_dir: String,
    /// PostgreSQL schema name (optional, default "public").
    #[serde(default)]
    pub schema: Option<String>,
    /// Table name prefix (default "yauth_").
    #[serde(default = "default_table_prefix")]
    pub table_prefix: String,
}

/// Plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// List of enabled plugin names.
    pub enabled: Vec<String>,
}

fn default_migrations_dir() -> String {
    "migrations".to_string()
}

fn default_table_prefix() -> String {
    "yauth_".to_string()
}

impl YAuthConfig {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
        let config: Self = toml::from_str(&contents)
            .map_err(|e| ConfigError::Parse(path.display().to_string(), e))?;
        config.validate()?;
        Ok(config)
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let contents =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Serialize(e.to_string()))?;
        std::fs::write(path, contents)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
        Ok(())
    }

    /// Validate config values.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate dialect
        if self.migration.dialect.parse::<crate::Dialect>().is_err() {
            return Err(ConfigError::InvalidValue(format!(
                "unknown dialect: '{}'",
                self.migration.dialect
            )));
        }

        // Validate plugins
        for plugin in &self.plugins.enabled {
            if !crate::is_known_plugin(plugin) {
                return Err(ConfigError::InvalidValue(format!(
                    "unknown plugin: '{plugin}'"
                )));
            }
        }

        // Validate table prefix
        if self.migration.table_prefix.is_empty() {
            return Err(ConfigError::InvalidValue(
                "table_prefix must not be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Create a new config with defaults for the given ORM and dialect.
    pub fn new(orm: crate::Orm, dialect: &str, plugins: Vec<String>) -> Self {
        Self {
            migration: MigrationConfig {
                orm,
                dialect: dialect.to_string(),
                migrations_dir: default_migrations_dir(),
                schema: None,
                table_prefix: default_table_prefix(),
            },
            plugins: PluginsConfig { enabled: plugins },
        }
    }
}

/// Errors from config operations.
#[derive(Debug)]
pub enum ConfigError {
    Io(String, std::io::Error),
    Parse(String, toml::de::Error),
    Serialize(String),
    InvalidValue(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(path, e) => write!(f, "I/O error with '{path}': {e}"),
            ConfigError::Parse(path, e) => write!(f, "parse error in '{path}': {e}"),
            ConfigError::Serialize(e) => write!(f, "serialization error: {e}"),
            ConfigError::InvalidValue(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}
