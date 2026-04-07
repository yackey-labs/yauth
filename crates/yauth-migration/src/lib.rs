//! Declarative schema system and migration file generator for yauth.
//!
//! This crate has **zero ORM dependencies** — it is a pure code generator.
//! It provides:
//!
//! - Schema types (`TableDef`, `ColumnDef`, `ColumnType`, etc.)
//! - Core + plugin schema definitions
//! - Schema collector with topological sort by FK dependencies
//! - Dialect-specific DDL generators (Postgres, SQLite, MySQL)
//! - Schema diff engine for incremental migrations
//! - Migration file generators (diesel up.sql/down.sql, sqlx numbered .sql)
//! - `yauth.toml` config file support
//! - Schema hash for tracking

mod types;
pub use types::*;

mod core;
pub use core::core_schema;

mod collector;
pub use collector::{SchemaError, YAuthSchema, collect_schema};

mod postgres;
pub use postgres::{generate_postgres_ddl, generate_postgres_drop, generate_postgres_drops};

mod sqlite;
pub use sqlite::{generate_sqlite_ddl, generate_sqlite_drop, generate_sqlite_drops};

mod mysql;
pub use mysql::{generate_mysql_ddl, generate_mysql_drop, generate_mysql_drops};

mod diesel_schema;
pub use diesel_schema::generate_diesel_schema;

mod tracking;
pub use tracking::schema_hash;

pub mod plugin_schemas;

pub mod config;
pub mod diff;
pub mod generate;

/// All known plugin names.
pub const ALL_PLUGINS: &[&str] = &[
    "email-password",
    "passkey",
    "mfa",
    "oauth",
    "bearer",
    "api-key",
    "magic-link",
    "oauth2-server",
    "account-lockout",
    "webhooks",
    "oidc",
];

/// Get the schema tables for a plugin by name.
///
/// Returns `None` if the plugin name is not recognized.
pub fn plugin_schema_by_name(name: &str) -> Option<Vec<TableDef>> {
    match name {
        "email-password" => Some(plugin_schemas::email_password_schema()),
        "passkey" => Some(plugin_schemas::passkey_schema()),
        "mfa" => Some(plugin_schemas::mfa_schema()),
        "oauth" => Some(plugin_schemas::oauth_schema()),
        "bearer" => Some(plugin_schemas::bearer_schema()),
        "api-key" => Some(plugin_schemas::api_key_schema()),
        "magic-link" => Some(plugin_schemas::magic_link_schema()),
        "oauth2-server" => Some(plugin_schemas::oauth2_server_schema()),
        "account-lockout" => Some(plugin_schemas::account_lockout_schema()),
        "webhooks" => Some(plugin_schemas::webhooks_schema()),
        "oidc" => Some(plugin_schemas::oidc_schema()),
        _ => None,
    }
}

/// Check if a plugin name is valid (even if it has no database tables).
/// Plugins like `admin`, `status`, `telemetry`, and `openapi` are code-only.
pub fn is_known_plugin(name: &str) -> bool {
    matches!(
        name,
        "email-password"
            | "passkey"
            | "mfa"
            | "oauth"
            | "bearer"
            | "api-key"
            | "magic-link"
            | "admin"
            | "status"
            | "oauth2-server"
            | "account-lockout"
            | "webhooks"
            | "oidc"
            | "telemetry"
            | "openapi"
    )
}

/// Collect a schema from a list of plugin names plus core tables.
///
/// The `table_prefix` replaces the default `yauth_` prefix on all table names
/// and FK references.
pub fn collect_schema_for_plugins(
    plugins: &[String],
    table_prefix: &str,
) -> Result<YAuthSchema, SchemaError> {
    let mut table_lists = vec![core_schema()];
    for plugin in plugins {
        match plugin_schema_by_name(plugin) {
            Some(tables) => table_lists.push(tables),
            None if is_known_plugin(plugin) => {
                // Plugin exists but has no tables (e.g., admin, status, telemetry, openapi)
            }
            None => {
                return Err(SchemaError::UnknownPlugin(plugin.clone()));
            }
        }
    }

    // Apply table prefix if not the default
    if table_prefix != "yauth_" {
        for list in &mut table_lists {
            for table in list.iter_mut() {
                table.apply_prefix("yauth_", table_prefix);
            }
        }
    }

    collect_schema(table_lists)
}

/// Generate DDL for a schema in the given dialect.
pub fn generate_ddl(schema: &YAuthSchema, dialect: Dialect) -> String {
    match dialect {
        Dialect::Postgres => generate_postgres_ddl(schema),
        Dialect::Sqlite => generate_sqlite_ddl(schema),
        Dialect::Mysql => generate_mysql_ddl(schema),
    }
}

#[cfg(test)]
mod tests;
