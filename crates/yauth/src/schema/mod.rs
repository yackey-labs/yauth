//! Declarative schema system for yauth.
//!
//! Plugins and core tables declare their schema as Rust data structures.
//! The schema collector merges everything, topologically sorts by FK deps,
//! and dialect-specific DDL generators produce the actual SQL.

mod types;
pub use types::*;

mod core;
pub use core::core_schema;

mod collector;
pub use collector::{SchemaError, YAuthSchema, collect_schema};

mod postgres;
#[cfg(feature = "diesel-pg-backend")]
pub use postgres::generate_migration_diff;
pub use postgres::generate_postgres_ddl;

mod sqlite;
pub use sqlite::generate_sqlite_ddl;

mod mysql;
pub use mysql::generate_mysql_ddl;

mod tracking;
pub use tracking::schema_hash;
#[cfg(feature = "diesel-pg-backend")]
pub use tracking::{ensure_tracking_table, is_schema_applied, record_schema_applied};

pub mod plugin_schemas;

/// Collect all table definitions based on compile-time feature flags.
///
/// Shared by MySQL and libSQL backends to avoid duplicating the feature-flag
/// schema collection logic.
#[cfg(any(feature = "diesel-mysql-backend", feature = "diesel-libsql-backend"))]
pub(crate) fn collect_feature_gated_schemas() -> Vec<Vec<TableDef>> {
    #[allow(unused_mut)]
    let mut lists = vec![core_schema()];

    #[cfg(feature = "email-password")]
    lists.push(plugin_schemas::email_password_schema());
    #[cfg(feature = "passkey")]
    lists.push(plugin_schemas::passkey_schema());
    #[cfg(feature = "mfa")]
    lists.push(plugin_schemas::mfa_schema());
    #[cfg(feature = "oauth")]
    lists.push(plugin_schemas::oauth_schema());
    #[cfg(feature = "bearer")]
    lists.push(plugin_schemas::bearer_schema());
    #[cfg(feature = "api-key")]
    lists.push(plugin_schemas::api_key_schema());
    #[cfg(feature = "magic-link")]
    lists.push(plugin_schemas::magic_link_schema());
    #[cfg(feature = "oauth2-server")]
    lists.push(plugin_schemas::oauth2_server_schema());
    #[cfg(feature = "account-lockout")]
    lists.push(plugin_schemas::account_lockout_schema());
    #[cfg(feature = "webhooks")]
    lists.push(plugin_schemas::webhooks_schema());
    #[cfg(feature = "oidc")]
    lists.push(plugin_schemas::oidc_schema());

    lists
}

#[cfg(test)]
mod tests;
