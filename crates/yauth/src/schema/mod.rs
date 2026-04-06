//! Declarative schema system for yauth.
//!
//! This module re-exports types from `yauth-migration` and provides
//! backend-specific runtime migration functionality that requires ORM deps.

// Re-export all public types from yauth-migration
pub use yauth_migration::{
    ALL_PLUGINS, ColumnDef, ColumnType, Dialect, ForeignKey, IndexDef, OnDelete, SchemaError,
    TableDef, YAuthSchema, collect_schema, collect_schema_for_plugins, core_schema, generate_ddl,
    generate_mysql_ddl, generate_postgres_ddl, generate_sqlite_ddl, plugin_schema_by_name,
    plugin_schemas, schema_hash,
};

// Keep the tracking functions that depend on diesel (ORM-specific)
mod tracking;
#[cfg(feature = "diesel-pg-backend")]
pub use tracking::{ensure_tracking_table, is_schema_applied, record_schema_applied};

// Keep the runtime migration diff that depends on diesel
mod postgres_runtime;
#[cfg(feature = "diesel-pg-backend")]
pub use postgres_runtime::generate_migration_diff;

/// Collect all table definitions based on compile-time feature flags.
///
/// Shared by MySQL and libSQL backends to avoid duplicating the feature-flag
/// schema collection logic.
#[cfg(any(
    feature = "diesel-mysql-backend",
    feature = "diesel-libsql-backend",
    feature = "diesel-sqlite-backend"
))]
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
