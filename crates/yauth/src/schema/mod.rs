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
#[cfg(feature = "diesel-backend")]
pub use postgres::generate_migration_diff;
pub use postgres::generate_postgres_ddl;

mod sqlite;
pub use sqlite::generate_sqlite_ddl;

mod mysql;
pub use mysql::generate_mysql_ddl;

mod tracking;
pub use tracking::schema_hash;
#[cfg(feature = "diesel-backend")]
pub use tracking::{ensure_tracking_table, is_schema_applied, record_schema_applied};

pub mod plugin_schemas;

#[cfg(test)]
mod tests;
