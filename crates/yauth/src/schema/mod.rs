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
pub use postgres::{generate_migration_diff, generate_postgres_ddl};

mod tracking;
pub use tracking::{ensure_tracking_table, is_schema_applied, record_schema_applied, schema_hash};

pub mod plugin_schemas;

#[cfg(test)]
mod tests;
