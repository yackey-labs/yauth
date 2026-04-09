//! Shared SeaORM helpers used across per-dialect backends (PG, MySQL, SQLite).
//!
//! Contains only dialect-agnostic utilities: error mapping, datetime conversion,
//! UUID/JSON parsing, and table name collection. Entities and repo implementations
//! live in each per-dialect backend module.

use crate::repo::RepoError;
use sea_orm::prelude::DateTimeWithTimeZone;

/// Parse a UUID from a stored string, logging and returning nil on failure.
/// Matches the diesel_common `str_to_uuid` pattern.
pub(crate) fn str_to_uuid(s: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(s).unwrap_or_else(|e| {
        log::error!("Failed to parse UUID from stored value '{}': {}", s, e);
        uuid::Uuid::nil()
    })
}

/// Parse an optional UUID from a stored string.
pub(crate) fn opt_str_to_uuid(s: Option<String>) -> Option<uuid::Uuid> {
    s.map(|s| str_to_uuid(&s))
}

/// Parse JSON from a stored string, logging and returning Null on failure.
pub(crate) fn str_to_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| {
        log::error!("Failed to parse JSON from stored value: {}", e);
        serde_json::Value::Null
    })
}

/// Convert a `NaiveDateTime` to `DateTimeWithTimeZone` (assumes UTC).
pub(crate) fn to_tz(dt: chrono::NaiveDateTime) -> DateTimeWithTimeZone {
    dt.and_utc().fixed_offset()
}

/// Convert an `Option<NaiveDateTime>` to `Option<DateTimeWithTimeZone>`.
pub(crate) fn opt_to_tz(dt: Option<chrono::NaiveDateTime>) -> Option<DateTimeWithTimeZone> {
    dt.map(|d| d.and_utc().fixed_offset())
}

/// Map a SeaORM `DbErr` to `RepoError::Internal`.
pub(crate) fn sea_err(e: sea_orm::DbErr) -> RepoError {
    RepoError::Internal(e.into())
}

/// Detect unique constraint violations and map to `RepoError::Conflict`.
pub(crate) fn sea_conflict(e: sea_orm::DbErr) -> RepoError {
    let msg = e.to_string();
    if msg.contains("duplicate key")
        || msg.contains("Duplicate entry")
        || msg.contains("UNIQUE constraint failed")
        || msg.contains("unique constraint")
    {
        return RepoError::Conflict(msg);
    }
    RepoError::Internal(e.into())
}
