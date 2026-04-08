//! Shared SeaORM entities and repository implementations.
//!
//! Database-agnostic — all three SeaORM backends (PG, MySQL, SQLite) share this module.
//! Each per-dialect backend re-exports entities and constructs repos with its own `DatabaseConnection`.

pub mod entities;

mod audit_repo;
mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;
mod user_repo;

#[cfg(feature = "account-lockout")]
mod account_lockout_repo;
#[cfg(feature = "api-key")]
mod api_key_repo;
#[cfg(feature = "bearer")]
mod bearer_repo;
#[cfg(feature = "magic-link")]
mod magic_link_repo;
#[cfg(feature = "mfa")]
mod mfa_repo;
#[cfg(feature = "oauth2-server")]
mod oauth2_server_repo;
#[cfg(feature = "oauth")]
mod oauth_repo;
#[cfg(feature = "passkey")]
mod passkey_repo;
#[cfg(feature = "email-password")]
mod password_repo;
#[cfg(feature = "webhooks")]
mod webhooks_repo;

// Re-export repo structs for backend construction
pub(crate) use audit_repo::*;
pub(crate) use challenge_repo::*;
pub(crate) use rate_limit_repo::*;
pub(crate) use revocation_repo::*;
pub(crate) use session_ops_repo::*;
pub(crate) use user_repo::*;

#[cfg(feature = "account-lockout")]
pub(crate) use account_lockout_repo::*;
#[cfg(feature = "api-key")]
pub(crate) use api_key_repo::*;
#[cfg(feature = "bearer")]
pub(crate) use bearer_repo::*;
#[cfg(feature = "magic-link")]
pub(crate) use magic_link_repo::*;
#[cfg(feature = "mfa")]
pub(crate) use mfa_repo::*;
#[cfg(feature = "oauth")]
pub(crate) use oauth_repo::*;
#[cfg(feature = "oauth2-server")]
pub(crate) use oauth2_server_repo::*;
#[cfg(feature = "passkey")]
pub(crate) use passkey_repo::*;
#[cfg(feature = "email-password")]
pub(crate) use password_repo::*;
#[cfg(feature = "webhooks")]
pub(crate) use webhooks_repo::*;

use crate::repo::RepoError;
use sea_orm::prelude::DateTimeWithTimeZone;

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
    // Check the Display output for constraint messages across all error variants
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
