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

/// Collect the list of required table names based on enabled features.
pub(crate) fn collect_required_tables(features: &crate::repo::EnabledFeatures) -> Vec<String> {
    let mut required: Vec<String> = vec![
        "yauth_users".into(),
        "yauth_sessions".into(),
        "yauth_audit_log".into(),
    ];

    if features.email_password {
        required.extend([
            "yauth_passwords".into(),
            "yauth_email_verifications".into(),
            "yauth_password_resets".into(),
        ]);
    }
    if features.passkey {
        required.push("yauth_webauthn_credentials".into());
    }
    if features.mfa {
        required.extend(["yauth_totp_secrets".into(), "yauth_backup_codes".into()]);
    }
    if features.oauth {
        required.extend(["yauth_oauth_accounts".into(), "yauth_oauth_states".into()]);
    }
    if features.api_key {
        required.push("yauth_api_keys".into());
    }
    if features.bearer {
        required.push("yauth_refresh_tokens".into());
    }
    if features.magic_link {
        required.push("yauth_magic_links".into());
    }
    if features.oauth2_server {
        required.extend([
            "yauth_oauth2_clients".into(),
            "yauth_authorization_codes".into(),
            "yauth_consents".into(),
            "yauth_device_codes".into(),
        ]);
    }
    if features.account_lockout {
        required.extend(["yauth_account_locks".into(), "yauth_unlock_tokens".into()]);
    }
    if features.webhooks {
        required.extend(["yauth_webhooks".into(), "yauth_webhook_deliveries".into()]);
    }

    required
}
