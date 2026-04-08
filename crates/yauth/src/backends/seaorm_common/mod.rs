//! Shared SeaORM helpers used across per-dialect backends (PG, MySQL, SQLite).
//!
//! Contains only dialect-agnostic utilities: error mapping, datetime conversion,
//! and table name collection. Entities and repo implementations live in each
//! per-dialect backend module.

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

/// Create all yauth tables using SeaORM schema builder.
///
/// Useful for test setup with in-memory SQLite or fresh databases.
/// NOT for production — users should use their ORM's migration tool.
pub(crate) async fn create_all_tables(db: &sea_orm::DatabaseConnection) -> Result<(), RepoError> {
    use sea_orm::sea_query::TableCreateStatement;
    use sea_orm::{ConnectionTrait, Schema};

    let schema = Schema::new(db.get_database_backend());

    async fn create_table(
        db: &sea_orm::DatabaseConnection,
        stmt: &TableCreateStatement,
    ) -> Result<(), RepoError> {
        let builder = db.get_database_backend();
        db.execute_unprepared(&builder.build(stmt).to_string())
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
        Ok(())
    }

    // Core tables
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::users::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::sessions::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::audit_log::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;

    // Plugin tables — always create all of them (feature gates only affect repo availability)
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::passwords::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::email_verifications::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::password_resets::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::passkeys::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::totp_secrets::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::backup_codes::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::oauth_accounts::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::oauth_states::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::api_keys::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::refresh_tokens::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::magic_links::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::oauth2_clients::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::authorization_codes::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::consents::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::device_codes::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::account_locks::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::unlock_tokens::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::webhooks::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;
    create_table(
        db,
        &schema
            .create_table_from_entity(entities::webhook_deliveries::Entity)
            .if_not_exists()
            .to_owned(),
    )
    .await?;

    Ok(())
}

/// Build the `Repositories` struct from a `DatabaseConnection`.
///
/// Shared across SeaORM backends that still use this common module (MySQL, SQLite).
/// The PG backend has its own `build_repositories()`.
pub(crate) fn build_repositories(db: &sea_orm::DatabaseConnection) -> crate::repo::Repositories {
    use std::sync::Arc;

    crate::repo::Repositories {
        users: Arc::new(SeaOrmUserRepo::new(db.clone())),
        sessions: Arc::new(SeaOrmSessionRepo::new(db.clone())),
        audit: Arc::new(SeaOrmAuditLogRepo::new(db.clone())),
        session_ops: Arc::new(SeaOrmSessionOpsRepo::new(db.clone())),
        challenges: Arc::new(SeaOrmChallengeRepo::new(db.clone())),
        rate_limits: Arc::new(SeaOrmRateLimitRepo::new(db.clone())),
        revocations: Arc::new(SeaOrmRevocationRepo::new(db.clone())),

        #[cfg(feature = "email-password")]
        passwords: Arc::new(SeaOrmPasswordRepo::new(db.clone())),
        #[cfg(feature = "email-password")]
        email_verifications: Arc::new(SeaOrmEmailVerificationRepo::new(db.clone())),
        #[cfg(feature = "email-password")]
        password_resets: Arc::new(SeaOrmPasswordResetRepo::new(db.clone())),

        #[cfg(feature = "passkey")]
        passkeys: Arc::new(SeaOrmPasskeyRepo::new(db.clone())),

        #[cfg(feature = "mfa")]
        totp: Arc::new(SeaOrmTotpRepo::new(db.clone())),
        #[cfg(feature = "mfa")]
        backup_codes: Arc::new(SeaOrmBackupCodeRepo::new(db.clone())),

        #[cfg(feature = "oauth")]
        oauth_accounts: Arc::new(SeaOrmOauthAccountRepo::new(db.clone())),
        #[cfg(feature = "oauth")]
        oauth_states: Arc::new(SeaOrmOauthStateRepo::new(db.clone())),

        #[cfg(feature = "api-key")]
        api_keys: Arc::new(SeaOrmApiKeyRepo::new(db.clone())),

        #[cfg(feature = "bearer")]
        refresh_tokens: Arc::new(SeaOrmRefreshTokenRepo::new(db.clone())),

        #[cfg(feature = "magic-link")]
        magic_links: Arc::new(SeaOrmMagicLinkRepo::new(db.clone())),

        #[cfg(feature = "oauth2-server")]
        oauth2_clients: Arc::new(SeaOrmOauth2ClientRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        authorization_codes: Arc::new(SeaOrmAuthorizationCodeRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        consents: Arc::new(SeaOrmConsentRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        device_codes: Arc::new(SeaOrmDeviceCodeRepo::new(db.clone())),

        #[cfg(feature = "account-lockout")]
        account_locks: Arc::new(SeaOrmAccountLockRepo::new(db.clone())),
        #[cfg(feature = "account-lockout")]
        unlock_tokens: Arc::new(SeaOrmUnlockTokenRepo::new(db.clone())),

        #[cfg(feature = "webhooks")]
        webhooks_repo: Arc::new(SeaOrmWebhookRepo::new(db.clone())),
        #[cfg(feature = "webhooks")]
        webhook_deliveries: Arc::new(SeaOrmWebhookDeliveryRepo::new(db.clone())),
    }
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
