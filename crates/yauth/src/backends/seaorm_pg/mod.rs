//! SeaORM-based PostgreSQL backend for yauth.
//!
//! Self-contained — entities and repo implementations live here, not in `seaorm_common`.
//! Shared helpers (`sea_err`, `to_tz`, etc.) are imported from `seaorm_common`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

// Local entities (PG-specific)
pub mod entities;

// Shared helpers from seaorm_common
use crate::backends::seaorm_common::{
    collect_required_tables, opt_to_tz, sea_conflict, sea_err, to_tz,
};

// Core repo modules (always compiled)
mod audit_repo;
mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;
mod user_repo;

// Feature-gated repo modules
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

// Re-export repo structs for build_repositories()
use audit_repo::*;
use challenge_repo::*;
use rate_limit_repo::*;
use revocation_repo::*;
use session_ops_repo::*;
use user_repo::*;

#[cfg(feature = "account-lockout")]
use account_lockout_repo::*;
#[cfg(feature = "api-key")]
use api_key_repo::*;
#[cfg(feature = "bearer")]
use bearer_repo::*;
#[cfg(feature = "magic-link")]
use magic_link_repo::*;
#[cfg(feature = "mfa")]
use mfa_repo::*;
#[cfg(feature = "oauth")]
use oauth_repo::*;
#[cfg(feature = "oauth2-server")]
use oauth2_server_repo::*;
#[cfg(feature = "passkey")]
use passkey_repo::*;
#[cfg(feature = "email-password")]
use password_repo::*;
#[cfg(feature = "webhooks")]
use webhooks_repo::*;

/// SeaORM-based PostgreSQL backend.
pub struct SeaOrmPgBackend {
    db: DatabaseConnection,
}

impl SeaOrmPgBackend {
    /// Create from a database URL.
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let mut opts = ConnectOptions::new(url.to_string());
        opts.max_connections(64)
            .min_connections(2)
            .sqlx_logging(false);
        let db = Database::connect(opts)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
        Ok(Self { db })
    }

    /// Create from an existing `DatabaseConnection`.
    pub fn from_connection(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }
}

impl DatabaseBackend for SeaOrmPgBackend {
    fn migrate(
        &self,
        features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        let required_tables = collect_required_tables(features);
        Box::pin(async move { validate_schema_pg(&self.db, &required_tables).await })
    }

    fn repositories(&self) -> Repositories {
        build_repositories(&self.db)
    }
}

/// Build the `Repositories` struct from a `DatabaseConnection`.
fn build_repositories(db: &DatabaseConnection) -> Repositories {
    Repositories {
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

/// Validate that expected yauth tables exist in the database.
/// Does NOT run any DDL -- returns a descriptive error if tables are missing.
async fn validate_schema_pg(db: &DatabaseConnection, required: &[String]) -> Result<(), RepoError> {
    use sea_orm::{ConnectionTrait, Statement};

    let stmt = Statement::from_string(
        db.get_database_backend(),
        "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'yauth_%'"
            .to_string(),
    );
    let rows = db.query_all_raw(stmt).await.map_err(|e| {
        RepoError::Internal(format!("failed to query information_schema: {e}").into())
    })?;

    let existing_tables: std::collections::HashSet<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<String>("", "table_name").ok())
        .collect();

    let missing: Vec<&String> = required
        .iter()
        .filter(|t| !existing_tables.contains(*t))
        .collect();

    if !missing.is_empty() {
        return Err(RepoError::Internal(
            format!(
                "missing yauth tables: {} -- run SeaORM migrations first",
                missing
                    .iter()
                    .map(|t| t.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into(),
        ));
    }

    Ok(())
}
