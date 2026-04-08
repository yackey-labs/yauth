//! SeaORM-based MySQL backend for yauth.
//!
//! Self-contained -- entities and repo implementations live here, not in `seaorm_common`.
//! Uses `String` for UUID columns (MySQL stores as CHAR(36)).
//! Shared helpers (`sea_err`, `to_tz`, etc.) are imported from `seaorm_common`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

// Local entities (MySQL-specific -- String UUIDs)
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

/// SeaORM-based MySQL backend.
pub struct SeaOrmMysqlBackend {
    db: DatabaseConnection,
}

impl SeaOrmMysqlBackend {
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

    /// Create all yauth tables using SeaORM schema builder.
    /// Useful for test setup. NOT for production.
    pub async fn create_tables(&self) -> Result<(), RepoError> {
        use sea_orm::sea_query::TableCreateStatement;
        use sea_orm::{ConnectionTrait, Schema};

        let schema = Schema::new(self.db.get_database_backend());

        async fn create_table(
            db: &DatabaseConnection,
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
            &self.db,
            &schema
                .create_table_from_entity(entities::users::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;
        create_table(
            &self.db,
            &schema
                .create_table_from_entity(entities::sessions::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;
        create_table(
            &self.db,
            &schema
                .create_table_from_entity(entities::audit_log::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;

        // Plugin tables
        #[cfg(feature = "email-password")]
        {
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::passwords::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::email_verifications::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::password_resets::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        }
        #[cfg(feature = "passkey")]
        create_table(
            &self.db,
            &schema
                .create_table_from_entity(entities::passkeys::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;
        #[cfg(feature = "mfa")]
        {
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::totp_secrets::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::backup_codes::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        }
        #[cfg(feature = "oauth")]
        {
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::oauth_accounts::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::oauth_states::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        }
        #[cfg(feature = "api-key")]
        create_table(
            &self.db,
            &schema
                .create_table_from_entity(entities::api_keys::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;
        #[cfg(feature = "bearer")]
        create_table(
            &self.db,
            &schema
                .create_table_from_entity(entities::refresh_tokens::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;
        #[cfg(feature = "magic-link")]
        create_table(
            &self.db,
            &schema
                .create_table_from_entity(entities::magic_links::Entity)
                .if_not_exists()
                .to_owned(),
        )
        .await?;
        #[cfg(feature = "oauth2-server")]
        {
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::oauth2_clients::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::authorization_codes::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::consents::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::device_codes::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        }
        #[cfg(feature = "account-lockout")]
        {
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::account_locks::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::unlock_tokens::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        }
        #[cfg(feature = "webhooks")]
        {
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::webhooks::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
            create_table(
                &self.db,
                &schema
                    .create_table_from_entity(entities::webhook_deliveries::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        }

        Ok(())
    }
}

impl DatabaseBackend for SeaOrmMysqlBackend {
    fn migrate(
        &self,
        features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        let required_tables = collect_required_tables(features);
        Box::pin(async move { validate_schema_mysql(&self.db, &required_tables).await })
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

/// Validate that expected yauth tables exist in the MySQL database.
/// Does NOT run any DDL -- returns a descriptive error if tables are missing.
async fn validate_schema_mysql(
    db: &DatabaseConnection,
    required: &[String],
) -> Result<(), RepoError> {
    use sea_orm::{ConnectionTrait, Statement};

    let stmt = Statement::from_string(
        db.get_database_backend(),
        "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'yauth_%'"
            .to_string(),
    );
    let rows = db.query_all_raw(stmt).await.map_err(|e| {
        RepoError::Internal(format!("failed to query information_schema: {e}").into())
    })?;

    let existing_tables: std::collections::HashSet<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<String>("", "TABLE_NAME").ok())
        .collect();

    let missing: Vec<&String> = required
        .iter()
        .filter(|t| !existing_tables.contains(*t))
        .collect();

    if !missing.is_empty() {
        return Err(RepoError::Internal(
            format!(
                "missing yauth tables: {} -- run migrations first",
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
