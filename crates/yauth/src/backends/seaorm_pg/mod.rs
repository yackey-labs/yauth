//! SeaORM-based PostgreSQL backend for yauth.
//!
//! Uses SeaORM 2.0 with sqlx-postgres under the hood. Entities are shared
//! via `seaorm_common` and re-exported here for public access.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

// Re-export entities for public access
pub use crate::backends::seaorm_common::entities;

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
        // Clone the features data we need to avoid lifetime issues
        let required_tables = collect_required_tables(features);
        Box::pin(async move { validate_schema(&self.db, &required_tables).await })
    }

    fn repositories(&self) -> Repositories {
        use crate::backends::seaorm_common::*;

        Repositories {
            users: Arc::new(SeaOrmUserRepo::new(self.db.clone())),
            sessions: Arc::new(SeaOrmSessionRepo::new(self.db.clone())),
            audit: Arc::new(SeaOrmAuditLogRepo::new(self.db.clone())),
            session_ops: Arc::new(SeaOrmSessionOpsRepo::new(self.db.clone())),
            challenges: Arc::new(SeaOrmChallengeRepo::new(self.db.clone())),
            rate_limits: Arc::new(SeaOrmRateLimitRepo::new(self.db.clone())),
            revocations: Arc::new(SeaOrmRevocationRepo::new(self.db.clone())),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(SeaOrmPasswordRepo::new(self.db.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(SeaOrmEmailVerificationRepo::new(self.db.clone())),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(SeaOrmPasswordResetRepo::new(self.db.clone())),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(SeaOrmPasskeyRepo::new(self.db.clone())),

            #[cfg(feature = "mfa")]
            totp: Arc::new(SeaOrmTotpRepo::new(self.db.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(SeaOrmBackupCodeRepo::new(self.db.clone())),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(SeaOrmOauthAccountRepo::new(self.db.clone())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(SeaOrmOauthStateRepo::new(self.db.clone())),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(SeaOrmApiKeyRepo::new(self.db.clone())),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(SeaOrmRefreshTokenRepo::new(self.db.clone())),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(SeaOrmMagicLinkRepo::new(self.db.clone())),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(SeaOrmOauth2ClientRepo::new(self.db.clone())),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(SeaOrmAuthorizationCodeRepo::new(self.db.clone())),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(SeaOrmConsentRepo::new(self.db.clone())),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(SeaOrmDeviceCodeRepo::new(self.db.clone())),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(SeaOrmAccountLockRepo::new(self.db.clone())),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(SeaOrmUnlockTokenRepo::new(self.db.clone())),

            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(SeaOrmWebhookRepo::new(self.db.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(SeaOrmWebhookDeliveryRepo::new(self.db.clone())),
        }
    }
}

/// Collect the list of required table names based on enabled features.
fn collect_required_tables(features: &EnabledFeatures) -> Vec<String> {
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

/// Validate that expected yauth tables exist in the database.
/// Does NOT run any DDL -- returns a descriptive error if tables are missing.
async fn validate_schema(db: &DatabaseConnection, required: &[String]) -> Result<(), RepoError> {
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
