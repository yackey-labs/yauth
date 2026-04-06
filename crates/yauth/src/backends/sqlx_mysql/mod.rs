//! sqlx-based MySQL/MariaDB backend for yauth.
//!
//! MySQL-specific: `?` placeholders, no RETURNING, CHAR(36) UUIDs,
//! LIKE (case-insensitive by default), JSON type, DATETIME, ON DUPLICATE KEY UPDATE.

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

mod migrations;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sqlx::MySqlPool;

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

/// sqlx-based MySQL backend.
pub struct SqlxMysqlBackend {
    pool: MySqlPool,
}

impl SqlxMysqlBackend {
    /// Create from a database URL.
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let pool = MySqlPool::connect(url)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
        Ok(Self { pool })
    }

    /// Create from an existing pool.
    pub fn from_pool(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl DatabaseBackend for SqlxMysqlBackend {
    fn migrate(
        &self,
        _features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        Box::pin(async move {
            migrations::run_migrations(&self.pool)
                .await
                .map_err(RepoError::Internal)
        })
    }

    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::SqlxMysqlUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::SqlxMysqlSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::SqlxMysqlAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::SqlxMysqlSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::SqlxMysqlChallengeRepo::new(
                self.pool.clone(),
            )),
            rate_limits: Arc::new(rate_limit_repo::SqlxMysqlRateLimitRepo::new(
                self.pool.clone(),
            )),
            revocations: Arc::new(revocation_repo::SqlxMysqlRevocationRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::SqlxMysqlPasswordRepo::new(self.pool.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::SqlxMysqlEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::SqlxMysqlPasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::SqlxMysqlPasskeyRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::SqlxMysqlTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::SqlxMysqlBackupCodeRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::SqlxMysqlOauthAccountRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::SqlxMysqlOauthStateRepo::new(self.pool.clone())),
            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::SqlxMysqlApiKeyRepo::new(self.pool.clone())),
            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::SqlxMysqlRefreshTokenRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::SqlxMysqlMagicLinkRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::SqlxMysqlOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::SqlxMysqlAuthorizationCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::SqlxMysqlConsentRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::SqlxMysqlDeviceCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::SqlxMysqlAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::SqlxMysqlUnlockTokenRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::SqlxMysqlWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::SqlxMysqlWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}
