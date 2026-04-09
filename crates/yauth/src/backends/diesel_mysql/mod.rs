//! MySQL/MariaDB backend implementation for yauth.
//!
//! This module provides `DieselMysqlBackend`, which implements `DatabaseBackend`
//! using `diesel-async` with the MySQL backend for MySQL 8+ and MariaDB 10.6+.
//!
//! Key differences from the Postgres backend:
//! - All UUID columns stored as CHAR(36) (String in Diesel models)
//! - All DateTime columns stored as DATETIME (String in Diesel models, converted via helpers)
//! - All JSON columns stored as JSON (String in Diesel models)
//! - No RETURNING support — INSERT then SELECT by known primary key
//! - Uses `ON DUPLICATE KEY UPDATE` instead of `ON CONFLICT`
//! - Uses `LIKE` instead of `ILIKE` (MySQL LIKE is case-insensitive with default collation)
//! - Uses `diesel_async::AsyncMysqlConnection` with `deadpool` pooling

mod models;
pub(crate) mod schema;

mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;

mod audit_repo;
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

use std::sync::Arc;

use crate::repo::{DatabaseBackend, Repositories};

/// Type alias for the MySQL deadpool connection pool.
pub type MysqlPool =
    diesel_async_crate::pooled_connection::deadpool::Pool<diesel_async_crate::AsyncMysqlConnection>;

/// The MySQL database backend for yauth.
///
/// Supports MySQL 8.0+ and MariaDB 10.6+.
pub struct DieselMysqlBackend {
    pool: MysqlPool,
}

impl DieselMysqlBackend {
    /// Create from an existing pool.
    pub fn from_pool(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl DatabaseBackend for DieselMysqlBackend {
    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::MysqlUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::MysqlSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::MysqlAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::MysqlSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::MysqlChallengeRepo::new(self.pool.clone())),
            rate_limits: Arc::new(rate_limit_repo::MysqlRateLimitRepo::new(self.pool.clone())),
            revocations: Arc::new(revocation_repo::MysqlRevocationRepo::new(self.pool.clone())),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::MysqlPasswordRepo::new(self.pool.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::MysqlEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::MysqlPasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::MysqlPasskeyRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::MysqlTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::MysqlBackupCodeRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::MysqlOauthAccountRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::MysqlOauthStateRepo::new(self.pool.clone())),
            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::MysqlApiKeyRepo::new(self.pool.clone())),
            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::MysqlRefreshTokenRepo::new(self.pool.clone())),
            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::MysqlMagicLinkRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::MysqlOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::MysqlAuthorizationCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::MysqlConsentRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::MysqlDeviceCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::MysqlAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::MysqlUnlockTokenRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::MysqlWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::MysqlWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}
