//! diesel-libsql backend implementation for yauth.
//!
//! This module provides `DieselLibsqlBackend`, which implements `DatabaseBackend`
//! using the `diesel-libsql` crate for SQLite/libSQL/Turso databases.
//!
//! Key differences from the Postgres backend:
//! - All UUID columns stored as TEXT (String)
//! - All DateTime columns stored as TEXT (ISO 8601 strings)
//! - All JSON columns stored as TEXT (serialized JSON)
//! - Uses `diesel_libsql::AsyncLibSqlConnection` instead of `AsyncPgConnection`
//! - Uses `diesel_libsql::deadpool::Pool` for connection pooling
//! - Uses `LIKE` instead of `ILIKE` (SQLite LIKE is case-insensitive for ASCII)
//! - Uses `RETURNING` (supported by libSQL)

mod models;
pub(crate) mod schema;

mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;

mod audit_repo;
mod user_repo;

#[cfg(feature = "email-password")]
mod password_repo;

#[cfg(feature = "passkey")]
mod passkey_repo;

#[cfg(feature = "mfa")]
mod mfa_repo;

#[cfg(feature = "oauth")]
mod oauth_repo;

#[cfg(feature = "api-key")]
mod api_key_repo;

#[cfg(feature = "bearer")]
mod bearer_repo;

#[cfg(feature = "magic-link")]
mod magic_link_repo;

#[cfg(feature = "oauth2-server")]
mod oauth2_server_repo;

#[cfg(feature = "account-lockout")]
mod account_lockout_repo;

#[cfg(feature = "webhooks")]
mod webhooks_repo;

use std::sync::Arc;

use crate::repo::{DatabaseBackend, Repositories};

/// Type alias for the diesel-libsql deadpool connection pool.
pub type LibsqlPool = diesel_libsql::deadpool::Pool;

/// The diesel-libsql database backend for yauth.
///
/// Supports local SQLite files (`file:path.db`), in-memory databases
/// (`file::memory:`), and remote Turso databases (`libsql://...`).
pub struct DieselLibsqlBackend {
    pool: LibsqlPool,
}

impl DieselLibsqlBackend {
    /// Create from an existing pool.
    pub fn from_pool(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl DatabaseBackend for DieselLibsqlBackend {
    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::LibsqlUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::LibsqlSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::LibsqlAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::LibsqlSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::LibsqlChallengeRepo::new(self.pool.clone())),
            rate_limits: Arc::new(rate_limit_repo::LibsqlRateLimitRepo::new(self.pool.clone())),
            revocations: Arc::new(revocation_repo::LibsqlRevocationRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::LibsqlPasswordRepo::new(self.pool.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::LibsqlEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::LibsqlPasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::LibsqlPasskeyRepo::new(self.pool.clone())),

            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::LibsqlTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::LibsqlBackupCodeRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::LibsqlOauthAccountRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::LibsqlOauthStateRepo::new(self.pool.clone())),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::LibsqlApiKeyRepo::new(self.pool.clone())),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::LibsqlRefreshTokenRepo::new(self.pool.clone())),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::LibsqlMagicLinkRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::LibsqlOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::LibsqlAuthorizationCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::LibsqlConsentRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::LibsqlDeviceCodeRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::LibsqlAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::LibsqlUnlockTokenRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::LibsqlWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::LibsqlWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}
