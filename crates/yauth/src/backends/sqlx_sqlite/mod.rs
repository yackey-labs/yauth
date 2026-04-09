//! sqlx-based SQLite backend for yauth.
//!
//! SQLite-specific: `?` placeholders, RETURNING (3.35+), TEXT for UUIDs/JSON/datetimes,
//! LIKE (case-insensitive via COLLATE NOCASE on email column), datetime('now').

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

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::repo::{DatabaseBackend, Repositories};

/// sqlx-based SQLite backend.
pub struct SqlxSqliteBackend {
    pool: SqlitePool,
}

impl SqlxSqliteBackend {
    /// Create from an existing pool.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl DatabaseBackend for SqlxSqliteBackend {
    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::SqlxSqliteUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::SqlxSqliteSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::SqlxSqliteAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::SqlxSqliteSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::SqlxSqliteChallengeRepo::new(
                self.pool.clone(),
            )),
            rate_limits: Arc::new(rate_limit_repo::SqlxSqliteRateLimitRepo::new(
                self.pool.clone(),
            )),
            revocations: Arc::new(revocation_repo::SqlxSqliteRevocationRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::SqlxSqlitePasswordRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::SqlxSqliteEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::SqlxSqlitePasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::SqlxSqlitePasskeyRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::SqlxSqliteTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::SqlxSqliteBackupCodeRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::SqlxSqliteOauthAccountRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::SqlxSqliteOauthStateRepo::new(self.pool.clone())),
            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::SqlxSqliteApiKeyRepo::new(self.pool.clone())),
            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::SqlxSqliteRefreshTokenRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::SqlxSqliteMagicLinkRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::SqlxSqliteOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(
                oauth2_server_repo::SqlxSqliteAuthorizationCodeRepo::new(self.pool.clone()),
            ),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::SqlxSqliteConsentRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::SqlxSqliteDeviceCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::SqlxSqliteAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::SqlxSqliteUnlockTokenRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::SqlxSqliteWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::SqlxSqliteWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}
