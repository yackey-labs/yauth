//! sqlx-based PostgreSQL backend for yauth.
//!
//! Uses `sqlx::query()` / `sqlx::query_as()` with runtime SQL strings.
//! Postgres-specific: native UUID, RETURNING, ILIKE, JSONB, TIMESTAMPTZ,
//! `$1` placeholders, `make_interval()`, UNLOGGED tables.

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

use sqlx::PgPool;

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

pub use sqlx::postgres::PgPoolOptions;

/// sqlx-based PostgreSQL backend.
pub struct SqlxPgBackend {
    pool: PgPool,
}

impl SqlxPgBackend {
    /// Create from a database URL.
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let pool = PgPool::connect(url)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
        Ok(Self { pool })
    }

    /// Create from an existing pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl DatabaseBackend for SqlxPgBackend {
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
            users: Arc::new(user_repo::SqlxPgUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::SqlxPgSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::SqlxPgAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::SqlxPgSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::SqlxPgChallengeRepo::new(self.pool.clone())),
            rate_limits: Arc::new(rate_limit_repo::SqlxPgRateLimitRepo::new(self.pool.clone())),
            revocations: Arc::new(revocation_repo::SqlxPgRevocationRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::SqlxPgPasswordRepo::new(self.pool.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::SqlxPgEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::SqlxPgPasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::SqlxPgPasskeyRepo::new(self.pool.clone())),

            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::SqlxPgTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::SqlxPgBackupCodeRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::SqlxPgOauthAccountRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::SqlxPgOauthStateRepo::new(self.pool.clone())),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::SqlxPgApiKeyRepo::new(self.pool.clone())),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::SqlxPgRefreshTokenRepo::new(self.pool.clone())),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::SqlxPgMagicLinkRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::SqlxPgOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::SqlxPgAuthorizationCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::SqlxPgConsentRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::SqlxPgDeviceCodeRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::SqlxPgAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::SqlxPgUnlockTokenRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::SqlxPgWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::SqlxPgWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}
