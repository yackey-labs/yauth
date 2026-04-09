//! Native SQLite backend implementation for yauth.
//!
//! This module provides `DieselSqliteBackend`, which implements `DatabaseBackend`
//! using diesel's built-in `SqliteConnection` wrapped in `SyncConnectionWrapper`
//! from diesel-async for async compatibility.
//!
//! Key differences from the Postgres backend:
//! - All UUID columns stored as TEXT (String)
//! - All DateTime columns stored as TEXT (ISO 8601 strings)
//! - All JSON columns stored as TEXT (serialized JSON)
//! - No RETURNING support — INSERT then SELECT (same as MySQL backend)
//! - Uses `SyncConnectionWrapper<SqliteConnection>` + deadpool pooling
//! - Uses `LIKE` instead of `ILIKE` (SQLite LIKE is case-insensitive for ASCII)
//! - `:memory:` databases need pool max_size=1; file databases use WAL mode

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

/// Type alias for the SQLite async connection (sync connection wrapped for async use).
pub type SqliteAsyncConn =
    diesel_async_crate::sync_connection_wrapper::SyncConnectionWrapper<diesel::SqliteConnection>;

/// Type alias for the SQLite deadpool connection pool.
pub type SqlitePool = diesel_async_crate::pooled_connection::deadpool::Pool<SqliteAsyncConn>;

/// The native SQLite database backend for yauth.
///
/// Uses diesel's built-in `SqliteConnection` via `SyncConnectionWrapper` for async
/// compatibility. Supports file-based databases and `:memory:` databases.
pub struct DieselSqliteBackend {
    pool: SqlitePool,
    /// Whether this is an in-memory database. Stored for diagnostics.
    #[allow(dead_code)]
    is_memory: bool,
}

impl DieselSqliteBackend {
    /// Create from an existing pool.
    ///
    /// Assumes a file-based database. Use `from_pool_memory` for in-memory databases.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self {
            pool,
            is_memory: false,
        }
    }

    /// Create from an existing pool for an in-memory database.
    pub fn from_pool_memory(pool: SqlitePool) -> Self {
        Self {
            pool,
            is_memory: true,
        }
    }
}

impl DatabaseBackend for DieselSqliteBackend {
    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::SqliteUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::SqliteSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::SqliteAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::SqliteSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::SqliteChallengeRepo::new(self.pool.clone())),
            rate_limits: Arc::new(rate_limit_repo::SqliteRateLimitRepo::new(self.pool.clone())),
            revocations: Arc::new(revocation_repo::SqliteRevocationRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::SqlitePasswordRepo::new(self.pool.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::SqliteEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::SqlitePasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::SqlitePasskeyRepo::new(self.pool.clone())),

            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::SqliteTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::SqliteBackupCodeRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::SqliteOauthAccountRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::SqliteOauthStateRepo::new(self.pool.clone())),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::SqliteApiKeyRepo::new(self.pool.clone())),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::SqliteRefreshTokenRepo::new(self.pool.clone())),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::SqliteMagicLinkRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::SqliteOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::SqliteAuthorizationCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::SqliteConsentRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::SqliteDeviceCodeRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::SqliteAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::SqliteUnlockTokenRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::SqliteWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::SqliteWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}
