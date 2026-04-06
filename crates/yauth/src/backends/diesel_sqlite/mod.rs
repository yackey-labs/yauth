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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

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
    is_memory: bool,
}

impl DieselSqliteBackend {
    /// Create from a database URL.
    ///
    /// Supported URL formats:
    /// - `:memory:` or `file::memory:` for in-memory SQLite
    /// - `file:path.db` or `/path/to/db.sqlite` for file databases
    ///
    /// In-memory databases use pool max_size=1 (one connection = one database).
    /// File databases use WAL mode with pool size 8.
    pub fn new(url: &str) -> Result<Self, RepoError> {
        let config = diesel_async_crate::pooled_connection::AsyncDieselConnectionManager::<
            SqliteAsyncConn,
        >::new(url);

        let is_memory =
            url == ":memory:" || url == "file::memory:" || url.starts_with("file::memory:?");
        let max_size = if is_memory { 1 } else { 8 };

        let pool = diesel_async_crate::pooled_connection::deadpool::Pool::builder(config)
            .max_size(max_size)
            .build()
            .map_err(|e| {
                RepoError::Internal(format!("Failed to create SQLite pool: {e}").into())
            })?;

        Ok(Self { pool, is_memory })
    }

    /// Create from an existing pool.
    ///
    /// Assumes a file-based database (WAL pragma will be set during migration).
    /// Use `from_pool_memory` for in-memory databases.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self {
            pool,
            is_memory: false,
        }
    }
}

impl DatabaseBackend for DieselSqliteBackend {
    fn migrate(
        &self,
        _features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        let is_memory = self.is_memory;
        Box::pin(async move {
            run_sqlite_migrations(&self.pool, is_memory)
                .await
                .map_err(RepoError::Internal)
        })
    }

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

/// Run declarative migrations using the SQLite DDL generator.
///
/// When `is_memory` is true, the WAL journal mode pragma is skipped since
/// in-memory databases do not support persistent journal modes.
async fn run_sqlite_migrations(
    pool: &SqlitePool,
    is_memory: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::{RunQueryDsl, SimpleAsyncConnection};

    let table_lists = crate::schema::collect_feature_gated_schemas();
    let merged = crate::schema::collect_schema(table_lists)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let mut conn = pool.get().await.map_err(|e| {
        Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error + Send + Sync>
    })?;

    // Enable foreign keys
    (*conn)
        .batch_execute("PRAGMA foreign_keys = ON")
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Enable WAL mode for file-based databases only (in-memory databases ignore it)
    if !is_memory {
        (*conn)
            .batch_execute("PRAGMA journal_mode = WAL")
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    }

    // Create tracking table
    (*conn)
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS yauth_schema_migrations (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            schema_hash TEXT NOT NULL, \
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))\
        )",
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Check schema hash
    let hash = crate::schema::schema_hash(&merged);

    use diesel::QueryableByName;
    use diesel::sql_types::Integer;

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = Integer)]
        count: i32,
    }

    let query = diesel::sql_query(
        "SELECT CAST(COUNT(*) AS INTEGER) AS count FROM yauth_schema_migrations WHERE schema_hash = ?",
    )
    .bind::<diesel::sql_types::Text, _>(&hash);
    let rows: Vec<CountRow> = RunQueryDsl::load(query, &mut *conn)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let already_applied = rows.into_iter().next().is_some_and(|r| r.count > 0);
    if already_applied {
        return Ok(());
    }

    // Generate and run SQLite DDL
    let ddl = crate::schema::generate_sqlite_ddl(&merged);

    for statement in ddl.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        (*conn)
            .batch_execute(trimmed)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    }

    // Record the schema hash
    diesel::sql_query("INSERT INTO yauth_schema_migrations (schema_hash) VALUES (?)")
        .bind::<diesel::sql_types::Text, _>(&hash)
        .execute(&mut *conn)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(())
}
