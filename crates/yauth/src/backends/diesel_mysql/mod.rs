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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

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
    /// Create from a MySQL database URL.
    ///
    /// URL format: `mysql://user:password@host:port/database`
    pub fn new(url: &str) -> Result<Self, RepoError> {
        let config = diesel_async_crate::pooled_connection::AsyncDieselConnectionManager::<
            diesel_async_crate::AsyncMysqlConnection,
        >::new(url);

        let pool = diesel_async_crate::pooled_connection::deadpool::Pool::builder(config)
            .max_size(32)
            .build()
            .map_err(|e| RepoError::Internal(format!("Failed to create MySQL pool: {e}").into()))?;

        Ok(Self { pool })
    }

    /// Create from an existing pool.
    pub fn from_pool(pool: MysqlPool) -> Self {
        Self { pool }
    }
}

impl DatabaseBackend for DieselMysqlBackend {
    fn migrate(
        &self,
        _features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        Box::pin(async move {
            run_mysql_migrations(&self.pool)
                .await
                .map_err(RepoError::Internal)
        })
    }

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

/// Run declarative migrations using the MySQL DDL generator.
///
/// 1. Collects core + plugin schemas based on compile-time feature flags
/// 2. Generates MySQL DDL
/// 3. Checks if schema hash has changed (via yauth_schema_migrations table)
/// 4. Runs CREATE TABLE IF NOT EXISTS for all tables
/// 5. Records the schema hash in the tracking table
async fn run_mysql_migrations(
    pool: &MysqlPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::{RunQueryDsl, SimpleAsyncConnection};

    let table_lists = crate::schema::collect_feature_gated_schemas();
    let merged = crate::schema::collect_schema(table_lists)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let mut conn = pool.get().await.map_err(|e| {
        Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error + Send + Sync>
    })?;

    // Create tracking table (MySQL-compatible)
    (*conn)
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS `yauth_schema_migrations` (\
            `id` INT AUTO_INCREMENT PRIMARY KEY, \
            `schema_hash` VARCHAR(255) NOT NULL, \
            `applied_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP\
        ) ENGINE=InnoDB",
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Check schema hash
    let hash = crate::schema::schema_hash(&merged);

    // Check if hash is already applied using raw SQL
    use diesel::QueryableByName;
    use diesel::sql_types::BigInt;

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    let query = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM yauth_schema_migrations WHERE schema_hash = ?",
    )
    .bind::<diesel::sql_types::Text, _>(&hash);
    let rows: Vec<CountRow> = RunQueryDsl::load(query, &mut *conn)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let already_applied = rows.into_iter().next().is_some_and(|r| r.count > 0);
    if already_applied {
        return Ok(());
    }

    // Generate and run MySQL DDL
    let ddl = crate::schema::generate_mysql_ddl(&merged);

    // Execute each statement individually
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
