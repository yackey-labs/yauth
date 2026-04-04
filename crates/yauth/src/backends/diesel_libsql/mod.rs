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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

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
    /// Create from a database URL.
    ///
    /// Supported URL formats:
    /// - `file:path.db` or `file::memory:` for local SQLite
    /// - `libsql://host` for remote Turso (requires `LIBSQL_AUTH_TOKEN` env var)
    /// - `:memory:` for in-memory SQLite
    pub fn new(url: &str) -> Result<Self, RepoError> {
        let manager = diesel_libsql::deadpool::Manager::new(url);

        // In-memory libSQL databases are connection-scoped — each connection gets
        // its own empty database. Restrict the pool to a single connection so all
        // queries share the same in-memory state.
        let is_memory =
            url == ":memory:" || url == "file::memory:" || url.starts_with("file::memory:?");
        let max_size = if is_memory { 1 } else { 8 };

        let pool = diesel_libsql::deadpool::Pool::builder(manager)
            .max_size(max_size)
            .build()
            .map_err(|e| {
                RepoError::Internal(format!("Failed to create libsql pool: {e}").into())
            })?;
        Ok(Self { pool })
    }

    /// Create from an existing pool.
    pub fn from_pool(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}

impl DatabaseBackend for DieselLibsqlBackend {
    fn migrate(
        &self,
        _features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        Box::pin(async move {
            run_libsql_migrations(&self.pool)
                .await
                .map_err(RepoError::Internal)
        })
    }

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

/// Collect all table definitions based on compile-time feature flags.
fn collect_feature_gated_schemas() -> Vec<Vec<crate::schema::TableDef>> {
    let mut lists = vec![crate::schema::core_schema()];

    #[cfg(feature = "email-password")]
    lists.push(crate::schema::plugin_schemas::email_password_schema());
    #[cfg(feature = "passkey")]
    lists.push(crate::schema::plugin_schemas::passkey_schema());
    #[cfg(feature = "mfa")]
    lists.push(crate::schema::plugin_schemas::mfa_schema());
    #[cfg(feature = "oauth")]
    lists.push(crate::schema::plugin_schemas::oauth_schema());
    #[cfg(feature = "bearer")]
    lists.push(crate::schema::plugin_schemas::bearer_schema());
    #[cfg(feature = "api-key")]
    lists.push(crate::schema::plugin_schemas::api_key_schema());
    #[cfg(feature = "magic-link")]
    lists.push(crate::schema::plugin_schemas::magic_link_schema());
    #[cfg(feature = "oauth2-server")]
    lists.push(crate::schema::plugin_schemas::oauth2_server_schema());
    #[cfg(feature = "account-lockout")]
    lists.push(crate::schema::plugin_schemas::account_lockout_schema());
    #[cfg(feature = "webhooks")]
    lists.push(crate::schema::plugin_schemas::webhooks_schema());
    #[cfg(feature = "oidc")]
    lists.push(crate::schema::plugin_schemas::oidc_schema());

    lists
}

/// Run declarative migrations using the SQLite DDL generator.
///
/// 1. Collects core + plugin schemas based on compile-time feature flags
/// 2. Generates SQLite DDL
/// 3. Checks if schema hash has changed (via yauth_schema_migrations table)
/// 4. Runs CREATE TABLE IF NOT EXISTS for all tables
/// 5. Records the schema hash in the tracking table
async fn run_libsql_migrations(
    pool: &LibsqlPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::{RunQueryDsl, SimpleAsyncConnection};

    let table_lists = collect_feature_gated_schemas();
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

    // Create tracking table (SQLite-compatible)
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

    // Check if hash is already applied using raw SQL
    use diesel::QueryableByName;
    use diesel::sql_types::Integer;

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = Integer)]
        count: i32,
    }

    let query = diesel::sql_query(
        "SELECT CAST(COUNT(*) AS INTEGER) AS count FROM yauth_schema_migrations WHERE schema_hash = ?"
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
