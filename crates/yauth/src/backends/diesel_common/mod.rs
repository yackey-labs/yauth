//! Shared helpers for Diesel-based backends (Postgres and libSQL).
//!
//! Provides `PoolAccess` trait + `get_conn`, `diesel_err`, and `diesel_conflict`
//! to eliminate per-method boilerplate in every repository implementation.

use std::future::Future;
use std::pin::Pin;

use crate::repo::RepoError;

/// Abstraction over connection pool types so helpers work with both
/// `deadpool::Pool<AsyncPgConnection>` (Postgres) and `diesel_libsql::deadpool::Pool`.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) trait PoolAccess: Send + Sync {
    type Conn: Send;

    fn get_conn(&self) -> Pin<Box<dyn Future<Output = Result<Self::Conn, BoxError>> + Send + '_>>;
}

// ── Postgres pool impl ──

#[cfg(feature = "diesel-pg-backend")]
impl PoolAccess
    for diesel_async_crate::pooled_connection::deadpool::Pool<diesel_async_crate::AsyncPgConnection>
{
    type Conn = diesel_async_crate::pooled_connection::deadpool::Object<
        diesel_async_crate::AsyncPgConnection,
    >;

    fn get_conn(&self) -> Pin<Box<dyn Future<Output = Result<Self::Conn, BoxError>> + Send + '_>> {
        Box::pin(async move { self.get().await.map_err(|e| Box::new(e) as _) })
    }
}

// ── MySQL pool impl ──

#[cfg(feature = "diesel-mysql-backend")]
impl PoolAccess
    for diesel_async_crate::pooled_connection::deadpool::Pool<
        diesel_async_crate::AsyncMysqlConnection,
    >
{
    type Conn = diesel_async_crate::pooled_connection::deadpool::Object<
        diesel_async_crate::AsyncMysqlConnection,
    >;

    fn get_conn(&self) -> Pin<Box<dyn Future<Output = Result<Self::Conn, BoxError>> + Send + '_>> {
        Box::pin(async move { self.get().await.map_err(|e| Box::new(e) as _) })
    }
}

// ── libSQL pool impl ──

#[cfg(feature = "diesel-libsql-backend")]
impl PoolAccess for diesel_libsql::deadpool::Pool {
    type Conn = diesel_libsql::deadpool::Object;

    fn get_conn(&self) -> Pin<Box<dyn Future<Output = Result<Self::Conn, BoxError>> + Send + '_>> {
        Box::pin(async move {
            self.get()
                .await
                .map_err(|e| -> BoxError { format!("pool error: {e}").into() })
        })
    }
}

// ── Helper functions ──

/// Get a connection from any pool type, mapping the error to `RepoError`.
pub(crate) async fn get_conn<P: PoolAccess>(pool: &P) -> Result<P::Conn, RepoError> {
    pool.get_conn().await.map_err(RepoError::Internal)
}

/// Run a DDL statement once via `OnceCell`, recording initialization.
///
/// Shared by MySQL and libSQL backends for lazy-init of rate_limit,
/// revocation, and challenge tables.
///
/// The caller provides a future-returning closure that gets a connection from
/// the pool and runs the DDL. This avoids trait-object issues with different
/// connection types.
#[cfg(any(feature = "diesel-mysql-backend", feature = "diesel-libsql-backend"))]
pub(crate) async fn lazy_init_table<F, Fut>(
    cell: &tokio::sync::OnceCell<()>,
    init_fn: F,
) -> Result<(), RepoError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), RepoError>>,
{
    cell.get_or_try_init(|| async { init_fn().await })
        .await
        .map(|_| ())
}

/// Map a Diesel error to `RepoError::Internal`.
pub(crate) fn diesel_err(e: diesel::result::Error) -> RepoError {
    RepoError::Internal(e.into())
}

/// Shared conflict-detection logic: map a Diesel `UniqueViolation` to
/// `RepoError::Conflict`, optionally checking a fallback string pattern for
/// backends that sometimes surface constraint errors via generic error messages.
fn diesel_conflict_inner(e: diesel::result::Error, fallback_pattern: Option<&str>) -> RepoError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    match e {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            RepoError::Conflict(info.message().to_string())
        }
        other => {
            if let Some(pattern) = fallback_pattern {
                let msg = other.to_string();
                if msg.contains(pattern) {
                    return RepoError::Conflict(msg);
                }
            }
            RepoError::Internal(other.into())
        }
    }
}

/// Map a Diesel unique-violation error to `RepoError::Conflict`, falling back
/// to `RepoError::Internal` for all other errors.
#[cfg(feature = "diesel-pg-backend")]
pub(crate) fn diesel_conflict(e: diesel::result::Error) -> RepoError {
    diesel_conflict_inner(e, None)
}

/// Compute a `RateLimitResult` from a count, limit, window start, and window duration.
///
/// Shared by the Postgres and libSQL rate-limit repo implementations.
pub(crate) fn rate_limit_result(
    count: u32,
    limit: u32,
    window_start: chrono::DateTime<chrono::Utc>,
    window_secs: u64,
) -> crate::domain::RateLimitResult {
    if count >= limit {
        let window_end = window_start + chrono::Duration::seconds(window_secs as i64);
        let now = chrono::Utc::now();
        let retry_after = (window_end - now).num_seconds().max(0) as u64;
        crate::domain::RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after,
        }
    } else {
        crate::domain::RateLimitResult {
            allowed: true,
            remaining: limit - count,
            retry_after: 0,
        }
    }
}

// ── UUID / JSON string converters ──
// Shared by libSQL and MySQL backends where UUIDs and JSON are stored as TEXT.

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn uuid_to_str(u: uuid::Uuid) -> String {
    u.to_string()
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn str_to_uuid(s: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(s).unwrap_or_else(|e| {
        log::error!("Failed to parse UUID from stored value '{}': {}", s, e);
        uuid::Uuid::nil()
    })
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn opt_uuid_to_str(u: Option<uuid::Uuid>) -> Option<String> {
    u.map(uuid_to_str)
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn opt_str_to_uuid(s: Option<String>) -> Option<uuid::Uuid> {
    s.map(|s| str_to_uuid(&s))
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn json_to_str(v: serde_json::Value) -> String {
    serde_json::to_string(&v).unwrap_or_else(|_| "null".to_string())
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn str_to_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn opt_json_to_str(v: Option<serde_json::Value>) -> Option<String> {
    v.map(json_to_str)
}

#[cfg(any(feature = "diesel-libsql-backend", feature = "diesel-mysql-backend"))]
pub(crate) fn opt_str_to_json(s: Option<String>) -> Option<serde_json::Value> {
    s.map(|s| str_to_json(&s))
}

/// Map a Diesel unique-violation error OR a MySQL "Duplicate entry" string match
/// to `RepoError::Conflict`. MySQL returns `DatabaseError(UniqueViolation, _)` for
/// most cases, but we also handle the string pattern as a fallback.
#[cfg(feature = "diesel-mysql-backend")]
pub(crate) fn diesel_conflict_mysql(e: diesel::result::Error) -> RepoError {
    diesel_conflict_inner(e, Some("Duplicate entry"))
}

/// Map a Diesel unique-violation error OR a SQLite "UNIQUE constraint failed"
/// string match to `RepoError::Conflict`. Used by the libSQL backend where
/// diesel-libsql sometimes returns a generic error with the constraint message
/// embedded in the string representation.
#[cfg(feature = "diesel-libsql-backend")]
pub(crate) fn diesel_conflict_sqlite(e: diesel::result::Error) -> RepoError {
    diesel_conflict_inner(e, Some("UNIQUE constraint failed"))
}
