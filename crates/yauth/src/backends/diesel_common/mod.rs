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

/// Map a Diesel error to `RepoError::Internal`.
pub(crate) fn diesel_err(e: diesel::result::Error) -> RepoError {
    RepoError::Internal(e.into())
}

/// Map a Diesel unique-violation error to `RepoError::Conflict`, falling back
/// to `RepoError::Internal` for all other errors.
pub(crate) fn diesel_conflict(e: diesel::result::Error) -> RepoError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    match e {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            RepoError::Conflict(info.message().to_string())
        }
        other => RepoError::Internal(other.into()),
    }
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

/// Map a Diesel unique-violation error OR a SQLite "UNIQUE constraint failed"
/// string match to `RepoError::Conflict`. Used by the libSQL backend where
/// diesel-libsql sometimes returns a generic error with the constraint message
/// embedded in the string representation.
#[cfg(feature = "diesel-libsql-backend")]
pub(crate) fn diesel_conflict_sqlite(e: diesel::result::Error) -> RepoError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    match e {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            RepoError::Conflict(info.message().to_string())
        }
        other => {
            let msg = other.to_string();
            if msg.contains("UNIQUE constraint failed") {
                RepoError::Conflict(msg)
            } else {
                RepoError::Internal(other.into())
            }
        }
    }
}
