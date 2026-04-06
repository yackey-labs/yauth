//! Shared helpers for sqlx-based backends.
//!
//! Provides error mapping, UUID/JSON conversion, and rate limit helpers
//! analogous to `diesel_common` but for sqlx.

use crate::repo::RepoError;

/// Map a sqlx error to `RepoError::Internal`.
pub(crate) fn sqlx_err(e: sqlx::Error) -> RepoError {
    RepoError::Internal(e.into())
}

/// Detect unique constraint violations and map to `RepoError::Conflict`.
/// Falls back to `RepoError::Internal` for other errors.
pub(crate) fn sqlx_conflict(e: sqlx::Error) -> RepoError {
    match &e {
        sqlx::Error::Database(db_err) => {
            // Postgres: 23505, MySQL: 1062, SQLite: "UNIQUE constraint failed"
            if let Some(code) = db_err.code()
                && (code == "23505" || code == "1062")
            {
                return RepoError::Conflict(db_err.message().to_string());
            }
            let msg = db_err.message();
            if msg.contains("UNIQUE constraint failed")
                || msg.contains("Duplicate entry")
                || msg.contains("unique constraint")
            {
                return RepoError::Conflict(msg.to_string());
            }
            RepoError::Internal(e.into())
        }
        _ => RepoError::Internal(e.into()),
    }
}

/// Compute a `RateLimitResult` from a count, limit, window start, and window duration.
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
// Used by MySQL and SQLite sqlx backends where UUIDs and JSON are stored as TEXT/CHAR(36).
// Currently unused — these will be needed when sqlx_mysql/sqlx_sqlite repos do inline
// UUID↔String and JSON↔String conversion instead of relying on sqlx's native mapping.

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn uuid_to_str(u: uuid::Uuid) -> String {
    u.to_string()
}

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn str_to_uuid(s: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(s).unwrap_or_else(|e| {
        log::error!("Failed to parse UUID from stored value '{}': {}", s, e);
        uuid::Uuid::nil()
    })
}

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn opt_str_to_uuid(s: Option<String>) -> Option<uuid::Uuid> {
    s.map(|s| str_to_uuid(&s))
}

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn json_to_str(v: serde_json::Value) -> String {
    serde_json::to_string(&v).unwrap_or_else(|_| "null".to_string())
}

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn str_to_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
}

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn opt_json_to_str(v: Option<serde_json::Value>) -> Option<String> {
    v.map(json_to_str)
}

#[cfg(any(feature = "sqlx-mysql-backend", feature = "sqlx-sqlite-backend"))]
#[allow(dead_code)]
pub(crate) fn opt_str_to_json(s: Option<String>) -> Option<serde_json::Value> {
    s.map(|s| str_to_json(&s))
}
