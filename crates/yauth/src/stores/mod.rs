pub mod memory;
#[cfg(feature = "diesel-backend")]
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;

use std::future::Future;
use std::pin::Pin;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub enum StoreBackend {
    Memory,
    #[cfg(feature = "diesel-backend")]
    Postgres,
    #[cfg(feature = "redis")]
    Redis(Box<::redis::aio::ConnectionManager>, String),
}

impl std::fmt::Debug for StoreBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "Memory"),
            #[cfg(feature = "diesel-backend")]
            Self::Postgres => write!(f, "Postgres"),
            #[cfg(feature = "redis")]
            Self::Redis(_, prefix) => write!(f, "Redis(prefix={prefix})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Rate Limiting
// ---------------------------------------------------------------------------

pub trait RateLimitStore: Send + Sync {
    fn check(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Pin<Box<dyn Future<Output = RateLimitResult> + Send + '_>>;
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after: u64,
}

// ---------------------------------------------------------------------------
// Challenge (CSRF, WebAuthn)
// ---------------------------------------------------------------------------

pub trait ChallengeStore: Send + Sync {
    fn set(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, String>> + Send + '_>>;
    fn delete(&self, key: &str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// A session record as stored by the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

pub trait SessionStore: Send + Sync {
    /// Store a new session. Returns the session UUID.
    fn create(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Uuid, String>> + Send + '_>>;

    /// Look up a session by token hash. Returns None if not found or expired.
    fn validate(
        &self,
        token_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StoredSession>, String>> + Send + '_>>;

    /// Delete a session by token hash. Returns true if a session was deleted.
    fn delete(
        &self,
        token_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>>;

    /// Delete all sessions for a user. Returns count deleted.
    fn delete_all_for_user(
        &self,
        user_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>>;

    /// Delete all sessions for a user except the one matching `keep_hash`.
    fn delete_others_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// JTI Revocation (for bearer token invalidation)
// ---------------------------------------------------------------------------

pub trait RevocationStore: Send + Sync {
    /// Revoke a JTI. The entry auto-expires after `ttl`.
    fn revoke(
        &self,
        jti: &str,
        ttl: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;

    /// Check if a JTI has been revoked.
    fn is_revoked(
        &self,
        jti: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>>;
}
