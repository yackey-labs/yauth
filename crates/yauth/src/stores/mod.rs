pub mod memory;
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub enum StoreBackend {
    Memory,
    Postgres,
    #[cfg(feature = "redis")]
    Redis(Box<::redis::aio::ConnectionManager>),
}

impl std::fmt::Debug for StoreBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "Memory"),
            Self::Postgres => write!(f, "Postgres"),
            #[cfg(feature = "redis")]
            Self::Redis(_) => write!(f, "Redis"),
        }
    }
}

// ---------------------------------------------------------------------------
// Rate Limiting
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> RateLimitResult;
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

#[async_trait::async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn set(&self, key: &str, value: serde_json::Value, ttl_secs: u64) -> Result<(), String>;
    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
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

#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a new session. Returns the session UUID.
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> Result<Uuid, String>;

    /// Look up a session by token hash. Returns None if not found or expired.
    async fn validate(&self, token_hash: &str) -> Result<Option<StoredSession>, String>;

    /// Delete a session by token hash. Returns true if a session was deleted.
    async fn delete(&self, token_hash: &str) -> Result<bool, String>;

    /// Delete all sessions for a user. Returns count deleted.
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64, String>;

    /// Delete all sessions for a user except the one matching `keep_hash`.
    async fn delete_others_for_user(&self, user_id: Uuid, keep_hash: &str) -> Result<u64, String>;
}

// ---------------------------------------------------------------------------
// JTI Revocation (for bearer token invalidation)
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait RevocationStore: Send + Sync {
    /// Revoke a JTI. The entry auto-expires after `ttl`.
    async fn revoke(&self, jti: &str, ttl: std::time::Duration) -> Result<(), String>;

    /// Check if a JTI has been revoked.
    async fn is_revoked(&self, jti: &str) -> Result<bool, String>;
}
