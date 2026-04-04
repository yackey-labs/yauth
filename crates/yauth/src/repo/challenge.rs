use super::{RepoFuture, sealed};

/// Repository for ephemeral challenge storage (CSRF, WebAuthn, MFA pending sessions).
///
/// Replaces the old `ChallengeStore` trait from the stores module.
/// Key-value store with TTL-based expiration.
pub trait ChallengeRepository: sealed::Sealed + Send + Sync {
    /// Set a challenge value with a TTL in seconds.
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()>;

    /// Get a challenge value. Returns None if not found or expired.
    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>>;

    /// Delete a challenge by key.
    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()>;
}
