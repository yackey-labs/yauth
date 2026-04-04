use super::{RepoFuture, sealed};

/// Repository for JTI revocation (bearer token invalidation).
///
/// Replaces the old `RevocationStore` trait from the stores module.
pub trait RevocationRepository: sealed::Sealed + Send + Sync {
    /// Revoke a JTI. The entry auto-expires after `ttl`.
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()>;

    /// Check if a JTI has been revoked.
    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool>;
}
