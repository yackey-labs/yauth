use super::{RepoFuture, sealed};
use crate::domain;

/// Repository for rate limiting.
///
/// Replaces the old `RateLimitStore` trait from the stores module.
/// Implementations must be fail-open: on error, return `allowed: true`.
pub trait RateLimitRepository: sealed::Sealed + Send + Sync {
    /// Check if a request is within the rate limit for the given key.
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult>;
}
