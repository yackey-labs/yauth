//! Redis caching decorators for repository traits.
//!
//! Each decorator wraps an `Arc<dyn XxxRepository>` (the "inner" — typically
//! backed by a database) and adds a Redis read-cache in front.  The database
//! is **always** the source of truth; Redis is best-effort.  Any Redis error
//! is logged with `log::warn!` and the operation falls back to the inner repo.

mod cached_challenges;
mod cached_rate_limits;
mod cached_revocations;
mod cached_sessions;

pub use cached_challenges::RedisCachedChallenges;
pub use cached_rate_limits::RedisCachedRateLimits;
pub use cached_revocations::RedisCachedRevocations;
pub use cached_sessions::RedisCachedSessionOps;
