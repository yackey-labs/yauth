use std::sync::Arc;

use redis::AsyncCommands;

use crate::domain;
use crate::repo::{RateLimitRepository, RepoFuture, sealed};

/// Redis caching decorator for [`RateLimitRepository`].
///
/// Uses the Redis `INCR` + `EXPIRE` pattern for fast, atomic rate limiting.
/// If Redis is unavailable, falls back to the inner (database) repo —
/// preserving the fail-open contract.
///
/// ## Redis key layout
///
/// | Key | Type | TTL |
/// |-----|------|-----|
/// | `{prefix}:rate:{key}` | String (counter) | `window_secs` |
pub struct RedisCachedRateLimits {
    inner: Arc<dyn RateLimitRepository>,
    redis: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisCachedRateLimits {
    pub fn new(
        inner: Arc<dyn RateLimitRepository>,
        redis: redis::aio::ConnectionManager,
        prefix: String,
    ) -> Self {
        Self {
            inner,
            redis,
            prefix,
        }
    }

    fn rate_key(&self, key: &str) -> String {
        format!("{}:rate:{}", self.prefix, key)
    }
}

impl sealed::Sealed for RedisCachedRateLimits {}

impl RateLimitRepository for RedisCachedRateLimits {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            let mut conn = self.redis.clone();
            let rate_key = self.rate_key(&key);

            // INCR the key; if it's new (returns 1), set the expiry
            let count: Result<i64, redis::RedisError> = conn.incr(&rate_key, 1i64).await;

            match count {
                Ok(count) => {
                    if count == 1 {
                        // New key — set the window expiry
                        let _: Result<(), redis::RedisError> =
                            conn.expire(&rate_key, window_secs as i64).await;
                    }

                    if count as u32 > limit {
                        // Over limit — get TTL for retry_after
                        let ttl: i64 = conn.ttl(&rate_key).await.unwrap_or(window_secs as i64);
                        Ok(domain::RateLimitResult {
                            allowed: false,
                            remaining: 0,
                            retry_after: ttl.max(0) as u64,
                        })
                    } else {
                        Ok(domain::RateLimitResult {
                            allowed: true,
                            remaining: limit - count as u32,
                            retry_after: 0,
                        })
                    }
                }
                Err(e) => {
                    // Redis unavailable — fall back to inner (fail-open on Redis errors)
                    log::warn!("Redis rate limit check failed, falling back to inner: {e}");
                    self.inner.check_rate_limit(&key, limit, window_secs).await
                }
            }
        })
    }
}
