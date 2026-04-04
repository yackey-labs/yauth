use std::sync::Arc;

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

/// Lua script for atomic INCR + conditional EXPIRE.
///
/// Guarantees that the first INCR on a new key also sets the TTL in the same
/// atomic operation — no race window where a crash between INCR and EXPIRE
/// could leave the key without a TTL (permanently rate-limiting that key).
const RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"#;

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

            let script = redis::Script::new(RATE_LIMIT_SCRIPT);
            let result: Result<(i64, i64), redis::RedisError> = script
                .key(&rate_key)
                .arg(window_secs as i64)
                .invoke_async(&mut conn)
                .await;

            match result {
                Ok((count, ttl)) => {
                    if count as u32 >= limit {
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
