use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands;

use crate::repo::{RepoFuture, RevocationRepository, sealed};

/// Redis caching decorator for [`RevocationRepository`].
///
/// Writes go to the inner (database) repo first, then cache in Redis.
/// Reads try Redis first and fall back to the inner repo on miss or error.
///
/// ## Redis key layout
///
/// | Key | Type | TTL |
/// |-----|------|-----|
/// | `{prefix}:revoked:{jti}` | String (`"1"`) | revocation TTL |
pub struct RedisCachedRevocations {
    inner: Arc<dyn RevocationRepository>,
    redis: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisCachedRevocations {
    pub fn new(
        inner: Arc<dyn RevocationRepository>,
        redis: redis::aio::ConnectionManager,
        prefix: String,
    ) -> Self {
        Self {
            inner,
            redis,
            prefix,
        }
    }

    fn revoked_key(&self, jti: &str) -> String {
        format!("{}:revoked:{}", self.prefix, jti)
    }
}

impl sealed::Sealed for RedisCachedRevocations {}

impl RevocationRepository for RedisCachedRevocations {
    fn revoke_token(&self, jti: &str, ttl: Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            // Database first — source of truth
            self.inner.revoke_token(&jti, ttl).await?;

            // Best-effort cache in Redis
            let mut conn = self.redis.clone();
            let r: Result<(), redis::RedisError> = conn
                .set_ex(self.revoked_key(&jti), "1", ttl.as_secs())
                .await;
            if let Err(e) = r {
                log::warn!("Redis cache write failed for revoke_token: {e}");
            }

            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            // Try Redis first
            let mut conn = self.redis.clone();
            let cache_result: Result<bool, redis::RedisError> =
                conn.exists(self.revoked_key(&jti)).await;

            match cache_result {
                Ok(true) => return Ok(true),
                Ok(false) => {
                    // Cache miss — fall through to inner
                }
                Err(e) => {
                    log::warn!("Redis cache read failed for is_token_revoked: {e}");
                }
            }

            // Fall back to inner (database)
            let revoked = self.inner.is_token_revoked(&jti).await?;

            // Backfill cache if revoked (best-effort)
            // We don't know the original TTL, so use a reasonable default (1 hour)
            if revoked {
                let mut conn = self.redis.clone();
                let r: Result<(), redis::RedisError> =
                    conn.set_ex(self.revoked_key(&jti), "1", 3600).await;
                if let Err(e) = r {
                    log::warn!("Redis cache backfill failed for is_token_revoked: {e}");
                }
            }

            Ok(revoked)
        })
    }
}
