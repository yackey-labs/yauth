use std::sync::Arc;

use redis::AsyncCommands;

use crate::repo::{ChallengeRepository, RepoFuture, sealed};

/// Redis caching decorator for [`ChallengeRepository`].
///
/// Writes go to the inner (database) repo first, then cache in Redis
/// with the same TTL.  Reads try Redis first, falling back to the inner
/// repo on miss or error.
///
/// ## Redis key layout
///
/// | Key | Type | TTL |
/// |-----|------|-----|
/// | `{prefix}:challenge:{key}` | String (JSON) | from `set_challenge` call |
pub struct RedisCachedChallenges {
    inner: Arc<dyn ChallengeRepository>,
    redis: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisCachedChallenges {
    pub fn new(
        inner: Arc<dyn ChallengeRepository>,
        redis: redis::aio::ConnectionManager,
        prefix: String,
    ) -> Self {
        Self {
            inner,
            redis,
            prefix,
        }
    }

    fn challenge_key(&self, key: &str) -> String {
        format!("{}:challenge:{}", self.prefix, key)
    }
}

impl sealed::Sealed for RedisCachedChallenges {}

impl ChallengeRepository for RedisCachedChallenges {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            // Database first — source of truth
            self.inner
                .set_challenge(&key, value.clone(), ttl_secs)
                .await?;

            // Best-effort cache in Redis
            if let Ok(json) = serde_json::to_string(&value) {
                let mut conn = self.redis.clone();
                let r: Result<(), redis::RedisError> =
                    conn.set_ex(self.challenge_key(&key), json, ttl_secs).await;
                if let Err(e) = r {
                    log::warn!("Redis cache write failed for set_challenge: {e}");
                }
            }

            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            // Try Redis first
            let mut conn = self.redis.clone();
            let cache_result: Result<Option<String>, redis::RedisError> =
                conn.get(self.challenge_key(&key)).await;

            match cache_result {
                Ok(Some(json)) => {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
                        return Ok(Some(value));
                    }
                    // Corrupt cache entry — fall through to inner
                }
                Ok(None) => {
                    // Cache miss — fall through to inner
                }
                Err(e) => {
                    log::warn!("Redis cache read failed for get_challenge: {e}");
                }
            }

            // Fall back to inner (database)
            let result = self.inner.get_challenge(&key).await?;

            // Backfill cache on miss (best-effort, use a reasonable TTL)
            // We don't know the original TTL here, so we skip backfill.
            // The next set_challenge will populate Redis.

            Ok(result)
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            // Delete from inner (database) first
            self.inner.delete_challenge(&key).await?;

            // Best-effort delete from Redis
            let mut conn = self.redis.clone();
            let r: Result<(), redis::RedisError> = conn.del(self.challenge_key(&key)).await;
            if let Err(e) = r {
                log::warn!("Redis cache cleanup failed for delete_challenge: {e}");
            }

            Ok(())
        })
    }
}
