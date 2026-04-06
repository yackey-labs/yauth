use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands;
use uuid::Uuid;

use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};

/// Redis caching decorator for [`SessionOpsRepository`].
///
/// Wraps an inner (database-backed) implementation.  Writes always go to the
/// inner repo first; Redis is updated best-effort afterwards.  Reads try Redis
/// first and fall back to the inner repo on miss or error.
///
/// ## Redis key layout
///
/// | Key | Type | TTL |
/// |-----|------|-----|
/// | `{prefix}:session:{token_hash}` | String (JSON) | session TTL |
/// | `{prefix}:user_sessions:{user_id}` | Set of token hashes | none (cleaned on delete-all) |
pub struct RedisCachedSessionOps {
    inner: Arc<dyn SessionOpsRepository>,
    redis: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisCachedSessionOps {
    pub fn new(
        inner: Arc<dyn SessionOpsRepository>,
        redis: redis::aio::ConnectionManager,
        prefix: String,
    ) -> Self {
        Self {
            inner,
            redis,
            prefix,
        }
    }

    fn session_key(&self, token_hash: &str) -> String {
        format!("{}:session:{}", self.prefix, token_hash)
    }

    fn user_sessions_key(&self, user_id: Uuid) -> String {
        format!("{}:user_sessions:{}", self.prefix, user_id)
    }
}

impl sealed::Sealed for RedisCachedSessionOps {}

impl SessionOpsRepository for RedisCachedSessionOps {
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: Duration,
    ) -> RepoFuture<'_, Uuid> {
        Box::pin(async move {
            // Database first — source of truth
            let id = self
                .inner
                .create_session(
                    user_id,
                    token_hash.clone(),
                    ip_address.clone(),
                    user_agent.clone(),
                    ttl,
                )
                .await?;

            // Best-effort cache in Redis
            let now = chrono::Utc::now().naive_utc();
            let expires_at = now
                + chrono::Duration::from_std(ttl)
                    .unwrap_or_else(|_| chrono::Duration::seconds(ttl.as_secs() as i64));
            let session = domain::StoredSession {
                id,
                user_id,
                ip_address,
                user_agent,
                expires_at,
                created_at: now,
            };

            if let Ok(json) = serde_json::to_string(&session) {
                let ttl_secs = ttl.as_secs() as i64;
                let session_key = self.session_key(&token_hash);
                let user_sessions_key = self.user_sessions_key(user_id);

                let mut conn = self.redis.clone();
                let result: Result<(), redis::RedisError> = redis::pipe()
                    .atomic()
                    .cmd("SETEX")
                    .arg(&session_key)
                    .arg(ttl_secs)
                    .arg(&json)
                    .cmd("SADD")
                    .arg(&user_sessions_key)
                    .arg(&token_hash)
                    .query_async(&mut conn)
                    .await;

                if let Err(e) = result {
                    log::warn!("Redis cache write failed for session create: {e}");
                }
            }

            Ok(id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            // Try Redis first
            let mut conn = self.redis.clone();
            let cache_result: Result<Option<String>, redis::RedisError> =
                conn.get(self.session_key(&token_hash)).await;

            match cache_result {
                Ok(Some(json)) => {
                    if let Ok(session) = serde_json::from_str::<domain::StoredSession>(&json) {
                        let now = chrono::Utc::now().naive_utc();
                        if session.expires_at > now {
                            return Ok(Some(session));
                        }
                        // Expired in Redis — clean up best-effort
                        let _: Result<(), redis::RedisError> =
                            conn.del(self.session_key(&token_hash)).await;
                    }
                }
                Ok(None) => {
                    // Cache miss — fall through to inner
                }
                Err(e) => {
                    log::warn!("Redis cache read failed for session validate: {e}");
                }
            }

            // Fall back to inner (database)
            let result = self.inner.validate_session(&token_hash).await?;

            // Cache the result on miss (best-effort, background)
            if let Some(ref session) = result
                && let Ok(json) = serde_json::to_string(session)
            {
                let now = chrono::Utc::now().naive_utc();
                let remaining_secs = (session.expires_at - now).num_seconds().max(1) as u64;
                let session_key = self.session_key(&token_hash);
                let mut conn = self.redis.clone();
                tokio::spawn(async move {
                    let r: Result<(), redis::RedisError> =
                        conn.set_ex(session_key, json, remaining_secs).await;
                    if let Err(e) = r {
                        log::warn!("Redis cache backfill failed for session validate: {e}");
                    }
                });
            }

            Ok(result)
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            // Try to get session info from Redis for user_sessions cleanup
            let mut conn = self.redis.clone();
            let session_key = self.session_key(&token_hash);
            let cached: Result<Option<String>, redis::RedisError> = conn.get(&session_key).await;

            // Delete from inner (database) first
            let deleted = self.inner.delete_session(&token_hash).await?;

            // Clean up Redis best-effort
            if let Ok(Some(json)) = cached
                && let Ok(session) = serde_json::from_str::<domain::StoredSession>(&json)
            {
                let user_sessions_key = self.user_sessions_key(session.user_id);
                let r: Result<(), redis::RedisError> = redis::pipe()
                    .atomic()
                    .del(&session_key)
                    .cmd("SREM")
                    .arg(&user_sessions_key)
                    .arg(&token_hash)
                    .query_async(&mut conn)
                    .await;
                if let Err(e) = r {
                    log::warn!("Redis cache cleanup failed for session delete: {e}");
                }
                return Ok(deleted);
            }
            // Couldn't get session info — just delete the key
            let r: Result<(), redis::RedisError> = conn.del(&session_key).await;
            if let Err(e) = r {
                log::warn!("Redis cache cleanup failed for session delete: {e}");
            }

            Ok(deleted)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            // Delete from inner (database) first
            let count = self.inner.delete_all_sessions_for_user(user_id).await?;

            // Invalidate Redis — delete all session keys in the user set
            let mut conn = self.redis.clone();
            let user_sessions_key = self.user_sessions_key(user_id);
            let hashes: Result<Vec<String>, redis::RedisError> =
                conn.smembers(&user_sessions_key).await;

            match hashes {
                Ok(hashes) if !hashes.is_empty() => {
                    let mut pipe = redis::pipe();
                    pipe.atomic();
                    for hash in &hashes {
                        pipe.del(self.session_key(hash));
                    }
                    pipe.del(&user_sessions_key);
                    let r: Result<(), redis::RedisError> = pipe.query_async(&mut conn).await;
                    if let Err(e) = r {
                        log::warn!(
                            "Redis cache cleanup failed for delete_all_sessions_for_user: {e}"
                        );
                    }
                }
                Ok(_) => {
                    // No cached hashes — just delete the set key
                    let _: Result<(), redis::RedisError> = conn.del(&user_sessions_key).await;
                }
                Err(e) => {
                    log::warn!("Redis cache cleanup failed for delete_all_sessions_for_user: {e}");
                }
            }

            Ok(count)
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            // Delete from inner (database) first
            let count = self
                .inner
                .delete_other_sessions_for_user(user_id, &keep_hash)
                .await?;

            // Invalidate Redis — delete all session keys except the kept one
            let mut conn = self.redis.clone();
            let user_sessions_key = self.user_sessions_key(user_id);
            let hashes: Result<Vec<String>, redis::RedisError> =
                conn.smembers(&user_sessions_key).await;

            match hashes {
                Ok(hashes) => {
                    let to_remove: Vec<&String> =
                        hashes.iter().filter(|h| h.as_str() != keep_hash).collect();
                    if !to_remove.is_empty() {
                        let mut pipe = redis::pipe();
                        pipe.atomic();
                        for hash in &to_remove {
                            pipe.del(self.session_key(hash));
                            pipe.cmd("SREM").arg(&user_sessions_key).arg(hash.as_str());
                        }
                        let r: Result<(), redis::RedisError> = pipe.query_async(&mut conn).await;
                        if let Err(e) = r {
                            log::warn!(
                                "Redis cache cleanup failed for delete_other_sessions_for_user: {e}"
                            );
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Redis cache cleanup failed for delete_other_sessions_for_user: {e}"
                    );
                }
            }

            Ok(count)
        })
    }
}
