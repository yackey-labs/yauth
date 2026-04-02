use std::time::Duration;

use redis::AsyncCommands;
use uuid::Uuid;

use super::{
    ChallengeStore, RateLimitResult, RateLimitStore, RevocationStore, SessionStore, StoredSession,
};

// ---------------------------------------------------------------------------
// RedisSessionStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RedisSessionStore {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisSessionStore {
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            prefix: "yauth".into(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn session_key(&self, token_hash: &str) -> String {
        format!("{}:session:{}", self.prefix, token_hash)
    }

    fn user_sessions_key(&self, user_id: Uuid) -> String {
        format!("{}:user_sessions:{}", self.prefix, user_id)
    }
}

#[async_trait::async_trait]
impl SessionStore for RedisSessionStore {
    async fn create(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: Duration,
    ) -> Result<Uuid, String> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().naive_utc();
        let expires_at = now + chrono::Duration::from_std(ttl).map_err(|e| e.to_string())?;

        let session = StoredSession {
            id,
            user_id,
            ip_address,
            user_agent,
            expires_at,
            created_at: now,
        };

        let json = serde_json::to_string(&session).map_err(|e| e.to_string())?;
        let ttl_secs = ttl.as_secs() as i64;
        let session_key = self.session_key(&token_hash);
        let user_sessions_key = self.user_sessions_key(user_id);

        let mut conn = self.conn.clone();
        redis::pipe()
            .atomic()
            .cmd("SETEX")
            .arg(&session_key)
            .arg(ttl_secs)
            .arg(&json)
            .cmd("SADD")
            .arg(&user_sessions_key)
            .arg(&token_hash)
            .exec_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(id)
    }

    async fn validate(&self, token_hash: &str) -> Result<Option<StoredSession>, String> {
        let mut conn = self.conn.clone();
        let result: Option<String> = conn
            .get(self.session_key(token_hash))
            .await
            .map_err(|e| e.to_string())?;

        match result {
            Some(json) => {
                let session: StoredSession =
                    serde_json::from_str(&json).map_err(|e| e.to_string())?;
                let now = chrono::Utc::now().naive_utc();
                if session.expires_at > now {
                    Ok(Some(session))
                } else {
                    // Expired but Redis hasn't cleaned it up yet — remove it
                    let _: () = conn
                        .del(self.session_key(token_hash))
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, token_hash: &str) -> Result<bool, String> {
        let mut conn = self.conn.clone();
        let session_key = self.session_key(token_hash);

        // Get the session first so we can remove from the user_sessions set
        let result: Option<String> = conn.get(&session_key).await.map_err(|e| e.to_string())?;

        if let Some(json) = result {
            if let Ok(session) = serde_json::from_str::<StoredSession>(&json) {
                let user_sessions_key = self.user_sessions_key(session.user_id);
                redis::pipe()
                    .atomic()
                    .del(&session_key)
                    .cmd("SREM")
                    .arg(&user_sessions_key)
                    .arg(token_hash)
                    .exec_async(&mut conn)
                    .await
                    .map_err(|e| e.to_string())?;
                return Ok(true);
            }
            // Couldn't parse but key exists — just delete it
            let deleted: i64 = conn.del(&session_key).await.map_err(|e| e.to_string())?;
            return Ok(deleted > 0);
        }

        Ok(false)
    }

    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64, String> {
        let mut conn = self.conn.clone();
        let user_sessions_key = self.user_sessions_key(user_id);

        let hashes: Vec<String> = conn
            .smembers(&user_sessions_key)
            .await
            .map_err(|e| e.to_string())?;

        if hashes.is_empty() {
            return Ok(0);
        }

        let count = hashes.len() as u64;
        let mut pipe = redis::pipe();
        pipe.atomic();
        for hash in &hashes {
            pipe.del(self.session_key(hash));
        }
        pipe.del(&user_sessions_key);
        pipe.exec_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(count)
    }

    async fn delete_others_for_user(&self, user_id: Uuid, keep_hash: &str) -> Result<u64, String> {
        let mut conn = self.conn.clone();
        let user_sessions_key = self.user_sessions_key(user_id);

        let hashes: Vec<String> = conn
            .smembers(&user_sessions_key)
            .await
            .map_err(|e| e.to_string())?;

        let to_remove: Vec<&String> = hashes.iter().filter(|h| h.as_str() != keep_hash).collect();

        if to_remove.is_empty() {
            return Ok(0);
        }

        let count = to_remove.len() as u64;
        let mut pipe = redis::pipe();
        pipe.atomic();
        for hash in &to_remove {
            pipe.del(self.session_key(hash));
            pipe.cmd("SREM").arg(&user_sessions_key).arg(hash.as_str());
        }
        pipe.exec_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// RedisRateLimitStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RedisRateLimitStore {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisRateLimitStore {
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            prefix: "yauth".into(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn rate_key(&self, key: &str) -> String {
        format!("{}:rate:{}", self.prefix, key)
    }
}

#[async_trait::async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> RateLimitResult {
        let mut conn = self.conn.clone();
        let rate_key = self.rate_key(key);

        // INCR the key; if it's new (returns 1), set the expiry
        let count: i64 = match conn.incr(&rate_key, 1i64).await {
            Ok(c) => c,
            Err(_) => {
                // On Redis error, allow the request (fail-open)
                return RateLimitResult {
                    allowed: true,
                    remaining: limit.saturating_sub(1),
                    retry_after: 0,
                };
            }
        };

        if count == 1 {
            // New key — set the window expiry
            let _: Result<(), _> = conn.expire::<_, ()>(&rate_key, window_secs as i64).await;
        }

        if count as u32 > limit {
            // Over limit — get TTL for retry_after
            let ttl: i64 = conn.ttl(&rate_key).await.unwrap_or(window_secs as i64);
            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after: ttl.max(0) as u64,
            }
        } else {
            RateLimitResult {
                allowed: true,
                remaining: limit - count as u32,
                retry_after: 0,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RedisChallengeStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RedisChallengeStore {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisChallengeStore {
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            prefix: "yauth".into(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn challenge_key(&self, key: &str) -> String {
        format!("{}:challenge:{}", self.prefix, key)
    }
}

#[async_trait::async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn set(&self, key: &str, value: serde_json::Value, ttl_secs: u64) -> Result<(), String> {
        let mut conn = self.conn.clone();
        let json = serde_json::to_string(&value).map_err(|e| e.to_string())?;
        conn.set_ex::<_, _, ()>(self.challenge_key(key), json, ttl_secs)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
        let mut conn = self.conn.clone();
        let result: Option<String> = conn
            .get(self.challenge_key(key))
            .await
            .map_err(|e| e.to_string())?;

        match result {
            Some(json) => {
                let value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(self.challenge_key(key))
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RedisRevocationStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RedisRevocationStore {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisRevocationStore {
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            prefix: "yauth".into(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn revoked_key(&self, jti: &str) -> String {
        format!("{}:revoked:{}", self.prefix, jti)
    }
}

#[async_trait::async_trait]
impl RevocationStore for RedisRevocationStore {
    async fn revoke(&self, jti: &str, ttl: Duration) -> Result<(), String> {
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(self.revoked_key(jti), "1", ttl.as_secs())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        let mut conn = self.conn.clone();
        let exists: bool = conn
            .exists(self.revoked_key(jti))
            .await
            .map_err(|e| e.to_string())?;
        Ok(exists)
    }
}
