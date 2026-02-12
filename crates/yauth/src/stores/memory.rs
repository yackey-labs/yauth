use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::{ChallengeStore, RateLimitResult, RateLimitStore};

// --- MemoryChallengeStore ---

struct ChallengeEntry {
    value: serde_json::Value,
    expires_at: Instant,
}

pub struct MemoryChallengeStore {
    entries: Arc<Mutex<HashMap<String, ChallengeEntry>>>,
}

impl Default for MemoryChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryChallengeStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ChallengeStore for MemoryChallengeStore {
    async fn set(&self, key: &str, value: serde_json::Value, ttl_secs: u64) -> Result<(), String> {
        let mut map = self.entries.lock().await;
        // Cleanup expired entries if map is large
        if map.len() > 1000 {
            let now = Instant::now();
            map.retain(|_, e| e.expires_at > now);
        }
        map.insert(
            key.to_string(),
            ChallengeEntry {
                value,
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
        let map = self.entries.lock().await;
        match map.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => Ok(Some(entry.value.clone())),
            _ => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let mut map = self.entries.lock().await;
        map.remove(key);
        Ok(())
    }
}

// --- MemoryRateLimitStore ---

struct RateLimitEntry {
    timestamps: Vec<Instant>,
}

pub struct MemoryRateLimitStore {
    entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    default_limit: u32,
    default_window_secs: u64,
}

impl MemoryRateLimitStore {
    pub fn new(default_limit: u32, default_window_secs: u64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            default_limit,
            default_window_secs,
        }
    }
}

#[async_trait::async_trait]
impl RateLimitStore for MemoryRateLimitStore {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> RateLimitResult {
        let mut map = self.entries.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(if window_secs > 0 {
            window_secs
        } else {
            self.default_window_secs
        });
        let max = if limit > 0 { limit } else { self.default_limit };

        // Cleanup if map is large
        if map.len() > 10_000 {
            map.retain(|_, e| {
                e.timestamps.retain(|t| now.duration_since(*t) < window);
                !e.timestamps.is_empty()
            });
        }

        let entry = map
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry {
                timestamps: Vec::new(),
            });
        entry.timestamps.retain(|t| now.duration_since(*t) < window);

        if entry.timestamps.len() >= max as usize {
            let oldest = entry.timestamps.first().copied().unwrap_or(now);
            let retry_after = window
                .checked_sub(now.duration_since(oldest))
                .unwrap_or_default()
                .as_secs();
            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after,
            }
        } else {
            entry.timestamps.push(now);
            RateLimitResult {
                allowed: true,
                remaining: max - entry.timestamps.len() as u32,
                retry_after: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- ChallengeStore tests ---

    #[tokio::test]
    async fn challenge_store_set_and_get() {
        let store = MemoryChallengeStore::new();
        store.set("key1", json!({"foo": "bar"}), 60).await.unwrap();
        let val = store.get("key1").await.unwrap();
        assert_eq!(val, Some(json!({"foo": "bar"})));
    }

    #[tokio::test]
    async fn challenge_store_get_nonexistent() {
        let store = MemoryChallengeStore::new();
        assert_eq!(store.get("missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn challenge_store_delete() {
        let store = MemoryChallengeStore::new();
        store.set("key1", json!(1), 60).await.unwrap();
        store.delete("key1").await.unwrap();
        assert_eq!(store.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn challenge_store_expires() {
        let store = MemoryChallengeStore::new();
        store.set("key1", json!("data"), 1).await.unwrap(); // 1 second TTL
        assert!(store.get("key1").await.unwrap().is_some());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(store.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn challenge_store_overwrite() {
        let store = MemoryChallengeStore::new();
        store.set("key1", json!(1), 60).await.unwrap();
        store.set("key1", json!(2), 60).await.unwrap();
        assert_eq!(store.get("key1").await.unwrap(), Some(json!(2)));
    }

    // --- RateLimitStore tests ---

    #[tokio::test]
    async fn rate_limit_store_allows_under_limit() {
        let store = MemoryRateLimitStore::new(10, 60);
        let r = store.check("key1", 3, 60).await;
        assert!(r.allowed);
        assert_eq!(r.remaining, 2);
    }

    #[tokio::test]
    async fn rate_limit_store_blocks_at_limit() {
        let store = MemoryRateLimitStore::new(10, 60);
        store.check("key1", 2, 60).await;
        store.check("key1", 2, 60).await;
        let r = store.check("key1", 2, 60).await;
        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
        assert!(r.retry_after > 0);
    }

    #[tokio::test]
    async fn rate_limit_store_window_resets() {
        let store = MemoryRateLimitStore::new(10, 1);
        store.check("key1", 1, 1).await;
        let r = store.check("key1", 1, 1).await;
        assert!(!r.allowed);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let r = store.check("key1", 1, 1).await;
        assert!(r.allowed);
    }

    #[tokio::test]
    async fn rate_limit_store_independent_keys() {
        let store = MemoryRateLimitStore::new(10, 60);
        store.check("a", 1, 60).await;
        let r = store.check("b", 1, 60).await;
        assert!(r.allowed);
    }
}
