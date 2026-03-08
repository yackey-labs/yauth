use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_KEYS: usize = 10_000;

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Returns true if the request is allowed, false if rate limited.
    pub async fn check(&self, key: &str) -> bool {
        let mut map = self.requests.lock().await;
        let now = Instant::now();

        // Evict stale keys periodically to bound memory usage
        if map.len() > MAX_KEYS {
            map.retain(|_, entries| {
                entries.retain(|t| now.duration_since(*t) < self.window);
                !entries.is_empty()
            });
        }

        let entry = map.entry(key.to_string()).or_default();
        // Remove entries outside the window
        entry.retain(|t| now.duration_since(*t) < self.window);
        let allowed = entry.len() < self.max_requests;
        if allowed {
            entry.push(now);
        } else {
            // Record rate limiting on the parent SERVER span
            tracing::Span::current().record("yauth.rate_limited", true);
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_under_limit() {
        let rl = RateLimiter::new(3, 60);
        assert!(rl.check("user1").await);
        assert!(rl.check("user1").await);
        assert!(rl.check("user1").await);
    }

    #[tokio::test]
    async fn blocks_at_limit() {
        let rl = RateLimiter::new(2, 60);
        assert!(rl.check("user1").await);
        assert!(rl.check("user1").await);
        assert!(!rl.check("user1").await);
    }

    #[tokio::test]
    async fn different_keys_independent() {
        let rl = RateLimiter::new(1, 60);
        assert!(rl.check("user1").await);
        assert!(rl.check("user2").await);
        assert!(!rl.check("user1").await);
        assert!(!rl.check("user2").await);
    }

    #[tokio::test]
    async fn window_resets_after_expiry() {
        let rl = RateLimiter::new(1, 1); // 1 req / 1 sec
        assert!(rl.check("user1").await);
        assert!(!rl.check("user1").await);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(rl.check("user1").await);
    }
}
