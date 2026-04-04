use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::backends::memory::RateLimitEntry;
use crate::domain;
use crate::repo::{RateLimitRepository, RepoFuture, sealed};

pub(crate) struct InMemoryRateLimitRepo {
    entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl InMemoryRateLimitRepo {
    pub(crate) fn new(entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>) -> Self {
        Self { entries }
    }
}

impl sealed::Sealed for InMemoryRateLimitRepo {}

impl RateLimitRepository for InMemoryRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            let now = Instant::now();
            let window = Duration::from_secs(window_secs);

            // Cleanup if map is large
            if map.len() > 10_000 {
                map.retain(|_, e| now.duration_since(e.window_start) < window);
            }

            let entry = map.entry(key).or_insert_with(|| RateLimitEntry {
                count: 0,
                window_start: now,
            });

            // Reset window if expired
            if now.duration_since(entry.window_start) >= window {
                entry.count = 1;
                entry.window_start = now;
                return Ok(domain::RateLimitResult {
                    allowed: true,
                    remaining: limit.saturating_sub(1),
                    retry_after: 0,
                });
            }

            if entry.count >= limit {
                let retry_after = window
                    .checked_sub(now.duration_since(entry.window_start))
                    .unwrap_or_default()
                    .as_secs();
                Ok(domain::RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    retry_after,
                })
            } else {
                entry.count += 1;
                Ok(domain::RateLimitResult {
                    allowed: true,
                    remaining: limit - entry.count,
                    retry_after: 0,
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_repo() -> InMemoryRateLimitRepo {
        InMemoryRateLimitRepo::new(Arc::new(Mutex::new(HashMap::new())))
    }

    #[tokio::test]
    async fn rate_limit_allows_under_limit() {
        let repo = new_repo();
        let r = repo.check_rate_limit("key1", 3, 60).await.unwrap();
        assert!(r.allowed);
        assert_eq!(r.remaining, 2);
    }

    #[tokio::test]
    async fn rate_limit_blocks_at_limit() {
        let repo = new_repo();
        repo.check_rate_limit("key1", 2, 60).await.unwrap();
        repo.check_rate_limit("key1", 2, 60).await.unwrap();
        let r = repo.check_rate_limit("key1", 2, 60).await.unwrap();
        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
        assert!(r.retry_after > 0);
    }

    #[tokio::test]
    async fn rate_limit_window_resets() {
        let repo = new_repo();
        repo.check_rate_limit("key1", 1, 1).await.unwrap();
        let r = repo.check_rate_limit("key1", 1, 1).await.unwrap();
        assert!(!r.allowed);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let r = repo.check_rate_limit("key1", 1, 1).await.unwrap();
        assert!(r.allowed);
    }

    #[tokio::test]
    async fn rate_limit_independent_keys() {
        let repo = new_repo();
        repo.check_rate_limit("a", 1, 60).await.unwrap();
        let r = repo.check_rate_limit("b", 1, 60).await.unwrap();
        assert!(r.allowed);
    }
}
