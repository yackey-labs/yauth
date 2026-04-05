use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::backends::memory::ChallengeEntry;
use crate::repo::{ChallengeRepository, RepoFuture, sealed};

pub(crate) struct InMemoryChallengeRepo {
    entries: Arc<Mutex<HashMap<String, ChallengeEntry>>>,
}

impl InMemoryChallengeRepo {
    pub(crate) fn new(entries: Arc<Mutex<HashMap<String, ChallengeEntry>>>) -> Self {
        Self { entries }
    }
}

impl sealed::Sealed for InMemoryChallengeRepo {}

impl ChallengeRepository for InMemoryChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            // Cleanup expired entries if map is large
            if map.len() > 1000 {
                let now = Instant::now();
                map.retain(|_, e| e.expires_at > now);
            }
            map.insert(
                key,
                ChallengeEntry {
                    value,
                    expires_at: Instant::now() + Duration::from_secs(ttl_secs),
                },
            );
            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            let map = self.entries.lock().await;
            match map.get(&key) {
                Some(entry) if entry.expires_at > Instant::now() => Ok(Some(entry.value.clone())),
                _ => Ok(None),
            }
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            map.remove(&key);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn new_repo() -> InMemoryChallengeRepo {
        InMemoryChallengeRepo::new(Arc::new(Mutex::new(HashMap::new())))
    }

    #[tokio::test]
    async fn challenge_set_and_get() {
        let repo = new_repo();
        repo.set_challenge("key1", json!({"foo": "bar"}), 60)
            .await
            .unwrap();
        let val = repo.get_challenge("key1").await.unwrap();
        assert_eq!(val, Some(json!({"foo": "bar"})));
    }

    #[tokio::test]
    async fn challenge_get_nonexistent() {
        let repo = new_repo();
        assert_eq!(repo.get_challenge("missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn challenge_delete() {
        let repo = new_repo();
        repo.set_challenge("key1", json!(1), 60).await.unwrap();
        repo.delete_challenge("key1").await.unwrap();
        assert_eq!(repo.get_challenge("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn challenge_expires() {
        let repo = new_repo();
        repo.set_challenge("key1", json!("data"), 1).await.unwrap();
        assert!(repo.get_challenge("key1").await.unwrap().is_some());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(repo.get_challenge("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn challenge_overwrite() {
        let repo = new_repo();
        repo.set_challenge("key1", json!(1), 60).await.unwrap();
        repo.set_challenge("key1", json!(2), 60).await.unwrap();
        assert_eq!(repo.get_challenge("key1").await.unwrap(), Some(json!(2)));
    }
}
