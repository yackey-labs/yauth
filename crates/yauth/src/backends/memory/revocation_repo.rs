use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::backends::memory::RevocationEntry;
use crate::repo::{RepoFuture, RevocationRepository, sealed};

pub(crate) struct InMemoryRevocationRepo {
    entries: Arc<Mutex<HashMap<String, RevocationEntry>>>,
}

impl InMemoryRevocationRepo {
    pub(crate) fn new(entries: Arc<Mutex<HashMap<String, RevocationEntry>>>) -> Self {
        Self { entries }
    }
}

impl sealed::Sealed for InMemoryRevocationRepo {}

impl RevocationRepository for InMemoryRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            // Cleanup expired entries if map is large
            if map.len() > 1000 {
                let now = Instant::now();
                map.retain(|_, e| e.expires_at > now);
            }
            map.insert(
                jti,
                RevocationEntry {
                    expires_at: Instant::now() + ttl,
                },
            );
            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            let map = self.entries.lock().await;
            match map.get(&jti) {
                Some(entry) if entry.expires_at > Instant::now() => Ok(true),
                _ => Ok(false),
            }
        })
    }
}
