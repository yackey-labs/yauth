use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::domain;
use crate::repo::{RepoError, RepoFuture, SessionOpsRepository, sealed};

pub(crate) struct InMemorySessionOpsRepo {
    entries: Arc<Mutex<HashMap<String, domain::StoredSession>>>,
}

impl InMemorySessionOpsRepo {
    pub(crate) fn new(entries: Arc<Mutex<HashMap<String, domain::StoredSession>>>) -> Self {
        Self { entries }
    }
}

impl sealed::Sealed for InMemorySessionOpsRepo {}

impl SessionOpsRepository for InMemorySessionOpsRepo {
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: Duration,
    ) -> RepoFuture<'_, Uuid> {
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            // Cleanup expired entries if map is large
            if map.len() > 1000 {
                let now = Utc::now().naive_utc();
                map.retain(|_, s| s.expires_at > now);
            }
            let id = Uuid::new_v4();
            let now = Utc::now().naive_utc();
            let expires_at = now
                + chrono::Duration::from_std(ttl)
                    .map_err(|e| RepoError::Internal(e.to_string().into()))?;
            let session = domain::StoredSession {
                id,
                user_id,
                ip_address,
                user_agent,
                expires_at,
                created_at: now,
            };
            map.insert(token_hash, session);
            Ok(id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            let now = Utc::now().naive_utc();
            match map.get(&token_hash) {
                Some(session) if session.expires_at > now => Ok(Some(session.clone())),
                Some(_) => {
                    // Expired — remove it
                    map.remove(&token_hash);
                    Ok(None)
                }
                None => Ok(None),
            }
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            Ok(map.remove(&token_hash).is_some())
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            let before = map.len();
            map.retain(|_, s| s.user_id != user_id);
            Ok((before - map.len()) as u64)
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            let mut map = self.entries.lock().await;
            let before = map.len();
            map.retain(|key, s| !(s.user_id == user_id && key != &keep_hash));
            Ok((before - map.len()) as u64)
        })
    }
}
