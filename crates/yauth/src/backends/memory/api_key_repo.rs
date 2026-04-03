use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{ApiKeyRepository, RepoError, RepoFuture, sealed};

pub(crate) struct InMemoryApiKeyRepo {
    keys: Arc<RwLock<HashMap<Uuid, domain::ApiKey>>>,
}

impl InMemoryApiKeyRepo {
    pub(crate) fn new(keys: Arc<RwLock<HashMap<Uuid, domain::ApiKey>>>) -> Self {
        Self { keys }
    }
}

impl sealed::Sealed for InMemoryApiKeyRepo {}

impl ApiKeyRepository for InMemoryApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.keys.read().unwrap();
            // Expiration on read: return None if expired
            Ok(map
                .values()
                .find(|k| k.key_prefix == prefix && k.expires_at.is_none_or(|e| e > now))
                .cloned())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let map = self.keys.read().unwrap();
            Ok(map.get(&id).filter(|k| k.user_id == user_id).cloned())
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let map = self.keys.read().unwrap();
            Ok(map
                .values()
                .filter(|k| k.user_id == user_id)
                .cloned()
                .collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.keys.write().unwrap();
            // Enforce name uniqueness per user
            if map
                .values()
                .any(|k| k.user_id == input.user_id && k.name == input.name)
            {
                return Err(RepoError::Conflict(
                    "duplicate API key name for user".to_string(),
                ));
            }

            let key = domain::ApiKey {
                id: input.id,
                user_id: input.user_id,
                key_prefix: input.key_prefix,
                key_hash: input.key_hash,
                name: input.name,
                scopes: input.scopes,
                last_used_at: None,
                expires_at: input.expires_at,
                created_at: input.created_at,
            };
            map.insert(key.id, key);
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.keys.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let mut map = self.keys.write().unwrap();
            if let Some(key) = map.get_mut(&id) {
                key.last_used_at = Some(now);
            }
            Ok(())
        })
    }
}
