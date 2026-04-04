use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};

pub(crate) struct InMemoryPasskeyRepo {
    passkeys: Arc<RwLock<HashMap<Uuid, domain::WebauthnCredential>>>,
}

impl InMemoryPasskeyRepo {
    pub(crate) fn new(passkeys: Arc<RwLock<HashMap<Uuid, domain::WebauthnCredential>>>) -> Self {
        Self { passkeys }
    }
}

impl sealed::Sealed for InMemoryPasskeyRepo {}

impl PasskeyRepository for InMemoryPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let map = self.passkeys.read().unwrap();
            Ok(map
                .values()
                .filter(|p| p.user_id == user_id)
                .cloned()
                .collect())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>> {
        Box::pin(async move {
            let map = self.passkeys.read().unwrap();
            Ok(map.get(&id).filter(|p| p.user_id == user_id).cloned())
        })
    }

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let credential = domain::WebauthnCredential {
                id: input.id,
                user_id: input.user_id,
                name: input.name,
                aaguid: input.aaguid,
                device_name: input.device_name,
                credential: input.credential,
                created_at: input.created_at,
                last_used_at: None,
            };
            let mut map = self.passkeys.write().unwrap();
            map.insert(credential.id, credential);
            Ok(())
        })
    }

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let mut map = self.passkeys.write().unwrap();
            for p in map.values_mut() {
                if p.user_id == user_id {
                    p.last_used_at = Some(now);
                }
            }
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.passkeys.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }
}
