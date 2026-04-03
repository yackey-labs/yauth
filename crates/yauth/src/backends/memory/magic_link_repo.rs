use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};

pub(crate) struct InMemoryMagicLinkRepo {
    links: Arc<RwLock<HashMap<Uuid, domain::MagicLink>>>,
}

impl InMemoryMagicLinkRepo {
    pub(crate) fn new(links: Arc<RwLock<HashMap<Uuid, domain::MagicLink>>>) -> Self {
        Self { links }
    }
}

impl sealed::Sealed for InMemoryMagicLinkRepo {}

impl MagicLinkRepository for InMemoryMagicLinkRepo {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.links.read().unwrap();
            // Return None if expired or already used
            Ok(map
                .values()
                .find(|l| l.token_hash == token_hash && !l.used && l.expires_at > now)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let link = domain::MagicLink {
                id: input.id,
                email: input.email,
                token_hash: input.token_hash,
                expires_at: input.expires_at,
                used: false,
                created_at: input.created_at,
            };
            let mut map = self.links.write().unwrap();
            map.insert(link.id, link);
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.links.write().unwrap();
            if let Some(link) = map.get_mut(&id) {
                link.used = true;
            }
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.links.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let email = email.to_lowercase();
        Box::pin(async move {
            let mut map = self.links.write().unwrap();
            map.retain(|_, l| l.email.to_lowercase() != email || l.used);
            Ok(())
        })
    }
}
