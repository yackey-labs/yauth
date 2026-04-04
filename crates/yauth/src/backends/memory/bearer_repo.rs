use uuid::Uuid;

use super::Storage;
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};

/// The bearer repo needs access to the full storage because
/// `find_password_hash_by_user_id` reads from the passwords map.
pub(crate) struct InMemoryRefreshTokenRepo {
    storage: Storage,
}

impl InMemoryRefreshTokenRepo {
    pub(crate) fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

impl sealed::Sealed for InMemoryRefreshTokenRepo {}

impl RefreshTokenRepository for InMemoryRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let map = self.storage.refresh_tokens.read().unwrap();
            Ok(map.values().find(|t| t.token_hash == token_hash).cloned())
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let token = domain::RefreshToken {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                family_id: input.family_id,
                expires_at: input.expires_at,
                revoked: input.revoked,
                created_at: input.created_at,
            };
            let mut map = self.storage.refresh_tokens.write().unwrap();
            map.insert(token.id, token);
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.storage.refresh_tokens.write().unwrap();
            if let Some(token) = map.get_mut(&id) {
                token.revoked = true;
            }
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.storage.refresh_tokens.write().unwrap();
            for token in map.values_mut() {
                if token.family_id == family_id {
                    token.revoked = true;
                }
            }
            Ok(())
        })
    }

    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            // The bearer plugin's password grant needs to look up the user's password hash.
            // This crosses into the passwords store (email-password feature).
            #[cfg(feature = "email-password")]
            {
                let map = self.storage.passwords.read().unwrap();
                Ok(map.get(&user_id).map(|p| p.password_hash.clone()))
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}
