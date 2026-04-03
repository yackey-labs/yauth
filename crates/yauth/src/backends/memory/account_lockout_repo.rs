use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{NaiveDateTime, Utc};
use uuid::Uuid;

use crate::domain;
use crate::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};

// ──────────────────────────────────────────────
// Account Lock Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryAccountLockRepo {
    locks: Arc<RwLock<HashMap<Uuid, domain::AccountLock>>>,
}

impl InMemoryAccountLockRepo {
    pub(crate) fn new(locks: Arc<RwLock<HashMap<Uuid, domain::AccountLock>>>) -> Self {
        Self { locks }
    }
}

impl sealed::Sealed for InMemoryAccountLockRepo {}

impl AccountLockRepository for InMemoryAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let map = self.locks.read().unwrap();
            Ok(map.values().find(|l| l.user_id == user_id).cloned())
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let lock = domain::AccountLock {
                id: input.id,
                user_id: input.user_id,
                failed_count: input.failed_count,
                locked_until: input.locked_until,
                lock_count: input.lock_count,
                locked_reason: input.locked_reason,
                created_at: input.created_at,
                updated_at: input.updated_at,
            };
            let mut map = self.locks.write().unwrap();
            map.insert(lock.id, lock.clone());
            Ok(lock)
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.locks.write().unwrap();
            if let Some(lock) = map.get_mut(&id) {
                lock.failed_count += 1;
                lock.updated_at = Utc::now().naive_utc();
            }
            Ok(())
        })
    }

    fn set_locked(
        &self,
        id: Uuid,
        locked_until: Option<NaiveDateTime>,
        locked_reason: Option<&str>,
        lock_count: i32,
    ) -> RepoFuture<'_, ()> {
        let locked_reason = locked_reason.map(|s| s.to_string());
        Box::pin(async move {
            let mut map = self.locks.write().unwrap();
            if let Some(lock) = map.get_mut(&id) {
                lock.locked_until = locked_until;
                lock.locked_reason = locked_reason;
                lock.lock_count = lock_count;
                lock.updated_at = Utc::now().naive_utc();
            }
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.locks.write().unwrap();
            if let Some(lock) = map.get_mut(&id) {
                lock.failed_count = 0;
                lock.updated_at = Utc::now().naive_utc();
            }
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.locks.write().unwrap();
            if let Some(lock) = map.get_mut(&id) {
                lock.locked_until = None;
                lock.locked_reason = None;
                lock.updated_at = Utc::now().naive_utc();
            }
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Unlock Token Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryUnlockTokenRepo {
    tokens: Arc<RwLock<HashMap<Uuid, domain::UnlockToken>>>,
}

impl InMemoryUnlockTokenRepo {
    pub(crate) fn new(tokens: Arc<RwLock<HashMap<Uuid, domain::UnlockToken>>>) -> Self {
        Self { tokens }
    }
}

impl sealed::Sealed for InMemoryUnlockTokenRepo {}

impl UnlockTokenRepository for InMemoryUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.tokens.read().unwrap();
            // Expiration on read
            Ok(map
                .values()
                .find(|t| t.token_hash == token_hash && t.expires_at > now)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let token = domain::UnlockToken {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                expires_at: input.expires_at,
                created_at: input.created_at,
            };
            let mut map = self.tokens.write().unwrap();
            map.insert(token.id, token);
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.tokens.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.tokens.write().unwrap();
            map.retain(|_, t| t.user_id != user_id);
            Ok(())
        })
    }
}
