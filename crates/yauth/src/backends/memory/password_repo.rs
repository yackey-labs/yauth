use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};

// ──────────────────────────────────────────────
// Password Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryPasswordRepo {
    passwords: Arc<RwLock<HashMap<Uuid, domain::Password>>>,
}

impl InMemoryPasswordRepo {
    pub(crate) fn new(passwords: Arc<RwLock<HashMap<Uuid, domain::Password>>>) -> Self {
        Self { passwords }
    }
}

impl sealed::Sealed for InMemoryPasswordRepo {}

impl PasswordRepository for InMemoryPasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let map = self.passwords.read().unwrap();
            Ok(map.get(&user_id).cloned())
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.passwords.write().unwrap();
            let password = domain::Password {
                user_id: input.user_id,
                password_hash: input.password_hash,
            };
            map.insert(input.user_id, password);
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Email Verification Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryEmailVerificationRepo {
    verifications: Arc<RwLock<HashMap<Uuid, domain::EmailVerification>>>,
}

impl InMemoryEmailVerificationRepo {
    pub(crate) fn new(
        verifications: Arc<RwLock<HashMap<Uuid, domain::EmailVerification>>>,
    ) -> Self {
        Self { verifications }
    }
}

impl sealed::Sealed for InMemoryEmailVerificationRepo {}

impl EmailVerificationRepository for InMemoryEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.verifications.read().unwrap();
            Ok(map
                .values()
                .find(|v| v.token_hash == token_hash && v.expires_at > now)
                .cloned())
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let verification = domain::EmailVerification {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                expires_at: input.expires_at,
                created_at: input.created_at,
            };
            let mut map = self.verifications.write().unwrap();
            map.insert(verification.id, verification);
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.verifications.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.verifications.write().unwrap();
            map.retain(|_, v| v.user_id != user_id);
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Password Reset Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryPasswordResetRepo {
    resets: Arc<RwLock<HashMap<Uuid, domain::PasswordReset>>>,
}

impl InMemoryPasswordResetRepo {
    pub(crate) fn new(resets: Arc<RwLock<HashMap<Uuid, domain::PasswordReset>>>) -> Self {
        Self { resets }
    }
}

impl sealed::Sealed for InMemoryPasswordResetRepo {}

impl PasswordResetRepository for InMemoryPasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.resets.read().unwrap();
            // Return None if expired or already used
            Ok(map
                .values()
                .find(|r| r.token_hash == token_hash && r.expires_at > now && r.used_at.is_none())
                .cloned())
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let reset = domain::PasswordReset {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                expires_at: input.expires_at,
                used_at: None,
                created_at: input.created_at,
            };
            let mut map = self.resets.write().unwrap();
            map.insert(reset.id, reset);
            Ok(())
        })
    }

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.resets.write().unwrap();
            map.retain(|_, r| !(r.user_id == user_id && r.used_at.is_none()));
            Ok(())
        })
    }
}
