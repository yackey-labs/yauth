use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use uuid::Uuid;

use crate::domain;
use crate::repo::{BackupCodeRepository, RepoFuture, TotpRepository, sealed};

// ──────────────────────────────────────────────
// TOTP Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryTotpRepo {
    secrets: Arc<RwLock<HashMap<Uuid, domain::TotpSecret>>>,
}

impl InMemoryTotpRepo {
    pub(crate) fn new(secrets: Arc<RwLock<HashMap<Uuid, domain::TotpSecret>>>) -> Self {
        Self { secrets }
    }
}

impl sealed::Sealed for InMemoryTotpRepo {}

impl TotpRepository for InMemoryTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let map = self.secrets.read().unwrap();
            Ok(map
                .values()
                .find(|t| t.user_id == user_id && verified.is_none_or(|v| t.verified == v))
                .cloned())
        })
    }

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let secret = domain::TotpSecret {
                id: input.id,
                user_id: input.user_id,
                encrypted_secret: input.encrypted_secret,
                verified: input.verified,
                created_at: input.created_at,
            };
            let mut map = self.secrets.write().unwrap();
            map.insert(secret.id, secret);
            Ok(())
        })
    }

    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.secrets.write().unwrap();
            map.retain(|_, t| {
                if t.user_id != user_id {
                    return true;
                }
                match verified_only {
                    Some(v) => t.verified != v,
                    None => false,
                }
            });
            Ok(())
        })
    }

    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.secrets.write().unwrap();
            if let Some(secret) = map.get_mut(&id) {
                secret.verified = true;
            }
            Ok(())
        })
    }
}

// ──────────────────────────────────────────────
// Backup Code Repository
// ──────────────────────────────────────────────

pub(crate) struct InMemoryBackupCodeRepo {
    codes: Arc<RwLock<HashMap<Uuid, domain::BackupCode>>>,
}

impl InMemoryBackupCodeRepo {
    pub(crate) fn new(codes: Arc<RwLock<HashMap<Uuid, domain::BackupCode>>>) -> Self {
        Self { codes }
    }
}

impl sealed::Sealed for InMemoryBackupCodeRepo {}

impl BackupCodeRepository for InMemoryBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let map = self.codes.read().unwrap();
            Ok(map
                .values()
                .filter(|b| b.user_id == user_id && !b.used)
                .cloned()
                .collect())
        })
    }

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let code = domain::BackupCode {
                id: input.id,
                user_id: input.user_id,
                code_hash: input.code_hash,
                used: input.used,
                created_at: input.created_at,
            };
            let mut map = self.codes.write().unwrap();
            map.insert(code.id, code);
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.codes.write().unwrap();
            map.retain(|_, b| b.user_id != user_id);
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.codes.write().unwrap();
            if let Some(code) = map.get_mut(&id) {
                code.used = true;
            }
            Ok(())
        })
    }
}
