use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for TOTP secrets.
pub trait TotpRepository: sealed::Sealed + Send + Sync {
    /// Find a TOTP secret by user, optionally filtering by verified status.
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>>;

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()>;

    /// Delete TOTP secrets for a user. If `verified_only` is Some, only delete matching.
    fn delete_for_user(
        &self,
        user_id: Uuid,
        verified_only: Option<bool>,
    ) -> RepoFuture<'_, ()>;

    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()>;
}

/// Repository for MFA backup codes.
pub trait BackupCodeRepository: sealed::Sealed + Send + Sync {
    fn find_unused_by_user_id(
        &self,
        user_id: Uuid,
    ) -> RepoFuture<'_, Vec<domain::BackupCode>>;

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()>;

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()>;

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()>;
}
