use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for password hashes.
pub trait PasswordRepository: sealed::Sealed + Send + Sync {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>>;

    /// Insert or replace the password hash for a user.
    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()>;
}

/// Repository for email verification tokens.
///
/// # Invariants
///
/// - **`find_by_token_hash`**: MUST return `None` if the token is expired.
pub trait EmailVerificationRepository: sealed::Sealed + Send + Sync {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>>;

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Delete all verifications for a user.
    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()>;
}

/// Repository for password reset tokens.
///
/// # Invariants
///
/// - **`find_by_token_hash`**: MUST return `None` if the token is expired or already used.
pub trait PasswordResetRepository: sealed::Sealed + Send + Sync {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>>;

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()>;

    /// Delete all unused resets for a user.
    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()>;
}
