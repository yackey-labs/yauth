use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for JWT refresh tokens.
pub trait RefreshTokenRepository: sealed::Sealed + Send + Sync {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::RefreshToken>>;

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()>;

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Revoke all tokens in a rotation family (token reuse detection).
    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()>;

    /// Find password hash for a user (used by bearer plugin for password grant).
    fn find_password_hash_by_user_id(
        &self,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<String>>;
}
