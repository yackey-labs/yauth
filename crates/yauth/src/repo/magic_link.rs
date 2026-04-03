use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for magic link tokens.
///
/// # Invariants
///
/// - **`find_unused_by_token_hash`**: MUST return `None` if the token is expired or already used.
pub trait MagicLinkRepository: sealed::Sealed + Send + Sync {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>>;

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()>;

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Delete all unused magic links for an email address.
    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()>;
}
