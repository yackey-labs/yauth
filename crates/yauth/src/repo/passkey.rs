use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for WebAuthn credentials.
///
/// # Invariants
///
/// - **Uniqueness**: credential IDs must be unique per user.
pub trait PasskeyRepository: sealed::Sealed + Send + Sync {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>>;

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>>;

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()>;

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;
}
