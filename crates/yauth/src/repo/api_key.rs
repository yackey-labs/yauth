use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for API keys.
///
/// # Invariants
///
/// - **Uniqueness**: key name must be unique per user.
/// - **Expiration on read**: `find_by_prefix` MUST return `None` if the key is expired.
pub trait ApiKeyRepository: sealed::Sealed + Send + Sync {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>>;

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>>;

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>>;

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()>;
}
