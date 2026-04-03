use chrono::NaiveDateTime;
use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for account lock tracking.
pub trait AccountLockRepository: sealed::Sealed + Send + Sync {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>>;

    /// Insert a new lock record and return it.
    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock>;

    /// Increment failed_count on a lock.
    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Set the lock as locked with a reason and expiry.
    fn set_locked(
        &self,
        id: Uuid,
        locked_until: Option<NaiveDateTime>,
        locked_reason: Option<&str>,
        lock_count: i32,
    ) -> RepoFuture<'_, ()>;

    /// Reset failed count (successful login after partial failures).
    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Auto-unlock: clear locked_until and locked_reason.
    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()>;
}

/// Repository for account unlock tokens.
///
/// # Invariants
///
/// - **`find_by_token_hash`**: MUST return `None` if expired.
pub trait UnlockTokenRepository: sealed::Sealed + Send + Sync {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::UnlockToken>>;

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()>;
}
