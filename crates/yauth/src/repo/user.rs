use super::{RepoFuture, sealed};
use crate::domain;
use uuid::Uuid;

/// Repository for users and sessions.
///
/// # Invariants
///
/// - **`create`**: MUST reject duplicate emails (case-insensitive). Under concurrent
///   callers with the same email, exactly one succeeds, others return `RepoError::Conflict`.
///   This is a safety net for race conditions — OAuth and magic-link flows check
///   `find_by_email` first and only call `create` for genuinely new users.
/// - **`find_by_email`**: MUST be case-insensitive. This is the mechanism for account
///   linking: OAuth callback and magic-link verify look up by email first, and if a
///   user exists, they link/login to the existing account rather than creating a new one.
/// - **`delete`**: MUST cascade to all related entities (passwords, sessions, OAuth accounts,
///   passkeys, MFA secrets, API keys, etc.). Postgres does this via FK constraints;
///   other backends must implement it explicitly.
pub trait UserRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>>;

    /// Case-insensitive email lookup.
    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>>;

    /// Returns `RepoError::Conflict` if email already exists (case-insensitive).
    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User>;

    /// Update user fields. Returns the updated user.
    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User>;

    /// Delete user and cascade to all related entities.
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Check if any user exists (for auto-admin-first-user).
    fn any_exists(&self) -> RepoFuture<'_, bool>;

    /// Paginated user listing with optional search filter (case-insensitive).
    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::User>, i64)>;
}

/// Repository for session management (admin operations).
///
/// Note: ephemeral session storage (create, validate, delete) is handled by
/// `SessionStore` in the stores module. This repository covers admin-level
/// session operations that query the persistent session table.
pub trait SessionRepository: sealed::Sealed + Send + Sync {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>>;

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()>;

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()>;

    /// Paginated session listing for admin.
    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)>;
}
