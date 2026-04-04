use super::{RepoFuture, sealed};
use crate::domain;

/// Repository for audit log entries.
///
/// Insert-only — audit logs are never updated or deleted.
pub trait AuditLogRepository: sealed::Sealed + Send + Sync {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()>;
}
