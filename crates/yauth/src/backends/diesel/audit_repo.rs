use diesel_async_crate::RunQueryDsl;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{AuditLogRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselAuditLogRepo {
    pool: DbPool,
}

impl DieselAuditLogRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselAuditLogRepo {}

impl AuditLogRepository for DieselAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let diesel_input = DieselNewAuditLog::from_domain(input);
            diesel::insert_into(yauth_audit_log::table)
                .values(&diesel_input)
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}
