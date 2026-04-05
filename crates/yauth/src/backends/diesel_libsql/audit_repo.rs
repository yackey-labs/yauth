use super::LibsqlPool;
use super::models::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{AuditLogRepository, RepoFuture, sealed};
use diesel_async_crate::RunQueryDsl;

pub(crate) struct LibsqlAuditLogRepo {
    pool: LibsqlPool,
}
impl LibsqlAuditLogRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlAuditLogRepo {}

impl AuditLogRepository for LibsqlAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let a = LibsqlNewAuditLog::from_domain(input);
            diesel::sql_query(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind::<diesel::sql_types::Text, _>(&a.id)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&a.user_id)
            .bind::<diesel::sql_types::Text, _>(&a.event_type)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&a.metadata)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&a.ip_address)
            .bind::<diesel::sql_types::Text, _>(&a.created_at)
            .execute(&mut *conn).await.map_err(diesel_err)?;
            Ok(())
        })
    }
}
