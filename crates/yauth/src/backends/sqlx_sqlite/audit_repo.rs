use sqlx::SqlitePool;

use crate::backends::sqlx_common::{dt_to_str, sqlx_err};
use crate::domain;
use crate::repo::{AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SqlxSqliteAuditLogRepo {
    pool: SqlitePool,
}

impl SqlxSqliteAuditLogRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteAuditLogRepo {}

impl AuditLogRepository for SqlxSqliteAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.map(|u| u.to_string());
            let metadata_str = input.metadata.map(|v| v.to_string());
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.event_type,
                metadata_str,
                input.ip_address,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
