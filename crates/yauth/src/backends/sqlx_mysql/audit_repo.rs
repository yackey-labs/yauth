use sqlx::MySqlPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SqlxMysqlAuditLogRepo {
    pool: MySqlPool,
}

impl SqlxMysqlAuditLogRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxMysqlAuditLogRepo {}

impl AuditLogRepository for SqlxMysqlAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.map(|u| u.to_string());
            sqlx::query!(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.event_type,
                input.metadata,
                input.ip_address,
                input.created_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
