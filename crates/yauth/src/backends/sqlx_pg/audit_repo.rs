use sqlx::PgPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SqlxPgAuditLogRepo {
    pool: PgPool,
}

impl SqlxPgAuditLogRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgAuditLogRepo {}

impl AuditLogRepository for SqlxPgAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.event_type)
            .bind(&input.metadata)
            .bind(&input.ip_address)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
