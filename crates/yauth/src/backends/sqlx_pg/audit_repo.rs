use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, sqlx_err};
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
            sqlx::query!(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                input.id,
                input.user_id as Option<Uuid>,
                input.event_type,
                input.metadata as Option<serde_json::Value>,
                input.ip_address as Option<String>,
                naive_to_utc(input.created_at),
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
