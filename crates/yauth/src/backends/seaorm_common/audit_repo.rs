use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, Set};

use super::entities::audit_log;
use super::sea_err;
use crate::domain;
use crate::repo::{AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SeaOrmAuditLogRepo {
    db: DatabaseConnection,
}

impl SeaOrmAuditLogRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmAuditLogRepo {}

impl AuditLogRepository for SeaOrmAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = audit_log::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                event_type: Set(input.event_type),
                metadata: Set(input.metadata),
                ip_address: Set(input.ip_address),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }
}
