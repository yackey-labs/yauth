use toasty::Db;

use crate::entities::YauthAuditLog;
use crate::helpers::*;
use yauth::repo::{AuditLogRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyAuditLogRepo {
    db: Db,
}

impl ToastyAuditLogRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyAuditLogRepo {}

impl AuditLogRepository for ToastyAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthAuditLog {
                id: input.id,
                user_id: input.user_id,
                event_type: input.event_type,
                metadata: input.metadata,
                ip_address: input.ip_address,
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }
}
