use chrono::Utc;
use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::sessions;
use super::sea_err;
use crate::domain;
use crate::repo::{RepoFuture, SessionOpsRepository, sealed};

pub(crate) struct SeaOrmSessionOpsRepo {
    db: DatabaseConnection,
}

impl SeaOrmSessionOpsRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmSessionOpsRepo {}

impl SessionOpsRepository for SeaOrmSessionOpsRepo {
    fn create_session(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> RepoFuture<'_, Uuid> {
        Box::pin(async move {
            let session_id = Uuid::now_v7();
            let now = Utc::now();
            let expires_at =
                now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

            let model = sessions::ActiveModel {
                id: Set(session_id.to_string()),
                user_id: Set(user_id.to_string()),
                token_hash: Set(token_hash),
                ip_address: Set(ip_address),
                user_agent: Set(user_agent),
                expires_at: Set(expires_at.fixed_offset()),
                created_at: Set(now.fixed_offset()),
            };

            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(session_id)
        })
    }

    fn validate_session(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::StoredSession>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let session = sessions::Entity::find()
                .filter(sessions::Column::TokenHash.eq(&token_hash))
                .one(&self.db)
                .await
                .map_err(sea_err)?;

            match session {
                Some(s) => {
                    let now = Utc::now().fixed_offset();
                    if s.expires_at < now {
                        // Expired -- clean up (best-effort, don't fail the read)
                        sessions::Entity::delete_many()
                            .filter(sessions::Column::Id.eq(&s.id))
                            .exec(&self.db)
                            .await
                            .ok();
                        return Ok(None);
                    }

                    Ok(Some(domain::StoredSession {
                        id: crate::backends::seaorm_common::str_to_uuid(&s.id),
                        user_id: crate::backends::seaorm_common::str_to_uuid(&s.user_id),
                        ip_address: s.ip_address,
                        user_agent: s.user_agent,
                        expires_at: s.expires_at.naive_utc(),
                        created_at: s.created_at.naive_utc(),
                    }))
                }
                None => Ok(None),
            }
        })
    }

    fn delete_session(&self, token_hash: &str) -> RepoFuture<'_, bool> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let result = sessions::Entity::delete_many()
                .filter(sessions::Column::TokenHash.eq(&token_hash))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(result.rows_affected > 0)
        })
    }

    fn delete_all_sessions_for_user(&self, user_id: Uuid) -> RepoFuture<'_, u64> {
        Box::pin(async move {
            let result = sessions::Entity::delete_many()
                .filter(sessions::Column::UserId.eq(user_id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(result.rows_affected)
        })
    }

    fn delete_other_sessions_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> RepoFuture<'_, u64> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            let result = sessions::Entity::delete_many()
                .filter(sessions::Column::UserId.eq(user_id.to_string()))
                .filter(sessions::Column::TokenHash.ne(&keep_hash))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(result.rows_affected)
        })
    }
}
