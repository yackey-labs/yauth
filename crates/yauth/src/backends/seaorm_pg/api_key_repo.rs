use chrono::Utc;
use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::api_keys;
use super::sea_err;
use crate::domain;
use crate::repo::{ApiKeyRepository, RepoFuture, sealed};

pub(crate) struct SeaOrmApiKeyRepo {
    db: DatabaseConnection,
}

impl SeaOrmApiKeyRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmApiKeyRepo {}

impl ApiKeyRepository for SeaOrmApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let now = Utc::now().fixed_offset();
            let row = api_keys::Entity::find()
                .filter(api_keys::Column::KeyPrefix.eq(&prefix))
                .filter(
                    sea_orm::Condition::any()
                        .add(api_keys::Column::ExpiresAt.is_null())
                        .add(api_keys::Column::ExpiresAt.gt(now)),
                )
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let row = api_keys::Entity::find_by_id(id)
                .filter(api_keys::Column::UserId.eq(user_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let rows = api_keys::Entity::find()
                .filter(api_keys::Column::UserId.eq(user_id))
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = api_keys::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                key_prefix: Set(input.key_prefix),
                key_hash: Set(input.key_hash),
                name: Set(input.name),
                scopes: Set(input.scopes),
                last_used_at: Set(None),
                expires_at: Set(super::opt_to_tz(input.expires_at)),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            api_keys::Entity::delete_many()
                .filter(api_keys::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            api_keys::Entity::update_many()
                .col_expr(
                    api_keys::Column::LastUsedAt,
                    Expr::value(chrono::Utc::now().fixed_offset()),
                )
                .filter(api_keys::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
