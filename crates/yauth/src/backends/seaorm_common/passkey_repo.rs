use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::passkeys;
use super::sea_err;
use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};

pub(crate) struct SeaOrmPasskeyRepo {
    db: DatabaseConnection,
}

impl SeaOrmPasskeyRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmPasskeyRepo {}

impl PasskeyRepository for SeaOrmPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let rows = passkeys::Entity::find()
                .filter(passkeys::Column::UserId.eq(user_id))
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>> {
        Box::pin(async move {
            let row = passkeys::Entity::find_by_id(id)
                .filter(passkeys::Column::UserId.eq(user_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = passkeys::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                name: Set(input.name),
                aaguid: Set(input.aaguid),
                device_name: Set(input.device_name),
                credential: Set(input.credential),
                created_at: Set(super::to_tz(input.created_at)),
                last_used_at: Set(None),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            passkeys::Entity::update_many()
                .col_expr(
                    passkeys::Column::LastUsedAt,
                    Expr::value(chrono::Utc::now().fixed_offset()),
                )
                .filter(passkeys::Column::UserId.eq(user_id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            passkeys::Entity::delete_many()
                .filter(passkeys::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
