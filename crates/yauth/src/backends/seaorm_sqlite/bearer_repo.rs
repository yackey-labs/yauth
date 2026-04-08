use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::refresh_tokens;
use super::sea_err;
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};

pub(crate) struct SeaOrmRefreshTokenRepo {
    db: DatabaseConnection,
}

impl SeaOrmRefreshTokenRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmRefreshTokenRepo {}

impl RefreshTokenRepository for SeaOrmRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = refresh_tokens::Entity::find()
                .filter(refresh_tokens::Column::TokenHash.eq(&token_hash))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = refresh_tokens::ActiveModel {
                id: Set(input.id.to_string()),
                user_id: Set(input.user_id.to_string()),
                token_hash: Set(input.token_hash),
                family_id: Set(input.family_id.to_string()),
                expires_at: Set(super::to_tz(input.expires_at)),
                revoked: Set(input.revoked),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            refresh_tokens::Entity::update_many()
                .col_expr(refresh_tokens::Column::Revoked, Expr::value(true))
                .filter(refresh_tokens::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            refresh_tokens::Entity::update_many()
                .col_expr(refresh_tokens::Column::Revoked, Expr::value(true))
                .filter(refresh_tokens::Column::FamilyId.eq(family_id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            // Look up the passwords table
            #[cfg(feature = "email-password")]
            {
                use super::entities::passwords;
                let row = passwords::Entity::find_by_id(user_id.to_string())
                    .one(&self.db)
                    .await
                    .map_err(sea_err)?;
                Ok(row.map(|m| m.password_hash))
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}
