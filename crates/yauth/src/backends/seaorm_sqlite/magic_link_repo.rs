use chrono::Utc;
use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::magic_links;
use super::sea_err;
use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};

pub(crate) struct SeaOrmMagicLinkRepo {
    db: DatabaseConnection,
}

impl SeaOrmMagicLinkRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmMagicLinkRepo {}

impl MagicLinkRepository for SeaOrmMagicLinkRepo {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().fixed_offset();
            let row = magic_links::Entity::find()
                .filter(magic_links::Column::TokenHash.eq(&token_hash))
                .filter(magic_links::Column::ExpiresAt.gt(now))
                .filter(magic_links::Column::Used.eq(false))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = magic_links::ActiveModel {
                id: Set(input.id.to_string()),
                email: Set(input.email),
                token_hash: Set(input.token_hash),
                expires_at: Set(super::to_tz(input.expires_at)),
                used: Set(false),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            magic_links::Entity::update_many()
                .col_expr(magic_links::Column::Used, Expr::value(true))
                .filter(magic_links::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            magic_links::Entity::delete_many()
                .filter(magic_links::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let email = email.to_string();
        Box::pin(async move {
            magic_links::Entity::delete_many()
                .filter(magic_links::Column::Email.eq(&email))
                .filter(magic_links::Column::Used.eq(false))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
