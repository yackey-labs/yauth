use chrono::Utc;
use sea_orm::prelude::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::{email_verifications, password_resets, passwords};
use super::sea_err;
use crate::domain;
use crate::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};

// ── PasswordRepository ──

pub(crate) struct SeaOrmPasswordRepo {
    db: DatabaseConnection,
}

impl SeaOrmPasswordRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmPasswordRepo {}

impl PasswordRepository for SeaOrmPasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let row = passwords::Entity::find_by_id(user_id)
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = passwords::ActiveModel {
                user_id: Set(input.user_id),
                password_hash: Set(input.password_hash),
            };
            passwords::Entity::insert(model)
                .on_conflict(
                    OnConflict::column(passwords::Column::UserId)
                        .update_column(passwords::Column::PasswordHash)
                        .to_owned(),
                )
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// ── EmailVerificationRepository ──

pub(crate) struct SeaOrmEmailVerificationRepo {
    db: DatabaseConnection,
}

impl SeaOrmEmailVerificationRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmEmailVerificationRepo {}

impl EmailVerificationRepository for SeaOrmEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().fixed_offset();
            let row = email_verifications::Entity::find()
                .filter(email_verifications::Column::TokenHash.eq(&token_hash))
                .filter(email_verifications::Column::ExpiresAt.gt(now))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = email_verifications::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                token_hash: Set(input.token_hash),
                expires_at: Set(super::to_tz(input.expires_at)),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            email_verifications::Entity::delete_many()
                .filter(email_verifications::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            email_verifications::Entity::delete_many()
                .filter(email_verifications::Column::UserId.eq(user_id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// ── PasswordResetRepository ──

pub(crate) struct SeaOrmPasswordResetRepo {
    db: DatabaseConnection,
}

impl SeaOrmPasswordResetRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmPasswordResetRepo {}

impl PasswordResetRepository for SeaOrmPasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().fixed_offset();
            let row = password_resets::Entity::find()
                .filter(password_resets::Column::TokenHash.eq(&token_hash))
                .filter(password_resets::Column::ExpiresAt.gt(now))
                .filter(password_resets::Column::UsedAt.is_null())
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = password_resets::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                token_hash: Set(input.token_hash),
                expires_at: Set(super::to_tz(input.expires_at)),
                used_at: Set(None),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            password_resets::Entity::delete_many()
                .filter(password_resets::Column::UserId.eq(user_id))
                .filter(password_resets::Column::UsedAt.is_null())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
