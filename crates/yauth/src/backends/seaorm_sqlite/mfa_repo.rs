use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::{backup_codes, totp_secrets};
use super::sea_err;
use crate::domain;
use crate::repo::{BackupCodeRepository, RepoFuture, TotpRepository, sealed};

// -- TotpRepository --

pub(crate) struct SeaOrmTotpRepo {
    db: DatabaseConnection,
}

impl SeaOrmTotpRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmTotpRepo {}

impl TotpRepository for SeaOrmTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let mut query = totp_secrets::Entity::find()
                .filter(totp_secrets::Column::UserId.eq(user_id.to_string()));

            if let Some(v) = verified {
                query = query.filter(totp_secrets::Column::Verified.eq(v));
            }

            let row = query.one(&self.db).await.map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = totp_secrets::ActiveModel {
                id: Set(input.id.to_string()),
                user_id: Set(input.user_id.to_string()),
                encrypted_secret: Set(input.encrypted_secret),
                verified: Set(input.verified),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut query = totp_secrets::Entity::delete_many()
                .filter(totp_secrets::Column::UserId.eq(user_id.to_string()));

            if let Some(v) = verified_only {
                query = query.filter(totp_secrets::Column::Verified.eq(v));
            }

            query.exec(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            totp_secrets::Entity::update_many()
                .col_expr(totp_secrets::Column::Verified, Expr::value(true))
                .filter(totp_secrets::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// -- BackupCodeRepository --

pub(crate) struct SeaOrmBackupCodeRepo {
    db: DatabaseConnection,
}

impl SeaOrmBackupCodeRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmBackupCodeRepo {}

impl BackupCodeRepository for SeaOrmBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let rows = backup_codes::Entity::find()
                .filter(backup_codes::Column::UserId.eq(user_id.to_string()))
                .filter(backup_codes::Column::Used.eq(false))
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows.into_iter().map(|m| m.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = backup_codes::ActiveModel {
                id: Set(input.id.to_string()),
                user_id: Set(input.user_id.to_string()),
                code_hash: Set(input.code_hash),
                used: Set(input.used),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            backup_codes::Entity::delete_many()
                .filter(backup_codes::Column::UserId.eq(user_id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            backup_codes::Entity::update_many()
                .col_expr(backup_codes::Column::Used, Expr::value(true))
                .filter(backup_codes::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
