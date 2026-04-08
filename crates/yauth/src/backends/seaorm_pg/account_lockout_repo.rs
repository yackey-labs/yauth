use chrono::{NaiveDateTime, Utc};
use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ExprTrait, Set};
use uuid::Uuid;

use super::entities::{account_locks, unlock_tokens};
use super::sea_err;
use crate::domain;
use crate::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};

// ── AccountLockRepository ──

pub(crate) struct SeaOrmAccountLockRepo {
    db: DatabaseConnection,
}

impl SeaOrmAccountLockRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmAccountLockRepo {}

impl AccountLockRepository for SeaOrmAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let row = account_locks::Entity::find()
                .filter(account_locks::Column::UserId.eq(user_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let model = account_locks::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                failed_count: Set(input.failed_count),
                locked_until: Set(super::opt_to_tz(input.locked_until)),
                lock_count: Set(input.lock_count),
                locked_reason: Set(input.locked_reason),
                created_at: Set(super::to_tz(input.created_at)),
                updated_at: Set(super::to_tz(input.updated_at)),
            };
            let result = model.insert(&self.db).await.map_err(sea_err)?;
            Ok(result.into_domain())
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            account_locks::Entity::update_many()
                .col_expr(
                    account_locks::Column::FailedCount,
                    Expr::col(account_locks::Column::FailedCount).add(1),
                )
                .col_expr(
                    account_locks::Column::UpdatedAt,
                    Expr::value(Utc::now().fixed_offset()),
                )
                .filter(account_locks::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn set_locked(
        &self,
        id: Uuid,
        locked_until: Option<NaiveDateTime>,
        locked_reason: Option<&str>,
        lock_count: i32,
    ) -> RepoFuture<'_, ()> {
        let locked_reason = locked_reason.map(|s| s.to_string());
        Box::pin(async move {
            account_locks::Entity::update_many()
                .col_expr(
                    account_locks::Column::LockedUntil,
                    Expr::value(super::opt_to_tz(locked_until)),
                )
                .col_expr(
                    account_locks::Column::LockedReason,
                    Expr::value(locked_reason),
                )
                .col_expr(account_locks::Column::LockCount, Expr::value(lock_count))
                .col_expr(
                    account_locks::Column::UpdatedAt,
                    Expr::value(Utc::now().fixed_offset()),
                )
                .filter(account_locks::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            account_locks::Entity::update_many()
                .col_expr(account_locks::Column::FailedCount, Expr::value(0))
                .col_expr(
                    account_locks::Column::UpdatedAt,
                    Expr::value(chrono::Utc::now().fixed_offset()),
                )
                .filter(account_locks::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            account_locks::Entity::update_many()
                .col_expr(
                    account_locks::Column::LockedUntil,
                    Expr::value(Option::<chrono::DateTime<chrono::FixedOffset>>::None),
                )
                .col_expr(
                    account_locks::Column::LockedReason,
                    Expr::value(Option::<String>::None),
                )
                .col_expr(account_locks::Column::FailedCount, Expr::value(0))
                .col_expr(
                    account_locks::Column::UpdatedAt,
                    Expr::value(Utc::now().fixed_offset()),
                )
                .filter(account_locks::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// ── UnlockTokenRepository ──

pub(crate) struct SeaOrmUnlockTokenRepo {
    db: DatabaseConnection,
}

impl SeaOrmUnlockTokenRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmUnlockTokenRepo {}

impl UnlockTokenRepository for SeaOrmUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().fixed_offset();
            let row = unlock_tokens::Entity::find()
                .filter(unlock_tokens::Column::TokenHash.eq(&token_hash))
                .filter(unlock_tokens::Column::ExpiresAt.gt(now))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = unlock_tokens::ActiveModel {
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
            unlock_tokens::Entity::delete_many()
                .filter(unlock_tokens::Column::Id.eq(id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            unlock_tokens::Entity::delete_many()
                .filter(unlock_tokens::Column::UserId.eq(user_id))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
