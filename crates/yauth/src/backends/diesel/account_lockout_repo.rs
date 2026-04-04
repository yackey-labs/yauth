use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{AccountLockRepository, RepoError, RepoFuture, UnlockTokenRepository, sealed};
use crate::state::DbPool;

pub(crate) struct DieselAccountLockRepo {
    pool: DbPool,
}
impl DieselAccountLockRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselAccountLockRepo {}

impl AccountLockRepository for DieselAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_account_locks::table
                .filter(yauth_account_locks::user_id.eq(user_id))
                .select(DieselAccountLock::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let diesel_input = DieselNewAccountLock::from_domain(input);
            let result = diesel::insert_into(yauth_account_locks::table)
                .values(&diesel_input)
                .returning(DieselAccountLock::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.into_domain())
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(id)))
                .set((
                    yauth_account_locks::failed_count.eq(yauth_account_locks::failed_count + 1),
                    yauth_account_locks::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
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
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(id)))
                .set((
                    yauth_account_locks::locked_until.eq(locked_until),
                    yauth_account_locks::locked_reason.eq(&locked_reason),
                    yauth_account_locks::lock_count.eq(lock_count),
                    yauth_account_locks::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(id)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(id)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::locked_until.eq(None::<NaiveDateTime>),
                    yauth_account_locks::locked_reason.eq(None::<String>),
                    yauth_account_locks::updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}

pub(crate) struct DieselUnlockTokenRepo {
    pool: DbPool,
}
impl DieselUnlockTokenRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselUnlockTokenRepo {}

impl UnlockTokenRepository for DieselUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            let result = yauth_unlock_tokens::table
                .filter(
                    yauth_unlock_tokens::token_hash
                        .eq(&token_hash)
                        .and(yauth_unlock_tokens::expires_at.gt(chrono::Utc::now().naive_utc())),
                )
                .select(DieselUnlockToken::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::insert_into(yauth_unlock_tokens::table)
                .values(&DieselNewUnlockToken::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::delete(yauth_unlock_tokens::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| RepoError::Internal(e.into()))?;
            diesel::delete(
                yauth_unlock_tokens::table.filter(yauth_unlock_tokens::user_id.eq(user_id)),
            )
            .execute(&mut conn)
            .await
            .map_err(|e| RepoError::Internal(e.into()))?;
            Ok(())
        })
    }
}
