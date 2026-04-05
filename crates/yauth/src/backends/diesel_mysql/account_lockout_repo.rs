use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlAccountLockRepo {
    pool: MysqlPool,
}
impl MysqlAccountLockRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlAccountLockRepo {}
impl AccountLockRepository for MysqlAccountLockRepo {
    fn find_by_user_id(&self, uid: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let u = uuid_to_str(uid);
            let r = yauth_account_locks::table
                .filter(yauth_account_locks::user_id.eq(&u))
                .select(MysqlAccountLock::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, i: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, fc, lu, lc, lr, ca, ua) = (
                uuid_to_str(i.id),
                uuid_to_str(i.user_id),
                i.failed_count,
                i.locked_until,
                i.lock_count,
                i.locked_reason,
                i.created_at,
                i.updated_at,
            );
            // MySQL: INSERT then SELECT (no RETURNING)
            diesel::sql_query(
                "INSERT INTO yauth_account_locks \
                 (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Integer, _>(fc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&lu)
            .bind::<diesel::sql_types::Integer, _>(lc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&lr)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .bind::<diesel::sql_types::Datetime, _>(&ua)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;

            let r = yauth_account_locks::table
                .find(&id)
                .select(MysqlAccountLock::as_select())
                .first(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_domain())
        })
    }
    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(yauth_account_locks::failed_count + 1),
                    yauth_account_locks::updated_at.eq(now),
                ))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn set_locked(
        &self,
        id: Uuid,
        lu: Option<NaiveDateTime>,
        lr: Option<&str>,
        lc: i32,
    ) -> RepoFuture<'_, ()> {
        let lr = lr.map(|s| s.to_string());
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::locked_until.eq(lu),
                    yauth_account_locks::locked_reason.eq(&lr),
                    yauth_account_locks::lock_count.eq(lc),
                    yauth_account_locks::updated_at.eq(now),
                ))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::updated_at.eq(now),
                ))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::locked_until.eq(None::<NaiveDateTime>),
                    yauth_account_locks::locked_reason.eq(None::<String>),
                    yauth_account_locks::updated_at.eq(now),
                ))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct MysqlUnlockTokenRepo {
    pool: MysqlPool,
}
impl MysqlUnlockTokenRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlUnlockTokenRepo {}
impl UnlockTokenRepository for MysqlUnlockTokenRepo {
    fn find_by_token_hash(&self, th: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let th = th.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = chrono::Utc::now().naive_utc();
            let r = yauth_unlock_tokens::table
                .filter(
                    yauth_unlock_tokens::token_hash
                        .eq(&th)
                        .and(yauth_unlock_tokens::expires_at.gt(now)),
                )
                .select(MysqlUnlockToken::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, i: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, th, ea, ca) = (
                uuid_to_str(i.id),
                uuid_to_str(i.user_id),
                i.token_hash,
                i.expires_at,
                i.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_unlock_tokens \
                 (id, user_id, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&th)
            .bind::<diesel::sql_types::Datetime, _>(&ea)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::delete(yauth_unlock_tokens::table.find(&ids))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete_all_for_user(&self, uid: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let u = uuid_to_str(uid);
            diesel::delete(yauth_unlock_tokens::table.filter(yauth_unlock_tokens::user_id.eq(&u)))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
