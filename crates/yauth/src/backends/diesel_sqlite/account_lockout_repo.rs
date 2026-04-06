use super::SqlitePool;
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

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_account_locks)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteAccountLock {
    pub id: String,
    pub user_id: String,
    pub failed_count: i32,
    pub locked_until: Option<String>,
    pub lock_count: i32,
    pub locked_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
impl SqliteAccountLock {
    fn into_domain(self) -> domain::AccountLock {
        domain::AccountLock {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            failed_count: self.failed_count,
            locked_until: opt_str_to_dt(self.locked_until),
            lock_count: self.lock_count,
            locked_reason: self.locked_reason,
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_unlock_tokens)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteUnlockToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}
impl SqliteUnlockToken {
    fn into_domain(self) -> domain::UnlockToken {
        domain::UnlockToken {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

pub(crate) struct SqliteAccountLockRepo {
    pool: SqlitePool,
}
impl SqliteAccountLockRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteAccountLockRepo {}
impl AccountLockRepository for SqliteAccountLockRepo {
    fn find_by_user_id(&self, uid: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let u = uuid_to_str(uid);
            let r = yauth_account_locks::table
                .filter(yauth_account_locks::user_id.eq(&u))
                .select(SqliteAccountLock::as_select())
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
                opt_dt_to_str(i.locked_until),
                i.lock_count,
                i.locked_reason,
                dt_to_str(i.created_at),
                dt_to_str(i.updated_at),
            );
            // SQLite does not support RETURNING — INSERT then SELECT
            diesel::sql_query("INSERT INTO yauth_account_locks (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Integer, _>(fc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&lu).bind::<diesel::sql_types::Integer, _>(lc).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&lr)
            .bind::<diesel::sql_types::Text, _>(&ca).bind::<diesel::sql_types::Text, _>(&ua)
            .execute(&mut *c).await.map_err(diesel_err)?;

            let r = yauth_account_locks::table
                .find(&id)
                .select(SqliteAccountLock::as_select())
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(yauth_account_locks::failed_count + 1),
                    yauth_account_locks::updated_at.eq(&now),
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::locked_until.eq(opt_dt_to_str(lu)),
                    yauth_account_locks::locked_reason.eq(&lr),
                    yauth_account_locks::lock_count.eq(lc),
                    yauth_account_locks::updated_at.eq(&now),
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::updated_at.eq(&now),
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::locked_until.eq(None::<String>),
                    yauth_account_locks::locked_reason.eq(None::<String>),
                    yauth_account_locks::updated_at.eq(&now),
                ))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct SqliteUnlockTokenRepo {
    pool: SqlitePool,
}
impl SqliteUnlockTokenRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteUnlockTokenRepo {}
impl UnlockTokenRepository for SqliteUnlockTokenRepo {
    fn find_by_token_hash(&self, th: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let th = th.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let r = yauth_unlock_tokens::table
                .filter(
                    yauth_unlock_tokens::token_hash
                        .eq(&th)
                        .and(yauth_unlock_tokens::expires_at.gt(&now)),
                )
                .select(SqliteUnlockToken::as_select())
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
                dt_to_str(i.expires_at),
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&th).bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
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
