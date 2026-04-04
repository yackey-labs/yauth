use super::LibsqlPool;
use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{AccountLockRepository, RepoError, RepoFuture, UnlockTokenRepository, sealed};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_account_locks)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct Lal {
    pub id: String,
    pub user_id: String,
    pub failed_count: i32,
    pub locked_until: Option<String>,
    pub lock_count: i32,
    pub locked_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
impl Lal {
    fn d(self) -> domain::AccountLock {
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
#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct LalByName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub user_id: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub failed_count: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub locked_until: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub lock_count: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub locked_reason: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub created_at: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub updated_at: String,
}
impl LalByName {
    fn d(self) -> domain::AccountLock {
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
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct Lut {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}
impl Lut {
    fn d(self) -> domain::UnlockToken {
        domain::UnlockToken {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

fn pe(e: impl std::fmt::Display) -> RepoError {
    RepoError::Internal(format!("{e}").into())
}
fn de(e: diesel::result::Error) -> RepoError {
    RepoError::Internal(e.into())
}

pub(crate) struct LibsqlAccountLockRepo {
    pool: LibsqlPool,
}
impl LibsqlAccountLockRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlAccountLockRepo {}
impl AccountLockRepository for LibsqlAccountLockRepo {
    fn find_by_user_id(&self, uid: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let u = uuid_to_str(uid);
            let r = yauth_account_locks::table
                .filter(yauth_account_locks::user_id.eq(&u))
                .select(Lal::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(de)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn create(&self, i: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
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
            let r: LalByName = diesel::sql_query("INSERT INTO yauth_account_locks (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Integer, _>(fc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&lu).bind::<diesel::sql_types::Integer, _>(lc).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&lr)
            .bind::<diesel::sql_types::Text, _>(&ca).bind::<diesel::sql_types::Text, _>(&ua)
            .get_result(&mut *c).await.map_err(de)?;
            Ok(r.d())
        })
    }
    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let ids = uuid_to_str(id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(yauth_account_locks::failed_count + 1),
                    yauth_account_locks::updated_at.eq(&now),
                ))
                .execute(&mut *c)
                .await
                .map_err(de)?;
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
            let mut c = self.pool.get().await.map_err(pe)?;
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
                .map_err(de)?;
            Ok(())
        })
    }
    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let ids = uuid_to_str(id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_account_locks::table.filter(yauth_account_locks::id.eq(&ids)))
                .set((
                    yauth_account_locks::failed_count.eq(0),
                    yauth_account_locks::updated_at.eq(&now),
                ))
                .execute(&mut *c)
                .await
                .map_err(de)?;
            Ok(())
        })
    }
    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
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
                .map_err(de)?;
            Ok(())
        })
    }
}

pub(crate) struct LibsqlUnlockTokenRepo {
    pool: LibsqlPool,
}
impl LibsqlUnlockTokenRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlUnlockTokenRepo {}
impl UnlockTokenRepository for LibsqlUnlockTokenRepo {
    fn find_by_token_hash(&self, th: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let th = th.to_string();
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let r = yauth_unlock_tokens::table
                .filter(
                    yauth_unlock_tokens::token_hash
                        .eq(&th)
                        .and(yauth_unlock_tokens::expires_at.gt(&now)),
                )
                .select(Lut::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(de)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn create(&self, i: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let (id, uid, th, ea, ca) = (
                uuid_to_str(i.id),
                uuid_to_str(i.user_id),
                i.token_hash,
                dt_to_str(i.expires_at),
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&th).bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(de)?;
            Ok(())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let ids = uuid_to_str(id);
            diesel::delete(yauth_unlock_tokens::table.find(&ids))
                .execute(&mut *c)
                .await
                .map_err(de)?;
            Ok(())
        })
    }
    fn delete_all_for_user(&self, uid: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = self.pool.get().await.map_err(pe)?;
            let u = uuid_to_str(uid);
            diesel::delete(yauth_unlock_tokens::table.filter(yauth_unlock_tokens::user_id.eq(&u)))
                .execute(&mut *c)
                .await
                .map_err(de)?;
            Ok(())
        })
    }
}
