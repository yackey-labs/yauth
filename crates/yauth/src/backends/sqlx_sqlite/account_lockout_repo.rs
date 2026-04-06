use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_dt_to_str, opt_str_to_dt, sqlx_err, str_to_dt, str_to_uuid,
};
use crate::domain;
use crate::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};

#[derive(sqlx::FromRow)]
struct AccountLockRow {
    id: Option<String>,
    user_id: Option<String>,
    failed_count: i64,
    locked_until: Option<String>,
    lock_count: i64,
    locked_reason: Option<String>,
    created_at: String,
    updated_at: String,
}

impl AccountLockRow {
    fn into_domain(self) -> domain::AccountLock {
        domain::AccountLock {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            user_id: str_to_uuid(&self.user_id.unwrap_or_default()),
            failed_count: self.failed_count as i32,
            locked_until: opt_str_to_dt(self.locked_until),
            lock_count: self.lock_count as i32,
            locked_reason: self.locked_reason,
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}

#[derive(sqlx::FromRow)]
struct UnlockTokenRow {
    id: Option<String>,
    user_id: Option<String>,
    token_hash: String,
    expires_at: String,
    created_at: String,
}

pub(crate) struct SqlxSqliteAccountLockRepo {
    pool: SqlitePool,
}
impl SqlxSqliteAccountLockRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteAccountLockRepo {}

impl AccountLockRepository for SqlxSqliteAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let row = sqlx::query_as!(
                AccountLockRow,
                "SELECT id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at \
                 FROM yauth_account_locks WHERE user_id = ? /* sqlite */",
                user_id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let locked_until_str = opt_dt_to_str(input.locked_until);
            let created_str = dt_to_str(input.created_at);
            let updated_str = dt_to_str(input.updated_at);
            let row = sqlx::query_as!(
                AccountLockRow,
                "INSERT INTO yauth_account_locks (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at /* sqlite */",
                id_str,
                user_id_str,
                input.failed_count,
                locked_until_str,
                input.lock_count,
                input.locked_reason,
                created_str,
                updated_str,
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = ? WHERE id = ? /* sqlite */",
                now,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
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
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let locked_until_str = opt_dt_to_str(locked_until);
            sqlx::query!(
                "UPDATE yauth_account_locks SET locked_until = ?, locked_reason = ?, lock_count = ?, updated_at = ? WHERE id = ? /* sqlite */",
                locked_until_str,
                locked_reason,
                lock_count,
                now,
                id_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET failed_count = 0, updated_at = ? WHERE id = ? /* sqlite */",
                now,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET failed_count = 0, locked_until = NULL, locked_reason = NULL, updated_at = ? WHERE id = ? /* sqlite */",
                now,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

pub(crate) struct SqlxSqliteUnlockTokenRepo {
    pool: SqlitePool,
}
impl SqlxSqliteUnlockTokenRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteUnlockTokenRepo {}

impl UnlockTokenRepository for SqlxSqliteUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                UnlockTokenRow,
                "SELECT id, user_id, token_hash, expires_at, created_at \
                 FROM yauth_unlock_tokens WHERE token_hash = ? AND expires_at > ? /* sqlite */",
                token_hash,
                now
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::UnlockToken {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                token_hash: r.token_hash,
                expires_at: str_to_dt(&r.expires_at),
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.token_hash,
                expires_str,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_unlock_tokens WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_unlock_tokens WHERE user_id = ? /* sqlite */",
                user_id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
