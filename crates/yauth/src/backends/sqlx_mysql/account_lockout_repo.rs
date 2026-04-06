use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};

#[derive(sqlx::FromRow)]
struct AccountLockRow {
    id: String,
    user_id: String,
    failed_count: i32,
    locked_until: Option<NaiveDateTime>,
    lock_count: i32,
    locked_reason: Option<String>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl AccountLockRow {
    fn into_domain(self) -> domain::AccountLock {
        domain::AccountLock {
            id: uuid::Uuid::parse_str(&self.id).unwrap_or_default(),
            user_id: uuid::Uuid::parse_str(&self.user_id).unwrap_or_default(),
            failed_count: self.failed_count,
            locked_until: self.locked_until,
            lock_count: self.lock_count,
            locked_reason: self.locked_reason,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct UnlockTokenRow {
    id: String,
    user_id: String,
    token_hash: String,
    expires_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

// ── AccountLock ──

pub(crate) struct SqlxMysqlAccountLockRepo {
    pool: MySqlPool,
}
impl SqlxMysqlAccountLockRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlAccountLockRepo {}

impl AccountLockRepository for SqlxMysqlAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, AccountLockRow>(
                "SELECT id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at \
                 FROM yauth_account_locks WHERE user_id = ?",
            )
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let id = input.id;
            // MySQL: no RETURNING — INSERT then SELECT
            sqlx::query(
                "INSERT INTO yauth_account_locks (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(input.user_id.to_string())
            .bind(input.failed_count)
            .bind(input.locked_until)
            .bind(input.lock_count)
            .bind(&input.locked_reason)
            .bind(input.created_at)
            .bind(input.updated_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;

            let row = sqlx::query_as::<_, AccountLockRow>(
                "SELECT id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at \
                 FROM yauth_account_locks WHERE id = ?",
            )
            .bind(id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = ? WHERE id = ?",
            )
            .bind(chrono::Utc::now().naive_utc())
            .bind(id.to_string())
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
            sqlx::query(
                "UPDATE yauth_account_locks SET locked_until = ?, locked_reason = ?, lock_count = ?, updated_at = ? WHERE id = ?",
            )
            .bind(locked_until)
            .bind(&locked_reason)
            .bind(lock_count)
            .bind(chrono::Utc::now().naive_utc())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE yauth_account_locks SET failed_count = 0, updated_at = ? WHERE id = ?",
            )
            .bind(chrono::Utc::now().naive_utc())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE yauth_account_locks SET failed_count = 0, locked_until = NULL, locked_reason = NULL, updated_at = ? WHERE id = ?",
            )
            .bind(chrono::Utc::now().naive_utc())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── UnlockToken ──

pub(crate) struct SqlxMysqlUnlockTokenRepo {
    pool: MySqlPool,
}
impl SqlxMysqlUnlockTokenRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlUnlockTokenRepo {}

impl UnlockTokenRepository for SqlxMysqlUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, UnlockTokenRow>(
                "SELECT id, user_id, token_hash, expires_at, created_at \
                 FROM yauth_unlock_tokens WHERE token_hash = ? AND expires_at > ?",
            )
            .bind(&token_hash)
            .bind(chrono::Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::UnlockToken {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                user_id: uuid::Uuid::parse_str(&r.user_id).unwrap_or_default(),
                token_hash: r.token_hash,
                expires_at: r.expires_at,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(input.user_id.to_string())
            .bind(&input.token_hash)
            .bind(input.expires_at)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_unlock_tokens WHERE id = ?")
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_unlock_tokens WHERE user_id = ?")
                .bind(user_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
