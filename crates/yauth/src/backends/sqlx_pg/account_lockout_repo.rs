use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, opt_naive_to_utc, sqlx_err};
use crate::domain;
use crate::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};

#[derive(sqlx::FromRow)]
struct AccountLockRow {
    id: Uuid,
    user_id: Uuid,
    failed_count: i32,
    locked_until: Option<DateTime<Utc>>,
    lock_count: i32,
    locked_reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AccountLockRow {
    fn into_domain(self) -> domain::AccountLock {
        domain::AccountLock {
            id: self.id,
            user_id: self.user_id,
            failed_count: self.failed_count,
            locked_until: self.locked_until.map(|dt| dt.naive_utc()),
            lock_count: self.lock_count,
            locked_reason: self.locked_reason,
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct UnlockTokenRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

// ── AccountLock ──

pub(crate) struct SqlxPgAccountLockRepo {
    pool: PgPool,
}
impl SqlxPgAccountLockRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgAccountLockRepo {}

impl AccountLockRepository for SqlxPgAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                AccountLockRow,
                r#"SELECT id, user_id as "user_id!", failed_count, locked_until, lock_count, locked_reason, created_at, updated_at
                 FROM yauth_account_locks WHERE user_id = $1"#,
                user_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let row = sqlx::query_as!(
                AccountLockRow,
                r#"INSERT INTO yauth_account_locks (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING id, user_id as "user_id!", failed_count, locked_until, lock_count, locked_reason, created_at, updated_at"#,
                input.id,
                input.user_id,
                input.failed_count,
                opt_naive_to_utc(input.locked_until) as Option<DateTime<Utc>>,
                input.lock_count,
                input.locked_reason as Option<String>,
                naive_to_utc(input.created_at),
                naive_to_utc(input.updated_at),
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = $1 WHERE id = $2",
                now,
                id
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
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET locked_until = $1, locked_reason = $2, lock_count = $3, updated_at = $4 WHERE id = $5",
                opt_naive_to_utc(locked_until) as Option<DateTime<Utc>>,
                locked_reason as Option<String>,
                lock_count,
                now,
                id,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET failed_count = 0, updated_at = $1 WHERE id = $2",
                now,
                id
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_account_locks SET failed_count = 0, locked_until = NULL, locked_reason = NULL, updated_at = $1 WHERE id = $2",
                now,
                id
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── UnlockToken ──

pub(crate) struct SqlxPgUnlockTokenRepo {
    pool: PgPool,
}
impl SqlxPgUnlockTokenRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgUnlockTokenRepo {}

impl UnlockTokenRepository for SqlxPgUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                UnlockTokenRow,
                r#"SELECT id, user_id as "user_id!", token_hash, expires_at, created_at
                   FROM yauth_unlock_tokens WHERE token_hash = $1 AND expires_at > $2"#,
                token_hash,
                now,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::UnlockToken {
                id: r.id,
                user_id: r.user_id,
                token_hash: r.token_hash,
                expires_at: r.expires_at.naive_utc(),
                created_at: r.created_at.naive_utc(),
            }))
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                input.id,
                input.user_id,
                input.token_hash,
                naive_to_utc(input.expires_at),
                naive_to_utc(input.created_at),
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!("DELETE FROM yauth_unlock_tokens WHERE id = $1", id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "DELETE FROM yauth_unlock_tokens WHERE user_id = $1",
                user_id
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
