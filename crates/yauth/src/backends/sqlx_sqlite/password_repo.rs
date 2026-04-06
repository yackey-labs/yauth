use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};

// ── Password ──

pub(crate) struct SqlxSqlitePasswordRepo {
    pool: SqlitePool,
}
impl SqlxSqlitePasswordRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqlitePasswordRepo {}

impl PasswordRepository for SqlxSqlitePasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let row: Option<(Uuid, String)> = sqlx::query_as(
                "SELECT user_id, password_hash FROM yauth_passwords WHERE user_id = ?",
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|(user_id, password_hash)| domain::Password {
                user_id,
                password_hash,
            }))
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_passwords (user_id, password_hash) VALUES (?, ?) \
                 ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash",
            )
            .bind(input.user_id)
            .bind(&input.password_hash)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── Email Verification ──

#[derive(sqlx::FromRow)]
struct EmailVerificationRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

pub(crate) struct SqlxSqliteEmailVerificationRepo {
    pool: SqlitePool,
}
impl SqlxSqliteEmailVerificationRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteEmailVerificationRepo {}

impl EmailVerificationRepository for SqlxSqliteEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, EmailVerificationRow>(
                "SELECT id, user_id, token_hash, expires_at, created_at \
                 FROM yauth_email_verifications \
                 WHERE token_hash = ? AND expires_at > ?",
            )
            .bind(&token_hash)
            .bind(chrono::Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::EmailVerification {
                id: r.id,
                user_id: r.user_id,
                token_hash: r.token_hash,
                expires_at: r.expires_at,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_email_verifications (id, user_id, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id)
            .bind(input.user_id)
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
            sqlx::query("DELETE FROM yauth_email_verifications WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_email_verifications WHERE user_id = ?")
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── Password Reset ──

#[derive(sqlx::FromRow)]
struct PasswordResetRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: NaiveDateTime,
    used_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

pub(crate) struct SqlxSqlitePasswordResetRepo {
    pool: SqlitePool,
}
impl SqlxSqlitePasswordResetRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqlitePasswordResetRepo {}

impl PasswordResetRepository for SqlxSqlitePasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, PasswordResetRow>(
                "SELECT id, user_id, token_hash, expires_at, used_at, created_at \
                 FROM yauth_password_resets \
                 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
            )
            .bind(&token_hash)
            .bind(chrono::Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::PasswordReset {
                id: r.id,
                user_id: r.user_id,
                token_hash: r.token_hash,
                expires_at: r.expires_at,
                used_at: r.used_at,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.token_hash)
            .bind(input.expires_at)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_password_resets WHERE user_id = ? AND used_at IS NULL")
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
