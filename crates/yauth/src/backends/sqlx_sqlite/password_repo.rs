use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{dt_to_str, opt_str_to_dt, sqlx_err, str_to_dt, str_to_uuid};
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
            let user_id_str = user_id.to_string();
            let row = sqlx::query!(
                "SELECT user_id, password_hash FROM yauth_passwords WHERE user_id = ? /* sqlite */",
                user_id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::Password {
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                password_hash: r.password_hash,
            }))
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let user_id_str = input.user_id.to_string();
            sqlx::query!(
                "INSERT INTO yauth_passwords (user_id, password_hash) VALUES (?, ?) \
                 ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash /* sqlite */",
                user_id_str,
                input.password_hash,
            )
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
    id: Option<String>,
    user_id: Option<String>,
    token_hash: String,
    expires_at: String,
    created_at: String,
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                EmailVerificationRow,
                "SELECT id, user_id, token_hash, expires_at, created_at \
                 FROM yauth_email_verifications \
                 WHERE token_hash = ? AND expires_at > ? /* sqlite */",
                token_hash,
                now,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::EmailVerification {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                token_hash: r.token_hash,
                expires_at: str_to_dt(&r.expires_at),
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_email_verifications (id, user_id, token_hash, expires_at, created_at) \
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
                "DELETE FROM yauth_email_verifications WHERE id = ? /* sqlite */",
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
                "DELETE FROM yauth_email_verifications WHERE user_id = ? /* sqlite */",
                user_id_str
            )
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
    id: Option<String>,
    user_id: Option<String>,
    token_hash: String,
    expires_at: String,
    used_at: Option<String>,
    created_at: String,
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                PasswordResetRow,
                "SELECT id, user_id, token_hash, expires_at, used_at, created_at \
                 FROM yauth_password_resets \
                 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? /* sqlite */",
                token_hash,
                now,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::PasswordReset {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                token_hash: r.token_hash,
                expires_at: str_to_dt(&r.expires_at),
                used_at: opt_str_to_dt(r.used_at),
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at) \
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

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_password_resets WHERE user_id = ? AND used_at IS NULL /* sqlite */",
                user_id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
