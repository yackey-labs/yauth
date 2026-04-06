use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{naive_to_utc, sqlx_err};
use crate::domain;
use crate::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};

// ── Password ──

pub(crate) struct SqlxPgPasswordRepo {
    pool: PgPool,
}
impl SqlxPgPasswordRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgPasswordRepo {}

impl PasswordRepository for SqlxPgPasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let row = sqlx::query!(
                "SELECT user_id, password_hash FROM yauth_passwords WHERE user_id = $1",
                user_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::Password {
                user_id: r.user_id,
                password_hash: r.password_hash,
            }))
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_passwords (user_id, password_hash) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash",
                input.user_id,
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
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

pub(crate) struct SqlxPgEmailVerificationRepo {
    pool: PgPool,
}
impl SqlxPgEmailVerificationRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgEmailVerificationRepo {}

impl EmailVerificationRepository for SqlxPgEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                EmailVerificationRow,
                r#"SELECT id, user_id as "user_id!", token_hash, expires_at, created_at
                   FROM yauth_email_verifications
                   WHERE token_hash = $1 AND expires_at > $2"#,
                token_hash,
                now,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::EmailVerification {
                id: r.id,
                user_id: r.user_id,
                token_hash: r.token_hash,
                expires_at: r.expires_at.naive_utc(),
                created_at: r.created_at.naive_utc(),
            }))
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_email_verifications (id, user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)",
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
            sqlx::query!("DELETE FROM yauth_email_verifications WHERE id = $1", id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "DELETE FROM yauth_email_verifications WHERE user_id = $1",
                user_id
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
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

pub(crate) struct SqlxPgPasswordResetRepo {
    pool: PgPool,
}
impl SqlxPgPasswordResetRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgPasswordResetRepo {}

impl PasswordResetRepository for SqlxPgPasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = naive_to_utc(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                PasswordResetRow,
                r#"SELECT id, user_id as "user_id!", token_hash, expires_at, used_at, created_at
                   FROM yauth_password_resets
                   WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2"#,
                token_hash,
                now,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::PasswordReset {
                id: r.id,
                user_id: r.user_id,
                token_hash: r.token_hash,
                expires_at: r.expires_at.naive_utc(),
                used_at: r.used_at.map(|dt| dt.naive_utc()),
                created_at: r.created_at.naive_utc(),
            }))
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)",
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

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query!(
                "DELETE FROM yauth_password_resets WHERE user_id = $1 AND used_at IS NULL",
                user_id
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
