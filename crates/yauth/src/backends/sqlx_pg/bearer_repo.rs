use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    family_id: Uuid,
    expires_at: DateTime<Utc>,
    revoked: bool,
    created_at: DateTime<Utc>,
}

pub(crate) struct SqlxPgRefreshTokenRepo {
    pool: PgPool,
}
impl SqlxPgRefreshTokenRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgRefreshTokenRepo {}

impl RefreshTokenRepository for SqlxPgRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, RefreshTokenRow>(
                "SELECT id, user_id, token_hash, family_id, expires_at, revoked, created_at \
                 FROM yauth_refresh_tokens WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::RefreshToken {
                id: r.id,
                user_id: r.user_id,
                token_hash: r.token_hash,
                family_id: r.family_id,
                expires_at: r.expires_at.naive_utc(),
                revoked: r.revoked,
                created_at: r.created_at.naive_utc(),
            }))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.token_hash)
            .bind(input.family_id)
            .bind(input.expires_at)
            .bind(input.revoked)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_refresh_tokens SET revoked = true WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = $1")
                .bind(family_id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn find_password_hash_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<String>> {
        Box::pin(async move {
            #[cfg(feature = "email-password")]
            {
                let row: Option<(String,)> =
                    sqlx::query_as("SELECT password_hash FROM yauth_passwords WHERE user_id = $1")
                        .bind(user_id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(sqlx_err)?;
                Ok(row.map(|r| r.0))
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}
