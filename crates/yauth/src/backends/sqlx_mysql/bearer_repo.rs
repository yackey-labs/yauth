use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: String,
    user_id: String,
    token_hash: String,
    family_id: String,
    expires_at: NaiveDateTime,
    revoked: bool,
    created_at: NaiveDateTime,
}

pub(crate) struct SqlxMysqlRefreshTokenRepo {
    pool: MySqlPool,
}
impl SqlxMysqlRefreshTokenRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlRefreshTokenRepo {}

impl RefreshTokenRepository for SqlxMysqlRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, RefreshTokenRow>(
                "SELECT id, user_id, token_hash, family_id, expires_at, revoked, created_at \
                 FROM yauth_refresh_tokens WHERE token_hash = ?",
            )
            .bind(&token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::RefreshToken {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                user_id: uuid::Uuid::parse_str(&r.user_id).unwrap_or_default(),
                token_hash: r.token_hash,
                family_id: uuid::Uuid::parse_str(&r.family_id).unwrap_or_default(),
                expires_at: r.expires_at,
                revoked: r.revoked,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(input.user_id.to_string())
            .bind(&input.token_hash)
            .bind(input.family_id.to_string())
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
            sqlx::query("UPDATE yauth_refresh_tokens SET revoked = true WHERE id = ?")
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = ?")
                .bind(family_id.to_string())
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
                    sqlx::query_as("SELECT password_hash FROM yauth_passwords WHERE user_id = ?")
                        .bind(user_id.to_string())
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
