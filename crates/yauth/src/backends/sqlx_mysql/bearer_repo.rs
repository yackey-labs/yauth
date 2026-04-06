use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_err, str_to_uuid};
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: String,
    user_id: Option<String>,
    token_hash: String,
    family_id: String,
    expires_at: NaiveDateTime,
    revoked: i8,
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
            let row = sqlx::query_as!(
                RefreshTokenRow,
                "SELECT id, user_id, token_hash, family_id, expires_at, revoked, created_at \
                 FROM yauth_refresh_tokens WHERE token_hash = ?",
                token_hash
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::RefreshToken {
                id: str_to_uuid(&r.id),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                token_hash: r.token_hash,
                family_id: str_to_uuid(&r.family_id),
                expires_at: r.expires_at,
                revoked: r.revoked != 0,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let family_id_str = input.family_id.to_string();
            sqlx::query!(
                "INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.token_hash,
                family_id_str,
                input.expires_at,
                input.revoked,
                input.created_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn revoke(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "UPDATE yauth_refresh_tokens SET revoked = true WHERE id = ?",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn revoke_family(&self, family_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let family_id_str = family_id.to_string();
            sqlx::query!(
                "UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = ?",
                family_id_str
            )
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
                let user_id_str = user_id.to_string();
                let row = sqlx::query!(
                    "SELECT password_hash FROM yauth_passwords WHERE user_id = ?",
                    user_id_str
                )
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
                Ok(row.map(|r| r.password_hash))
            }
            #[cfg(not(feature = "email-password"))]
            {
                let _ = user_id;
                Ok(None)
            }
        })
    }
}
