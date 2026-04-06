use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{dt_to_str, sqlx_err, str_to_dt, str_to_uuid};
use crate::domain;
use crate::repo::{RefreshTokenRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: Option<String>,
    user_id: Option<String>,
    token_hash: String,
    family_id: String,
    expires_at: String,
    revoked: i64,
    created_at: String,
}

pub(crate) struct SqlxSqliteRefreshTokenRepo {
    pool: SqlitePool,
}
impl SqlxSqliteRefreshTokenRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteRefreshTokenRepo {}

impl RefreshTokenRepository for SqlxSqliteRefreshTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::RefreshToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                RefreshTokenRow,
                "SELECT id, user_id, token_hash, family_id, expires_at, revoked, created_at \
                 FROM yauth_refresh_tokens WHERE token_hash = ? /* sqlite */",
                token_hash
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::RefreshToken {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                token_hash: r.token_hash,
                family_id: str_to_uuid(&r.family_id),
                expires_at: str_to_dt(&r.expires_at),
                revoked: r.revoked != 0,
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewRefreshToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let family_id_str = input.family_id.to_string();
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.token_hash,
                family_id_str,
                expires_str,
                input.revoked,
                created_str,
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
                "UPDATE yauth_refresh_tokens SET revoked = true WHERE id = ? /* sqlite */",
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
                "UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = ? /* sqlite */",
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
                    "SELECT password_hash FROM yauth_passwords WHERE user_id = ? /* sqlite */",
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
