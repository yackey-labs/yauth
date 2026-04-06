use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{dt_to_str, sqlx_err, str_to_dt, str_to_uuid};
use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct MagicLinkRow {
    id: Option<String>,
    email: String,
    token_hash: String,
    expires_at: String,
    used: i64,
    created_at: String,
}

pub(crate) struct SqlxSqliteMagicLinkRepo {
    pool: SqlitePool,
}
impl SqlxSqliteMagicLinkRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteMagicLinkRepo {}

impl MagicLinkRepository for SqlxSqliteMagicLinkRepo {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                MagicLinkRow,
                "SELECT id, email, token_hash, expires_at, used, created_at \
                 FROM yauth_magic_links \
                 WHERE token_hash = ? AND used = false AND expires_at > ? /* sqlite */",
                token_hash,
                now
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::MagicLink {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                email: r.email,
                token_hash: r.token_hash,
                expires_at: str_to_dt(&r.expires_at),
                used: r.used != 0,
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                input.email,
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

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "UPDATE yauth_magic_links SET used = true WHERE id = ? /* sqlite */",
                id_str
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
                "DELETE FROM yauth_magic_links WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let email = email.to_string();
        Box::pin(async move {
            sqlx::query!(
                "DELETE FROM yauth_magic_links WHERE email = ? AND used = false /* sqlite */",
                email
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
