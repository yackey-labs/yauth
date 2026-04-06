use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct MagicLinkRow {
    id: Uuid,
    email: String,
    token_hash: String,
    expires_at: NaiveDateTime,
    used: bool,
    created_at: NaiveDateTime,
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
            let row = sqlx::query_as::<_, MagicLinkRow>(
                "SELECT id, email, token_hash, expires_at, used, created_at \
                 FROM yauth_magic_links \
                 WHERE token_hash = ? AND used = false AND expires_at > ?",
            )
            .bind(&token_hash)
            .bind(chrono::Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::MagicLink {
                id: r.id,
                email: r.email,
                token_hash: r.token_hash,
                expires_at: r.expires_at,
                used: r.used,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id)
            .bind(&input.email)
            .bind(&input.token_hash)
            .bind(input.expires_at)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_magic_links SET used = true WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_magic_links WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_email(&self, email: &str) -> RepoFuture<'_, ()> {
        let email = email.to_string();
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_magic_links WHERE email = ? AND used = false")
                .bind(&email)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
