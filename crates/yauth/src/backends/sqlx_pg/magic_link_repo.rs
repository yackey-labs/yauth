use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{MagicLinkRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct MagicLinkRow {
    id: Uuid,
    email: String,
    token_hash: String,
    expires_at: DateTime<Utc>,
    used: bool,
    created_at: DateTime<Utc>,
}

pub(crate) struct SqlxPgMagicLinkRepo {
    pool: PgPool,
}
impl SqlxPgMagicLinkRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgMagicLinkRepo {}

impl MagicLinkRepository for SqlxPgMagicLinkRepo {
    fn find_unused_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::MagicLink>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, MagicLinkRow>(
                "SELECT id, email, token_hash, expires_at, used, created_at \
                 FROM yauth_magic_links \
                 WHERE token_hash = $1 AND used = false AND expires_at > $2",
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
                expires_at: r.expires_at.naive_utc(),
                used: r.used,
                created_at: r.created_at.naive_utc(),
            }))
        })
    }

    fn create(&self, input: domain::NewMagicLink) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5)",
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
            sqlx::query("UPDATE yauth_magic_links SET used = true WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_magic_links WHERE id = $1")
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
            sqlx::query("DELETE FROM yauth_magic_links WHERE email = $1 AND used = false")
                .bind(&email)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
