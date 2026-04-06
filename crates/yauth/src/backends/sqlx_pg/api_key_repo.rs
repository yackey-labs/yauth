use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{ApiKeyRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: Uuid,
    user_id: Uuid,
    key_prefix: String,
    key_hash: String,
    name: String,
    scopes: Option<serde_json::Value>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl ApiKeyRow {
    fn into_domain(self) -> domain::ApiKey {
        domain::ApiKey {
            id: self.id,
            user_id: self.user_id,
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            name: self.name,
            scopes: self.scopes,
            last_used_at: self.last_used_at.map(|dt| dt.naive_utc()),
            expires_at: self.expires_at.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
        }
    }
}

pub(crate) struct SqlxPgApiKeyRepo {
    pool: PgPool,
}
impl SqlxPgApiKeyRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgApiKeyRepo {}

impl ApiKeyRepository for SqlxPgApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE key_prefix = $1",
            )
            .bind(&prefix)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE id = $1 AND user_id = $2",
            )
            .bind(id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let rows: Vec<ApiKeyRow> = sqlx::query_as(
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE user_id = $1 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_api_keys (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.key_prefix)
            .bind(&input.key_hash)
            .bind(&input.name)
            .bind(&input.scopes)
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
            sqlx::query("DELETE FROM yauth_api_keys WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_api_keys SET last_used_at = $1 WHERE id = $2")
                .bind(chrono::Utc::now().naive_utc())
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
