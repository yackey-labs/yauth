use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_err, str_to_uuid};
use crate::domain;
use crate::repo::{ApiKeyRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    user_id: Option<String>,
    key_prefix: String,
    key_hash: String,
    name: String,
    scopes: Option<serde_json::Value>,
    last_used_at: Option<NaiveDateTime>,
    expires_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

impl ApiKeyRow {
    fn into_domain(self) -> domain::ApiKey {
        domain::ApiKey {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id.unwrap_or_default()),
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            name: self.name,
            scopes: self.scopes,
            last_used_at: self.last_used_at,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

pub(crate) struct SqlxMysqlApiKeyRepo {
    pool: MySqlPool,
}
impl SqlxMysqlApiKeyRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlApiKeyRepo {}

impl ApiKeyRepository for SqlxMysqlApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                ApiKeyRow,
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE key_prefix = ?",
                prefix
            )
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
            let id_str = id.to_string();
            let user_id_str = user_id.to_string();
            let row = sqlx::query_as!(
                ApiKeyRow,
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE id = ? AND user_id = ?",
                id_str,
                user_id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let rows = sqlx::query_as!(
                ApiKeyRow,
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE user_id = ? ORDER BY created_at DESC",
                user_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            sqlx::query!(
                "INSERT INTO yauth_api_keys (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.key_prefix,
                input.key_hash,
                input.name,
                input.scopes,
                input.expires_at,
                input.created_at,
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
            sqlx::query!("DELETE FROM yauth_api_keys WHERE id = ?", id_str)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let now = chrono::Utc::now().naive_utc();
            sqlx::query!(
                "UPDATE yauth_api_keys SET last_used_at = ? WHERE id = ?",
                now,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
