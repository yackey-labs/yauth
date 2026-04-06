use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_dt_to_str, opt_str_to_dt, opt_str_to_json, sqlx_err, str_to_dt, str_to_uuid,
};
use crate::domain;
use crate::repo::{ApiKeyRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: Option<String>,
    user_id: Option<String>,
    key_prefix: String,
    key_hash: String,
    name: String,
    scopes: Option<String>,
    last_used_at: Option<String>,
    expires_at: Option<String>,
    created_at: String,
}

impl ApiKeyRow {
    fn into_domain(self) -> domain::ApiKey {
        domain::ApiKey {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            user_id: str_to_uuid(&self.user_id.unwrap_or_default()),
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            name: self.name,
            scopes: opt_str_to_json(self.scopes),
            last_used_at: opt_str_to_dt(self.last_used_at),
            expires_at: opt_str_to_dt(self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

pub(crate) struct SqlxSqliteApiKeyRepo {
    pool: SqlitePool,
}
impl SqlxSqliteApiKeyRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteApiKeyRepo {}

impl ApiKeyRepository for SqlxSqliteApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                ApiKeyRow,
                "SELECT id, user_id, key_prefix, key_hash, name, scopes, last_used_at, expires_at, created_at \
                 FROM yauth_api_keys WHERE key_prefix = ? /* sqlite */",
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
                 FROM yauth_api_keys WHERE id = ? AND user_id = ? /* sqlite */",
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
                 FROM yauth_api_keys WHERE user_id = ? ORDER BY created_at DESC /* sqlite */",
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
            let scopes_str = input.scopes.map(|v| v.to_string());
            let expires_str = opt_dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_api_keys (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.key_prefix,
                input.key_hash,
                input.name,
                scopes_str,
                expires_str,
                created_str,
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
                "DELETE FROM yauth_api_keys WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_api_keys SET last_used_at = ? WHERE id = ? /* sqlite */",
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
