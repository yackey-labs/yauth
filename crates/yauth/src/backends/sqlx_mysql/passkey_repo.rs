use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_err, str_to_uuid};
use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct PasskeyRow {
    id: String,
    user_id: Option<String>,
    name: String,
    aaguid: Option<String>,
    device_name: Option<String>,
    credential: serde_json::Value,
    created_at: NaiveDateTime,
    last_used_at: Option<NaiveDateTime>,
}

impl PasskeyRow {
    fn into_domain(self) -> domain::WebauthnCredential {
        domain::WebauthnCredential {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id.unwrap_or_default()),
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: self.credential,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

pub(crate) struct SqlxMysqlPasskeyRepo {
    pool: MySqlPool,
}
impl SqlxMysqlPasskeyRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlPasskeyRepo {}

impl PasskeyRepository for SqlxMysqlPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let rows = sqlx::query_as!(
                PasskeyRow,
                "SELECT id, user_id, name, aaguid, device_name, credential, created_at, last_used_at \
                 FROM yauth_webauthn_credentials WHERE user_id = ?",
                user_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>> {
        Box::pin(async move {
            let id_str = id.to_string();
            let user_id_str = user_id.to_string();
            let row = sqlx::query_as!(
                PasskeyRow,
                "SELECT id, user_id, name, aaguid, device_name, credential, created_at, last_used_at \
                 FROM yauth_webauthn_credentials WHERE id = ? AND user_id = ?",
                id_str,
                user_id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            sqlx::query!(
                "INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.name,
                input.aaguid,
                input.device_name,
                input.credential,
                input.created_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let now = chrono::Utc::now().naive_utc();
            sqlx::query!(
                "UPDATE yauth_webauthn_credentials SET last_used_at = ? WHERE user_id = ?",
                now,
                user_id_str
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
                "DELETE FROM yauth_webauthn_credentials WHERE id = ?",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
