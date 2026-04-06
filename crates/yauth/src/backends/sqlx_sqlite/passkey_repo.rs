use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{dt_to_str, opt_str_to_dt, sqlx_err, str_to_dt, str_to_uuid};
use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct PasskeyRow {
    id: Option<String>,
    user_id: Option<String>,
    name: String,
    aaguid: Option<String>,
    device_name: Option<String>,
    credential: String,
    created_at: String,
    last_used_at: Option<String>,
}

impl PasskeyRow {
    fn into_domain(self) -> domain::WebauthnCredential {
        domain::WebauthnCredential {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            user_id: str_to_uuid(&self.user_id.unwrap_or_default()),
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: serde_json::from_str(&self.credential).unwrap_or_default(),
            created_at: str_to_dt(&self.created_at),
            last_used_at: opt_str_to_dt(self.last_used_at),
        }
    }
}

pub(crate) struct SqlxSqlitePasskeyRepo {
    pool: SqlitePool,
}
impl SqlxSqlitePasskeyRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqlitePasskeyRepo {}

impl PasskeyRepository for SqlxSqlitePasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let rows = sqlx::query_as!(
                PasskeyRow,
                "SELECT id, user_id, name, aaguid, device_name, credential, created_at, last_used_at \
                 FROM yauth_webauthn_credentials WHERE user_id = ? /* sqlite */",
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
                 FROM yauth_webauthn_credentials WHERE id = ? AND user_id = ? /* sqlite */",
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
            let credential_str = input.credential.to_string();
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.name,
                input.aaguid,
                input.device_name,
                credential_str,
                created_str,
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_webauthn_credentials SET last_used_at = ? WHERE user_id = ? /* sqlite */",
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
                "DELETE FROM yauth_webauthn_credentials WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
