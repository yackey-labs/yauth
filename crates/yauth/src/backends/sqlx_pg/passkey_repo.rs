use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};

#[derive(sqlx::FromRow)]
struct PasskeyRow {
    id: Uuid,
    user_id: Uuid,
    name: String,
    aaguid: Option<String>,
    device_name: Option<String>,
    credential: serde_json::Value,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl PasskeyRow {
    fn into_domain(self) -> domain::WebauthnCredential {
        domain::WebauthnCredential {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: self.credential,
            created_at: self.created_at.naive_utc(),
            last_used_at: self.last_used_at.map(|dt| dt.naive_utc()),
        }
    }
}

pub(crate) struct SqlxPgPasskeyRepo {
    pool: PgPool,
}
impl SqlxPgPasskeyRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxPgPasskeyRepo {}

impl PasskeyRepository for SqlxPgPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let rows: Vec<PasskeyRow> = sqlx::query_as(
                "SELECT id, user_id, name, aaguid, device_name, credential, created_at, last_used_at \
                 FROM yauth_webauthn_credentials WHERE user_id = $1",
            )
            .bind(user_id)
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
            let row = sqlx::query_as::<_, PasskeyRow>(
                "SELECT id, user_id, name, aaguid, device_name, credential, created_at, last_used_at \
                 FROM yauth_webauthn_credentials WHERE id = $1 AND user_id = $2",
            )
            .bind(id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.name)
            .bind(&input.aaguid)
            .bind(&input.device_name)
            .bind(&input.credential)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE yauth_webauthn_credentials SET last_used_at = $1 WHERE user_id = $2",
            )
            .bind(chrono::Utc::now().naive_utc())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_webauthn_credentials WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
