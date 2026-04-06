use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};

// ── Row types ──

#[derive(sqlx::FromRow)]
struct Oauth2ClientRow {
    id: String,
    client_id: String,
    client_secret_hash: Option<String>,
    redirect_uris: serde_json::Value,
    client_name: Option<String>,
    grant_types: serde_json::Value,
    scopes: Option<serde_json::Value>,
    is_public: bool,
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct AuthorizationCodeRow {
    id: String,
    code_hash: String,
    client_id: String,
    user_id: String,
    scopes: Option<serde_json::Value>,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: NaiveDateTime,
    used: bool,
    nonce: Option<String>,
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct ConsentRow {
    id: String,
    user_id: String,
    client_id: String,
    scopes: Option<serde_json::Value>,
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct DeviceCodeRow {
    id: String,
    device_code_hash: String,
    user_code: String,
    client_id: String,
    scopes: Option<serde_json::Value>,
    user_id: Option<String>,
    status: String,
    interval: i32,
    expires_at: NaiveDateTime,
    last_polled_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

// ── Oauth2Client ──

pub(crate) struct SqlxMysqlOauth2ClientRepo {
    pool: MySqlPool,
}
impl SqlxMysqlOauth2ClientRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlOauth2ClientRepo {}

impl Oauth2ClientRepository for SqlxMysqlOauth2ClientRepo {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, Oauth2ClientRow>(
                "SELECT id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at \
                 FROM yauth_oauth2_clients WHERE client_id = ?",
            )
            .bind(&client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::Oauth2Client {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                client_id: r.client_id,
                client_secret_hash: r.client_secret_hash,
                redirect_uris: r.redirect_uris,
                client_name: r.client_name,
                grant_types: r.grant_types,
                scopes: r.scopes,
                is_public: r.is_public,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(&input.client_id)
            .bind(&input.client_secret_hash)
            .bind(&input.redirect_uris)
            .bind(&input.client_name)
            .bind(&input.grant_types)
            .bind(&input.scopes)
            .bind(input.is_public)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── AuthorizationCode ──

pub(crate) struct SqlxMysqlAuthorizationCodeRepo {
    pool: MySqlPool,
}
impl SqlxMysqlAuthorizationCodeRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlAuthorizationCodeRepo {}

impl AuthorizationCodeRepository for SqlxMysqlAuthorizationCodeRepo {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let code_hash = code_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, AuthorizationCodeRow>(
                "SELECT id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at \
                 FROM yauth_authorization_codes \
                 WHERE code_hash = ? AND used = false AND expires_at > ?",
            )
            .bind(&code_hash)
            .bind(chrono::Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::AuthorizationCode {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                code_hash: r.code_hash,
                client_id: r.client_id,
                user_id: uuid::Uuid::parse_str(&r.user_id).unwrap_or_default(),
                scopes: r.scopes,
                redirect_uri: r.redirect_uri,
                code_challenge: r.code_challenge,
                code_challenge_method: r.code_challenge_method,
                expires_at: r.expires_at,
                used: r.used,
                nonce: r.nonce,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(&input.code_hash)
            .bind(&input.client_id)
            .bind(input.user_id.to_string())
            .bind(&input.scopes)
            .bind(&input.redirect_uri)
            .bind(&input.code_challenge)
            .bind(&input.code_challenge_method)
            .bind(input.expires_at)
            .bind(input.used)
            .bind(&input.nonce)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_authorization_codes SET used = true WHERE id = ?")
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── Consent ──

pub(crate) struct SqlxMysqlConsentRepo {
    pool: MySqlPool,
}
impl SqlxMysqlConsentRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlConsentRepo {}

impl ConsentRepository for SqlxMysqlConsentRepo {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, ConsentRow>(
                "SELECT id, user_id, client_id, scopes, created_at \
                 FROM yauth_consents WHERE user_id = ? AND client_id = ?",
            )
            .bind(user_id.to_string())
            .bind(&client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::Consent {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                user_id: uuid::Uuid::parse_str(&r.user_id).unwrap_or_default(),
                client_id: r.client_id,
                scopes: r.scopes,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(input.user_id.to_string())
            .bind(&input.client_id)
            .bind(&input.scopes)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_consents SET scopes = ? WHERE id = ?")
                .bind(&scopes)
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── DeviceCode ──

pub(crate) struct SqlxMysqlDeviceCodeRepo {
    pool: MySqlPool,
}
impl SqlxMysqlDeviceCodeRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlDeviceCodeRepo {}

impl DeviceCodeRepository for SqlxMysqlDeviceCodeRepo {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let user_code = user_code.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, DeviceCodeRow>(
                "SELECT id, device_code_hash, user_code, client_id, scopes, user_id, status, `interval`, expires_at, last_polled_at, created_at \
                 FROM yauth_device_codes \
                 WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
            )
            .bind(&user_code)
            .bind(chrono::Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::DeviceCode {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                device_code_hash: r.device_code_hash,
                user_code: r.user_code,
                client_id: r.client_id,
                scopes: r.scopes,
                user_id: r
                    .user_id
                    .as_deref()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok()),
                status: r.status,
                interval: r.interval,
                expires_at: r.expires_at,
                last_polled_at: r.last_polled_at,
                created_at: r.created_at,
            }))
        })
    }

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let device_code_hash = device_code_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, DeviceCodeRow>(
                "SELECT id, device_code_hash, user_code, client_id, scopes, user_id, status, `interval`, expires_at, last_polled_at, created_at \
                 FROM yauth_device_codes WHERE device_code_hash = ?",
            )
            .bind(&device_code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::DeviceCode {
                id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
                device_code_hash: r.device_code_hash,
                user_code: r.user_code,
                client_id: r.client_id,
                scopes: r.scopes,
                user_id: r
                    .user_id
                    .as_deref()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok()),
                status: r.status,
                interval: r.interval,
                expires_at: r.expires_at,
                last_polled_at: r.last_polled_at,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, user_id, status, `interval`, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(input.id.to_string())
            .bind(&input.device_code_hash)
            .bind(&input.user_code)
            .bind(&input.client_id)
            .bind(&input.scopes)
            .bind(input.user_id.map(|u| u.to_string()))
            .bind(&input.status)
            .bind(input.interval)
            .bind(input.expires_at)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()> {
        let status = status.to_string();
        Box::pin(async move {
            sqlx::query("UPDATE yauth_device_codes SET status = ?, user_id = ? WHERE id = ?")
                .bind(&status)
                .bind(user_id.map(|u| u.to_string()))
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_device_codes SET last_polled_at = ? WHERE id = ?")
                .bind(chrono::Utc::now().naive_utc())
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_device_codes SET `interval` = ? WHERE id = ?")
                .bind(interval)
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
