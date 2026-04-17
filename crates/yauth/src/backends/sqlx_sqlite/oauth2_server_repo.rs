use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_str_to_dt, opt_str_to_json, opt_str_to_uuid, sqlx_err, str_to_dt, str_to_uuid,
};
use crate::domain;
use crate::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};

#[derive(sqlx::FromRow)]
struct Oauth2ClientRow {
    id: Option<String>,
    client_id: String,
    client_secret_hash: Option<String>,
    redirect_uris: String,
    client_name: Option<String>,
    grant_types: String,
    scopes: Option<String>,
    is_public: i64,
    created_at: String,
    token_endpoint_auth_method: Option<String>,
    public_key_pem: Option<String>,
    jwks_uri: Option<String>,
    banned_at: Option<String>,
    banned_reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AuthorizationCodeRow {
    id: Option<String>,
    code_hash: String,
    client_id: String,
    user_id: Option<String>,
    scopes: Option<String>,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: String,
    used: i64,
    nonce: Option<String>,
    created_at: String,
}

#[derive(sqlx::FromRow)]
struct ConsentRow {
    id: Option<String>,
    user_id: Option<String>,
    client_id: String,
    scopes: Option<String>,
    created_at: String,
}

#[derive(sqlx::FromRow)]
struct DeviceCodeRow {
    id: Option<String>,
    device_code_hash: String,
    user_code: String,
    client_id: String,
    scopes: Option<String>,
    user_id: Option<String>,
    status: String,
    interval: i64,
    expires_at: String,
    last_polled_at: Option<String>,
    created_at: String,
}

// ── Oauth2Client ──

pub(crate) struct SqlxSqliteOauth2ClientRepo {
    pool: SqlitePool,
}
impl SqlxSqliteOauth2ClientRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteOauth2ClientRepo {}

impl Oauth2ClientRepository for SqlxSqliteOauth2ClientRepo {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                Oauth2ClientRow,
                "SELECT id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at, token_endpoint_auth_method, public_key_pem, jwks_uri, banned_at, banned_reason \
                 FROM yauth_oauth2_clients WHERE client_id = ? /* sqlite */",
                client_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::Oauth2Client {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                client_id: r.client_id,
                client_secret_hash: r.client_secret_hash,
                redirect_uris: serde_json::from_str(&r.redirect_uris).unwrap_or_default(),
                client_name: r.client_name,
                grant_types: serde_json::from_str(&r.grant_types).unwrap_or_default(),
                scopes: opt_str_to_json(r.scopes),
                is_public: r.is_public != 0,
                created_at: str_to_dt(&r.created_at),
                token_endpoint_auth_method: r.token_endpoint_auth_method,
                public_key_pem: r.public_key_pem,
                jwks_uri: r.jwks_uri,
                banned_at: opt_str_to_dt(r.banned_at),
                banned_reason: r.banned_reason,
            }))
        })
    }

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let redirect_uris_str = input.redirect_uris.to_string();
            let grant_types_str = input.grant_types.to_string();
            let scopes_str = input.scopes.map(|v| v.to_string());
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at, token_endpoint_auth_method, public_key_pem, jwks_uri) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                input.client_id,
                input.client_secret_hash,
                redirect_uris_str,
                input.client_name,
                grant_types_str,
                scopes_str,
                input.is_public,
                created_str,
                input.token_endpoint_auth_method,
                input.public_key_pem,
                input.jwks_uri,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn set_banned(
        &self,
        client_id: &str,
        banned: Option<(Option<String>, chrono::NaiveDateTime)>,
    ) -> RepoFuture<'_, bool> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let (at, reason) = match banned {
                Some((r, a)) => (Some(dt_to_str(a)), r),
                None => (None, None),
            };
            let result = sqlx::query!(
                "UPDATE yauth_oauth2_clients SET banned_at = ?, banned_reason = ? WHERE client_id = ? /* sqlite */",
                at,
                reason,
                client_id,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(result.rows_affected() > 0)
        })
    }

    fn rotate_public_key(
        &self,
        client_id: &str,
        public_key_pem: Option<String>,
    ) -> RepoFuture<'_, bool> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let result = sqlx::query!(
                "UPDATE yauth_oauth2_clients SET public_key_pem = ? WHERE client_id = ? /* sqlite */",
                public_key_pem,
                client_id,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(result.rows_affected() > 0)
        })
    }

    fn list_banned(&self) -> RepoFuture<'_, Vec<domain::Oauth2Client>> {
        Box::pin(async move {
            let rows = sqlx::query_as!(
                Oauth2ClientRow,
                "SELECT id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at, token_endpoint_auth_method, public_key_pem, jwks_uri, banned_at, banned_reason \
                 FROM yauth_oauth2_clients WHERE banned_at IS NOT NULL ORDER BY banned_at DESC /* sqlite */"
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::Oauth2Client {
                    id: str_to_uuid(&r.id.unwrap_or_default()),
                    client_id: r.client_id,
                    client_secret_hash: r.client_secret_hash,
                    redirect_uris: serde_json::from_str(&r.redirect_uris).unwrap_or_default(),
                    client_name: r.client_name,
                    grant_types: serde_json::from_str(&r.grant_types).unwrap_or_default(),
                    scopes: opt_str_to_json(r.scopes),
                    is_public: r.is_public != 0,
                    created_at: str_to_dt(&r.created_at),
                    token_endpoint_auth_method: r.token_endpoint_auth_method,
                    public_key_pem: r.public_key_pem,
                    jwks_uri: r.jwks_uri,
                    banned_at: opt_str_to_dt(r.banned_at),
                    banned_reason: r.banned_reason,
                })
                .collect())
        })
    }
}

// ── AuthorizationCode ──

pub(crate) struct SqlxSqliteAuthorizationCodeRepo {
    pool: SqlitePool,
}
impl SqlxSqliteAuthorizationCodeRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteAuthorizationCodeRepo {}

impl AuthorizationCodeRepository for SqlxSqliteAuthorizationCodeRepo {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let code_hash = code_hash.to_string();
        Box::pin(async move {
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                AuthorizationCodeRow,
                "SELECT id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at \
                 FROM yauth_authorization_codes \
                 WHERE code_hash = ? AND used = false AND expires_at > ? /* sqlite */",
                code_hash,
                now
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::AuthorizationCode {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                code_hash: r.code_hash,
                client_id: r.client_id,
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                scopes: opt_str_to_json(r.scopes),
                redirect_uri: r.redirect_uri,
                code_challenge: r.code_challenge,
                code_challenge_method: r.code_challenge_method,
                expires_at: str_to_dt(&r.expires_at),
                used: r.used != 0,
                nonce: r.nonce,
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let scopes_str = input.scopes.map(|v| v.to_string());
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                input.code_hash,
                input.client_id,
                user_id_str,
                scopes_str,
                input.redirect_uri,
                input.code_challenge,
                input.code_challenge_method,
                expires_str,
                input.used,
                input.nonce,
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
                "UPDATE yauth_authorization_codes SET used = true WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── Consent ──

pub(crate) struct SqlxSqliteConsentRepo {
    pool: SqlitePool,
}
impl SqlxSqliteConsentRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteConsentRepo {}

impl ConsentRepository for SqlxSqliteConsentRepo {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let row = sqlx::query_as!(
                ConsentRow,
                "SELECT id, user_id, client_id, scopes, created_at \
                 FROM yauth_consents WHERE user_id = ? AND client_id = ? /* sqlite */",
                user_id_str,
                client_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::Consent {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                client_id: r.client_id,
                scopes: opt_str_to_json(r.scopes),
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let scopes_str = input.scopes.map(|v| v.to_string());
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at) \
                 VALUES (?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.client_id,
                scopes_str,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let scopes_str = scopes.map(|v| v.to_string());
            sqlx::query!(
                "UPDATE yauth_consents SET scopes = ? WHERE id = ? /* sqlite */",
                scopes_str,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── DeviceCode ──

pub(crate) struct SqlxSqliteDeviceCodeRepo {
    pool: SqlitePool,
}
impl SqlxSqliteDeviceCodeRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteDeviceCodeRepo {}

impl DeviceCodeRepository for SqlxSqliteDeviceCodeRepo {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let user_code = user_code.to_string();
        Box::pin(async move {
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let row = sqlx::query_as!(
                DeviceCodeRow,
                "SELECT id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, last_polled_at, created_at \
                 FROM yauth_device_codes \
                 WHERE user_code = ? AND status = 'pending' AND expires_at > ? /* sqlite */",
                user_code,
                now
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::DeviceCode {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                device_code_hash: r.device_code_hash,
                user_code: r.user_code,
                client_id: r.client_id,
                scopes: opt_str_to_json(r.scopes),
                user_id: opt_str_to_uuid(r.user_id),
                status: r.status,
                interval: r.interval as i32,
                expires_at: str_to_dt(&r.expires_at),
                last_polled_at: opt_str_to_dt(r.last_polled_at),
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let device_code_hash = device_code_hash.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                DeviceCodeRow,
                "SELECT id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, last_polled_at, created_at \
                 FROM yauth_device_codes WHERE device_code_hash = ? /* sqlite */",
                device_code_hash
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| domain::DeviceCode {
                id: str_to_uuid(&r.id.unwrap_or_default()),
                device_code_hash: r.device_code_hash,
                user_code: r.user_code,
                client_id: r.client_id,
                scopes: opt_str_to_json(r.scopes),
                user_id: opt_str_to_uuid(r.user_id),
                status: r.status,
                interval: r.interval as i32,
                expires_at: str_to_dt(&r.expires_at),
                last_polled_at: opt_str_to_dt(r.last_polled_at),
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.map(|u| u.to_string());
            let scopes_str = input.scopes.map(|v| v.to_string());
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                input.device_code_hash,
                input.user_code,
                input.client_id,
                scopes_str,
                user_id_str,
                input.status,
                input.interval,
                expires_str,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()> {
        let status = status.to_string();
        Box::pin(async move {
            let id_str = id.to_string();
            let user_id_str = user_id.map(|u| u.to_string());
            sqlx::query!(
                "UPDATE yauth_device_codes SET status = ?, user_id = ? WHERE id = ? /* sqlite */",
                status,
                user_id_str,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            sqlx::query!(
                "UPDATE yauth_device_codes SET last_polled_at = ? WHERE id = ? /* sqlite */",
                now,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "UPDATE yauth_device_codes SET interval = ? WHERE id = ? /* sqlite */",
                interval,
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
