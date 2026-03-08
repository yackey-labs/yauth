use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::Utc;
use rand::Rng;
#[cfg(feature = "seaorm")]
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::crypto;
use crate::config::OAuth2ServerConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Diesel-async helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "diesel-async")]
mod diesel_db {
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;
    use uuid::Uuid;

    type Conn = diesel_async_crate::AsyncPgConnection;
    type DbResult<T> = Result<T, String>;

    // -- QueryableByName row types --

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct ClientRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub client_id: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub client_secret_hash: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        pub redirect_uris: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub client_name: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        pub grant_types: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        pub scopes: Option<serde_json::Value>,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pub is_public: bool,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct AuthCodeRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub code_hash: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub client_id: String,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub user_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        pub scopes: Option<serde_json::Value>,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub redirect_uri: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub code_challenge: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub code_challenge_method: String,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub expires_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pub used: bool,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub nonce: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct ConsentRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub user_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub client_id: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        pub scopes: Option<serde_json::Value>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct DeviceCodeRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub device_code_hash: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub user_code: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub client_id: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        pub scopes: Option<serde_json::Value>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
        pub user_id: Option<Uuid>,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub status: String,
        #[diesel(sql_type = diesel::sql_types::Int4)]
        pub interval: i32,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub expires_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
        pub last_polled_at: Option<chrono::NaiveDateTime>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct UserRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub email: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub display_name: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pub email_verified: bool,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub role: String,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pub banned: bool,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct RefreshTokenRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub user_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub token_hash: String,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub family_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub expires_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pub revoked: bool,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct CountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        pub cnt: i64,
    }

    // -- Client operations --

    pub async fn find_client_by_client_id(
        conn: &mut Conn,
        client_id: &str,
    ) -> DbResult<Option<ClientRow>> {
        diesel::sql_query(
            "SELECT id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at FROM yauth_oauth2_clients WHERE client_id = $1",
        )
        .bind::<diesel::sql_types::Text, _>(client_id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn insert_client(
        conn: &mut Conn,
        id: Uuid,
        client_id: &str,
        client_secret_hash: Option<&str>,
        redirect_uris: &serde_json::Value,
        client_name: Option<&str>,
        grant_types: &serde_json::Value,
        scopes: Option<&serde_json::Value>,
        is_public: bool,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(client_secret_hash)
        .bind::<diesel::sql_types::Jsonb, _>(redirect_uris)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(client_name)
        .bind::<diesel::sql_types::Jsonb, _>(grant_types)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(scopes)
        .bind::<diesel::sql_types::Bool, _>(is_public)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // -- Authorization code operations --

    pub async fn find_auth_code_by_hash(
        conn: &mut Conn,
        code_hash: &str,
    ) -> DbResult<Option<AuthCodeRow>> {
        diesel::sql_query(
            "SELECT id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at FROM yauth_authorization_codes WHERE code_hash = $1",
        )
        .bind::<diesel::sql_types::Text, _>(code_hash)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn mark_auth_code_used(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("UPDATE yauth_authorization_codes SET used = true WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn insert_auth_code(
        conn: &mut Conn,
        id: Uuid,
        code_hash: &str,
        client_id: &str,
        user_id: Uuid,
        scopes: Option<&serde_json::Value>,
        redirect_uri: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, nonce, expires_at, used, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, false, $10)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Text, _>(code_hash)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(scopes)
        .bind::<diesel::sql_types::Text, _>(redirect_uri)
        .bind::<diesel::sql_types::Text, _>(code_challenge)
        .bind::<diesel::sql_types::Text, _>(code_challenge_method)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // -- Consent operations --

    pub async fn find_consent(
        conn: &mut Conn,
        user_id: Uuid,
        client_id: &str,
    ) -> DbResult<Option<ConsentRow>> {
        diesel::sql_query(
            "SELECT id, user_id, client_id, scopes, created_at FROM yauth_consents WHERE user_id = $1 AND client_id = $2",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn update_consent(
        conn: &mut Conn,
        id: Uuid,
        scopes: Option<&serde_json::Value>,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "UPDATE yauth_consents SET scopes = $1, created_at = $2 WHERE id = $3",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(scopes)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn insert_consent(
        conn: &mut Conn,
        id: Uuid,
        user_id: Uuid,
        client_id: &str,
        scopes: Option<&serde_json::Value>,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(scopes)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // -- Device code operations --

    pub async fn find_device_code_by_user_code_pending(
        conn: &mut Conn,
        user_code: &str,
    ) -> DbResult<Option<DeviceCodeRow>> {
        diesel::sql_query(
            "SELECT id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, last_polled_at, created_at FROM yauth_device_codes WHERE user_code = $1 AND status = 'pending'",
        )
        .bind::<diesel::sql_types::Text, _>(user_code)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn find_device_code_by_hash(
        conn: &mut Conn,
        device_code_hash: &str,
    ) -> DbResult<Option<DeviceCodeRow>> {
        diesel::sql_query(
            "SELECT id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, last_polled_at, created_at FROM yauth_device_codes WHERE device_code_hash = $1",
        )
        .bind::<diesel::sql_types::Text, _>(device_code_hash)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn insert_device_code(
        conn: &mut Conn,
        id: Uuid,
        device_code_hash: &str,
        user_code: &str,
        client_id: &str,
        scopes: Option<&serde_json::Value>,
        interval: i32,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, last_polled_at, created_at) VALUES ($1, $2, $3, $4, $5, NULL, 'pending', $6, $7, NULL, $8)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Text, _>(device_code_hash)
        .bind::<diesel::sql_types::Text, _>(user_code)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(scopes)
        .bind::<diesel::sql_types::Int4, _>(interval)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn update_device_code_status(
        conn: &mut Conn,
        id: Uuid,
        status: &str,
        user_id: Option<Uuid>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "UPDATE yauth_device_codes SET status = $1, user_id = $2 WHERE id = $3",
        )
        .bind::<diesel::sql_types::Text, _>(status)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(user_id)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn update_device_code_polled(
        conn: &mut Conn,
        id: Uuid,
        last_polled_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "UPDATE yauth_device_codes SET last_polled_at = $1 WHERE id = $2",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(last_polled_at)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn update_device_code_slow_down(
        conn: &mut Conn,
        id: Uuid,
        new_interval: i32,
        last_polled_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "UPDATE yauth_device_codes SET interval = $1, last_polled_at = $2 WHERE id = $3",
        )
        .bind::<diesel::sql_types::Int4, _>(new_interval)
        .bind::<diesel::sql_types::Timestamptz, _>(last_polled_at)
        .bind::<diesel::sql_types::Uuid, _>(id)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // -- User operations --

    pub async fn find_user_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<UserRow>> {
        diesel::sql_query(
            "SELECT id, email, display_name, email_verified, role, banned FROM yauth_users WHERE id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    // -- Refresh token operations --

    pub async fn find_refresh_token_by_hash(
        conn: &mut Conn,
        token_hash: &str,
    ) -> DbResult<Option<RefreshTokenRow>> {
        diesel::sql_query(
            "SELECT id, user_id, token_hash, family_id, expires_at, revoked, created_at FROM yauth_refresh_tokens WHERE token_hash = $1",
        )
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn insert_refresh_token(
        conn: &mut Conn,
        id: Uuid,
        user_id: Uuid,
        token_hash: &str,
        family_id: Uuid,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
        created_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) VALUES ($1, $2, $3, $4, $5, false, $6)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .bind::<diesel::sql_types::Uuid, _>(family_id)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(created_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn revoke_refresh_token(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("UPDATE yauth_refresh_tokens SET revoked = true WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn revoke_family(conn: &mut Conn, family_id: Uuid) -> DbResult<()> {
        diesel::sql_query(
            "UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(family_id)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum request body size for OAuth endpoints (16 KB).
const MAX_OAUTH_BODY: usize = 16 * 1024;

/// Parse a request body as JSON or form-urlencoded based on Content-Type.
/// Returns `Err(message)` on unsupported content type or parse failure.
fn parse_json_or_form<T: serde::de::DeserializeOwned>(
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
) -> Result<T, String> {
    if body.len() > MAX_OAUTH_BODY {
        return Err("Request body too large".to_string());
    }

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/json") {
        serde_json::from_slice(body).map_err(|e| format!("Invalid JSON: {e}"))
    } else if content_type.contains("application/x-www-form-urlencoded") || content_type.is_empty()
    {
        serde_urlencoded::from_bytes(body).map_err(|e| format!("Invalid form data: {e}"))
    } else {
        Err(
            "Content-Type must be application/json or application/x-www-form-urlencoded"
                .to_string(),
        )
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct OAuth2ServerPlugin {
    _config: OAuth2ServerConfig,
}

impl OAuth2ServerPlugin {
    pub fn new(config: OAuth2ServerConfig) -> Self {
        Self { _config: config }
    }
}

impl YAuthPlugin for OAuth2ServerPlugin {
    fn name(&self) -> &'static str {
        "oauth2-server"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/.well-known/oauth-authorization-server", get(as_metadata))
                .route("/oauth/authorize", get(authorize_get).post(authorize_post))
                .route("/oauth/token", post(token_endpoint))
                .route("/oauth/introspect", post(introspect_endpoint))
                .route("/oauth/revoke", post(revoke_endpoint))
                .route("/oauth/register", post(dynamic_client_registration))
                .route("/oauth/device/code", post(device_authorization))
                .route(
                    "/oauth/device",
                    get(device_verify_get).post(device_verify_post),
                ),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }
}

// ---------------------------------------------------------------------------
// AS Metadata (RFC 8414)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_authorization_endpoint: Option<String>,
    introspection_endpoint: String,
    revocation_endpoint: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

async fn as_metadata(State(state): State<YAuthState>) -> Json<AuthorizationServerMetadata> {
    let config = &state.oauth2_server_config;
    let issuer = &config.issuer;

    let registration_endpoint = if config.allow_dynamic_registration {
        Some(format!("{}/oauth/register", issuer))
    } else {
        None
    };

    let device_authorization_endpoint = Some(format!("{}/oauth/device/code", issuer));

    Json(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", issuer),
        token_endpoint: format!("{}/oauth/token", issuer),
        registration_endpoint,
        device_authorization_endpoint,
        introspection_endpoint: format!("{}/oauth/introspect", issuer),
        revocation_endpoint: format!("{}/oauth/revoke", issuer),
        scopes_supported: config.scopes_supported.clone(),
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
            "urn:ietf:params:oauth:grant-type:device_code".into(),
        ],
        token_endpoint_auth_methods_supported: vec!["none".into(), "client_secret_post".into()],
        code_challenge_methods_supported: vec!["S256".into()],
    })
}

// ---------------------------------------------------------------------------
// Authorization Endpoint (GET /oauth/authorize)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    /// Optional per RFC 6749 §3.1.2.3 — when omitted, defaults to the
    /// client's single registered redirect URI.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

/// GET /oauth/authorize — returns JSON describing what the user needs to consent to.
/// In a real browser flow, this would render a consent page. For MCP clients,
/// the response tells the client what to display. If the user is already
/// authenticated (session cookie) and has already consented, we redirect
/// immediately with the authorization code.
async fn authorize_get(
    State(state): State<YAuthState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // Validate request parameters
    if let Err(e) = validate_authorize_params(&params) {
        return e.into_response();
    }

    // Look up client
    let client = match lookup_client(&state, &params.client_id).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    // Resolve redirect_uri: use provided value, or default to client's single registered URI
    let redirect_uri = match resolve_redirect_uri(&client, params.redirect_uri.as_deref()) {
        Ok(uri) => uri,
        Err(e) => return e.into_response(),
    };

    // If a consent UI URL is configured and the request is from a browser
    // (not an API client requesting JSON), redirect to the consent UI.
    let wants_json = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"));

    if !wants_json && let Some(ref consent_url) = state.oauth2_server_config.consent_ui_url {
        let mut url = url::Url::parse(consent_url)
            .unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
        url.query_pairs_mut()
            .append_pair("client_id", &params.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", &params.response_type)
            .append_pair("code_challenge", &params.code_challenge)
            .append_pair("code_challenge_method", &params.code_challenge_method);
        if let Some(ref scope) = params.scope {
            url.query_pairs_mut().append_pair("scope", scope);
        }
        if let Some(ref state_param) = params.state {
            url.query_pairs_mut().append_pair("state", state_param);
        }
        return Redirect::to(url.as_str()).into_response();
    }

    // Return a JSON response describing the authorization request.
    // The consent UI (or MCP client browser popup) uses this to display
    // the consent screen.
    Json(serde_json::json!({
        "type": "authorization_request",
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uri": redirect_uri,
        "scope": params.scope,
        "state": params.state,
        "code_challenge": params.code_challenge,
        "code_challenge_method": params.code_challenge_method,
        "login_endpoint": format!("{}/login", state.config.base_url),
        "consent_endpoint": format!("{}/oauth/authorize", state.config.base_url),
    }))
    .into_response()
}

/// POST /oauth/authorize — user submits consent decision. Requires authentication.
/// If approved, generates an authorization code and redirects to the client's
/// redirect_uri with the code. Accepts both JSON and form-urlencoded bodies
/// (form submission from consent UI avoids CORS issues with cross-origin redirects).
async fn authorize_post(
    State(state): State<YAuthState>,
    jar: axum_extra::extract::cookie::CookieJar,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let input: AuthorizeConsentRequest = match parse_json_or_form(&headers, &body) {
        Ok(v) => v,
        Err(msg) => return api_err(StatusCode::BAD_REQUEST, &msg).into_response(),
    };
    // Authenticate the user via session cookie or bearer token
    let auth_user = match authenticate_user(&state, &jar, &headers).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "login_required",
                    "error_description": "User must be authenticated to authorize"
                })),
            )
                .into_response();
        }
    };

    // Validate request parameters
    if let Err(e) = validate_authorize_params_from_consent(&input) {
        return e.into_response();
    }

    // Look up client
    let client = match lookup_client(&state, &input.client_id).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    // Validate redirect_uri
    if let Err(e) = validate_redirect_uri(&client, &input.redirect_uri) {
        return e.into_response();
    }

    // If user denied consent, redirect with error
    if !input.approved {
        let mut redirect_url = url::Url::parse(&input.redirect_uri)
            .unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
        redirect_url
            .query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("error_description", "User denied the authorization request");
        if let Some(ref s) = input.state {
            redirect_url.query_pairs_mut().append_pair("state", s);
        }
        return Redirect::to(redirect_url.as_str()).into_response();
    }

    // Store consent
    let scopes_json = input
        .scope
        .as_ref()
        .map(|s| serde_json::json!(s.split_whitespace().collect::<Vec<_>>()));

    save_consent(&state, auth_user.id, &input.client_id, scopes_json.clone()).await;

    // Generate authorization code
    let raw_code = crypto::generate_token();
    let code_hash = crypto::hash_token(&raw_code);
    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now()
        + chrono::Duration::from_std(state.oauth2_server_config.authorization_code_ttl)
            .unwrap_or(chrono::Duration::seconds(60)))
    .fixed_offset();

    #[cfg(feature = "seaorm")]
    {
        let auth_code = yauth_entity::authorization_codes::ActiveModel {
            id: Set(Uuid::new_v4()),
            code_hash: Set(code_hash),
            client_id: Set(input.client_id.clone()),
            user_id: Set(auth_user.id),
            scopes: Set(scopes_json.clone()),
            redirect_uri: Set(input.redirect_uri.clone()),
            code_challenge: Set(input.code_challenge.clone()),
            code_challenge_method: Set(input.code_challenge_method.clone()),
            nonce: Set(None),
            expires_at: Set(expires_at),
            used: Set(false),
            created_at: Set(now),
        };

        if let Err(e) = auth_code.insert(&state.db).await {
            tracing::error!("Failed to store authorization code: {}", e);
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = match state.db.get().await {
            Ok(c) => c,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
        };
        if let Err(e) = diesel_db::insert_auth_code(
            &mut conn,
            Uuid::new_v4(),
            &code_hash,
            &input.client_id,
            auth_user.id,
            scopes_json.as_ref(),
            &input.redirect_uri,
            &input.code_challenge,
            &input.code_challenge_method,
            expires_at,
            now,
        ).await {
            tracing::error!("Failed to store authorization code: {}", e);
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    info!(
        event = "oauth2_authorize_approved",
        user_id = %auth_user.id,
        client_id = %input.client_id,
        "User approved OAuth2 authorization"
    );

    state
        .write_audit_log(
            Some(auth_user.id),
            "oauth2_authorize_approved",
            Some(serde_json::json!({
                "client_id": input.client_id,
                "scope": input.scope,
            })),
            None,
        )
        .await;

    // Redirect back to client with authorization code
    let mut redirect_url = url::Url::parse(&input.redirect_uri)
        .unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &raw_code);
    if let Some(ref s) = input.state {
        redirect_url.query_pairs_mut().append_pair("state", s);
    }

    Redirect::to(redirect_url.as_str()).into_response()
}

fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct BoolOrString;

    impl<'de> de::Visitor<'de> for BoolOrString {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or a string \"true\"/\"false\"")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<bool, E> {
            Ok(v)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<bool, E> {
            match v {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(E::invalid_value(de::Unexpected::Str(v), &self)),
            }
        }
    }

    deserializer.deserialize_any(BoolOrString)
}

#[derive(Deserialize)]
pub struct AuthorizeConsentRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// Whether the user approved the authorization request.
    /// Accepts both native bool (JSON) and string "true"/"false" (form data).
    #[serde(deserialize_with = "deserialize_bool_or_string")]
    pub approved: bool,
}

// ---------------------------------------------------------------------------
// Token Endpoint — authorization_code grant (POST /oauth/token)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenCodeRequest {
    pub grant_type: String,
    // authorization_code fields
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    // refresh_token fields
    #[serde(default)]
    pub refresh_token: Option<String>,
    // device_code fields
    #[serde(default)]
    pub device_code: Option<String>,
    // client_credentials fields
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Serialize)]
struct OAuth2TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Token response for client_credentials grant (no refresh token per RFC).
#[derive(Serialize)]
struct OAuth2ClientCredentialsTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

// ---------------------------------------------------------------------------
// Introspection (RFC 7662)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IntrospectRequest {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
}

impl IntrospectResponse {
    fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            client_id: None,
            scope: None,
            exp: None,
            iat: None,
            token_type: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation (RFC 7009)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RevokeTokenRequest {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

async fn token_endpoint(
    State(state): State<YAuthState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let input: TokenCodeRequest = match parse_json_or_form(&headers, &body) {
        Ok(v) => v,
        Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_request", &msg),
    };
    match input.grant_type.as_str() {
        "authorization_code" => match handle_authorization_code_grant(&state, &input).await {
            Ok(resp) => resp.into_response(),
            Err(e) => e,
        },
        "refresh_token" => match handle_oauth2_refresh_token(&state, &input).await {
            Ok(resp) => resp.into_response(),
            Err(e) => e,
        },
        "urn:ietf:params:oauth:grant-type:device_code" => {
            match handle_device_code_grant(&state, &input).await {
                Ok(resp) => resp.into_response(),
                Err(e) => e,
            }
        }
        "client_credentials" => match handle_client_credentials_grant(&state, &input).await {
            Ok(resp) => resp.into_response(),
            Err(e) => e,
        },
        _ => oauth2_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("Grant type '{}' is not supported", input.grant_type),
        ),
    }
}

#[allow(unused_variables, clippy::needless_return)]
async fn handle_authorization_code_grant(
    state: &YAuthState,
    input: &TokenCodeRequest,
) -> Result<impl IntoResponse, Response> {
    let code = input.code.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'code' parameter",
        )
    })?;
    let redirect_uri = input.redirect_uri.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'redirect_uri' parameter",
        )
    })?;
    let client_id = input.client_id.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'client_id' parameter",
        )
    })?;
    let code_verifier = input.code_verifier.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'code_verifier' parameter",
        )
    })?;

    // Verify client exists
    let _client = lookup_client(state, client_id)
        .await
        .map_err(|e| e.into_response())?;

    // Find authorization code
    let code_hash = crypto::hash_token(code);

    // Cross-backend stored code info
    #[allow(dead_code)]
    struct StoredCode {
        id: Uuid,
        code_hash: String,
        client_id: String,
        user_id: Uuid,
        scopes: Option<serde_json::Value>,
        redirect_uri: String,
        code_challenge: String,
        code_challenge_method: String,
        expires_at: chrono::NaiveDateTime,
        used: bool,
    }

    #[cfg(feature = "seaorm")]
    let stored_code = {
        let row = yauth_entity::authorization_codes::Entity::find()
            .filter(yauth_entity::authorization_codes::Column::CodeHash.eq(&code_hash))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?
            .ok_or_else(|| {
                warn!(event = "oauth2_invalid_code", "Authorization code not found");
                oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid authorization code")
            })?;
        StoredCode {
            id: row.id, code_hash: row.code_hash, client_id: row.client_id,
            user_id: row.user_id, scopes: row.scopes, redirect_uri: row.redirect_uri,
            code_challenge: row.code_challenge, code_challenge_method: row.code_challenge_method,
            expires_at: row.expires_at.naive_utc(), used: row.used,
        }
    };
    #[cfg(feature = "diesel-async")]
    let stored_code = {
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        let row = diesel_db::find_auth_code_by_hash(&mut conn, &code_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?
            .ok_or_else(|| {
                warn!(event = "oauth2_invalid_code", "Authorization code not found");
                oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid authorization code")
            })?;
        StoredCode {
            id: row.id, code_hash: row.code_hash, client_id: row.client_id,
            user_id: row.user_id, scopes: row.scopes, redirect_uri: row.redirect_uri,
            code_challenge: row.code_challenge, code_challenge_method: row.code_challenge_method,
            expires_at: row.expires_at, used: row.used,
        }
    };

    // Check if code was already used
    if stored_code.used {
        warn!(
            event = "oauth2_code_reuse",
            client_id = %stored_code.client_id,
            user_id = %stored_code.user_id,
            "Authorization code reuse detected"
        );
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code has already been used",
        ));
    }

    // Check expiration
    let now_naive = Utc::now().naive_utc();
    if stored_code.expires_at < now_naive {
        warn!(event = "oauth2_code_expired", "Authorization code expired");
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code has expired",
        ));
    }

    // Validate client_id matches
    if stored_code.client_id != client_id {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Client ID mismatch",
        ));
    }

    // Validate redirect_uri matches
    if stored_code.redirect_uri != redirect_uri {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Redirect URI mismatch",
        ));
    }

    // Validate PKCE code_verifier
    if stored_code.code_challenge_method != "S256" {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Only S256 code challenge method is supported",
        ));
    }

    let computed_challenge = pkce_s256_challenge(code_verifier);
    if computed_challenge != stored_code.code_challenge {
        warn!(event = "oauth2_pkce_mismatch", "PKCE verification failed");
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        ));
    }

    // Mark code as used
    #[cfg(feature = "seaorm")]
    {
        let found = yauth_entity::authorization_codes::Entity::find_by_id(stored_code.id)
            .one(&state.db).await
            .map_err(|e| { tracing::error!("DB error: {}", e); oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error") })?
            .ok_or_else(|| oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error"))?;
        let mut active: yauth_entity::authorization_codes::ActiveModel = found.into();
        active.used = Set(true);
        active.update(&state.db).await.map_err(|e| {
            tracing::error!("Failed to mark auth code as used: {}", e);
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        diesel_db::mark_auth_code_used(&mut conn, stored_code.id).await.map_err(|e| {
            tracing::error!("Failed to mark auth code as used: {}", e);
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
    }

    // Look up user — common struct for cross-backend
    #[allow(dead_code)]
    struct AuthCodeUser {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        role: String,
        banned: bool,
    }

    #[cfg(feature = "seaorm")]
    let user = {
        let u = yauth_entity::users::Entity::find_by_id(stored_code.user_id)
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?
            .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;
        AuthCodeUser {
            id: u.id, email: u.email, display_name: u.display_name,
            email_verified: u.email_verified, role: u.role, banned: u.banned,
        }
    };
    #[cfg(feature = "diesel-async")]
    let user = {
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        let u = diesel_db::find_user_by_id(&mut conn, stored_code.user_id).await.map_err(|e| {
            tracing::error!("DB error: {}", e);
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?.ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;
        AuthCodeUser {
            id: u.id, email: u.email, display_name: u.display_name,
            email_verified: u.email_verified, role: u.role, banned: u.banned,
        }
    };

    if user.banned {
        return Err(oauth2_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Account suspended",
        ));
    }

    // Parse scopes from stored code
    let scope_str = stored_code
        .scopes
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });

    // Issue tokens using the bearer config (requires bearer feature)
    #[cfg(all(feature = "bearer", feature = "seaorm"))]
    {
        let bearer_config = &state.bearer_config;

        // Reconstruct users::Model for create_jwt_with_audience
        let user_model = yauth_entity::users::Model {
            id: user.id, email: user.email.clone(), display_name: user.display_name.clone(),
            email_verified: user.email_verified, role: user.role.clone(), banned: user.banned,
            banned_reason: None, banned_until: None,
            created_at: Utc::now().fixed_offset(), updated_at: Utc::now().fixed_offset(),
        };

        let (access_token, _jti) = crate::plugins::bearer::create_jwt_with_audience(
            &user_model,
            bearer_config,
            scope_str.as_deref(),
        )
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create token",
            )
        })?;

        let family_id = Uuid::new_v4();
        let refresh_token = create_refresh_token_for_oauth2(
            &state.db,
            user.id,
            family_id,
            bearer_config.refresh_token_ttl,
        )
        .await
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create refresh token",
            )
        })?;

        let expires_in = bearer_config.access_token_ttl.as_secs();

        info!(
            event = "oauth2_token_issued",
            user_id = %user.id,
            client_id = %client_id,
            "OAuth2 access token issued via authorization_code grant"
        );

        state
            .write_audit_log(
                Some(user.id),
                "oauth2_token_issued",
                Some(serde_json::json!({
                    "client_id": client_id,
                    "grant_type": "authorization_code",
                })),
                None,
            )
            .await;

        return Ok(Json(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            refresh_token,
            scope: scope_str,
        }));
    }

    #[cfg(all(feature = "bearer", feature = "diesel-async"))]
    {
        let bearer_config = &state.bearer_config;

        let jwt_user = crate::plugins::bearer::JwtUser {
            id: user.id,
            email: user.email.clone(),
            role: user.role.clone(),
        };

        let (access_token, _jti) = crate::plugins::bearer::create_jwt_with_audience_from_fields(
            &jwt_user,
            bearer_config,
            scope_str.as_deref(),
        )
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create token",
            )
        })?;

        let family_id = Uuid::new_v4();
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        let refresh_token = create_refresh_token_for_oauth2_diesel(
            &mut conn,
            user.id,
            family_id,
            bearer_config.refresh_token_ttl,
        )
        .await
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create refresh token",
            )
        })?;

        let expires_in = bearer_config.access_token_ttl.as_secs();

        info!(
            event = "oauth2_token_issued",
            user_id = %user.id,
            client_id = %client_id,
            "OAuth2 access token issued via authorization_code grant"
        );

        state
            .write_audit_log(
                Some(user.id),
                "oauth2_token_issued",
                Some(serde_json::json!({
                    "client_id": client_id,
                    "grant_type": "authorization_code",
                })),
                None,
            )
            .await;

        return Ok(Json(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            refresh_token,
            scope: scope_str,
        }));
    }

    #[cfg(not(feature = "bearer"))]
    {
        let _ = user;
        Err::<Json<OAuth2TokenResponse>, _>(oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Bearer feature is required for OAuth2 token issuance",
        ))
    }
}

#[allow(unused_variables, clippy::needless_return)]
async fn handle_oauth2_refresh_token(
    state: &YAuthState,
    input: &TokenCodeRequest,
) -> Result<impl IntoResponse, Response> {
    let refresh_token_raw = input.refresh_token.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'refresh_token' parameter",
        )
    })?;

    #[cfg(feature = "bearer")]
    {
        let token_hash = crypto::hash_token(refresh_token_raw);

        // Cross-backend stored refresh token info
        struct StoredRefresh {
            id: Uuid,
            user_id: Uuid,
            family_id: Uuid,
            expires_at: chrono::NaiveDateTime,
            revoked: bool,
        }

        // Find the refresh token
        #[cfg(feature = "seaorm")]
        let stored = {
            let row = yauth_entity::refresh_tokens::Entity::find()
                .filter(yauth_entity::refresh_tokens::Column::TokenHash.eq(&token_hash))
                .one(&state.db)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
                })?
                .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid refresh token"))?;
            StoredRefresh {
                id: row.id, user_id: row.user_id, family_id: row.family_id,
                expires_at: row.expires_at.naive_utc(), revoked: row.revoked,
            }
        };
        #[cfg(feature = "diesel-async")]
        let stored = {
            let mut conn = state.db.get().await.map_err(|_| {
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?;
            let row = diesel_db::find_refresh_token_by_hash(&mut conn, &token_hash)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
                })?
                .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid refresh token"))?;
            StoredRefresh {
                id: row.id, user_id: row.user_id, family_id: row.family_id,
                expires_at: row.expires_at, revoked: row.revoked,
            }
        };

        if stored.revoked {
            warn!(
                event = "oauth2_refresh_reuse",
                family_id = %stored.family_id,
                "Refresh token reuse detected — revoking family"
            );
            #[cfg(feature = "seaorm")]
            revoke_family(&state.db, stored.family_id).await;
            #[cfg(feature = "diesel-async")]
            {
                let mut conn = state.db.get().await.ok();
                if let Some(ref mut conn) = conn {
                    let _ = diesel_db::revoke_family(conn, stored.family_id).await;
                }
            }
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token has been revoked",
            ));
        }

        let now_naive = Utc::now().naive_utc();
        if stored.expires_at < now_naive {
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token has expired",
            ));
        }

        // Revoke old token
        let family_id = stored.family_id;
        let user_id = stored.user_id;
        #[cfg(feature = "seaorm")]
        {
            let found = yauth_entity::refresh_tokens::Entity::find_by_id(stored.id)
                .one(&state.db).await
                .map_err(|e| { tracing::error!("DB error: {}", e); oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error") })?
                .ok_or_else(|| oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error"))?;
            let mut active: yauth_entity::refresh_tokens::ActiveModel = found.into();
            active.revoked = Set(true);
            active.update(&state.db).await.map_err(|e| {
                tracing::error!("Failed to revoke old refresh token: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?;
        }
        #[cfg(feature = "diesel-async")]
        {
            let mut conn = state.db.get().await.map_err(|_| {
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?;
            diesel_db::revoke_refresh_token(&mut conn, stored.id).await.map_err(|e| {
                tracing::error!("Failed to revoke old refresh token: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?;
        }

        // Look up user — common struct
        struct RefreshUser {
            id: Uuid,
            email: String,
            display_name: Option<String>,
            email_verified: bool,
            role: String,
            banned: bool,
        }

        #[cfg(feature = "seaorm")]
        let user = {
            let u = yauth_entity::users::Entity::find_by_id(user_id)
                .one(&state.db)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
                })?
                .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;
            RefreshUser {
                id: u.id, email: u.email, display_name: u.display_name,
                email_verified: u.email_verified, role: u.role, banned: u.banned,
            }
        };
        #[cfg(feature = "diesel-async")]
        let user = {
            let mut conn = state.db.get().await.map_err(|_| {
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?;
            let u = diesel_db::find_user_by_id(&mut conn, user_id).await.map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?.ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;
            RefreshUser {
                id: u.id, email: u.email, display_name: u.display_name,
                email_verified: u.email_verified, role: u.role, banned: u.banned,
            }
        };

        if user.banned {
            return Err(oauth2_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Account suspended",
            ));
        }

        let bearer_config = &state.bearer_config;

        #[cfg(feature = "seaorm")]
        let (access_token, _jti) = {
            let user_model = yauth_entity::users::Model {
                id: user.id, email: user.email.clone(), display_name: user.display_name.clone(),
                email_verified: user.email_verified, role: user.role.clone(), banned: user.banned,
                banned_reason: None, banned_until: None,
                created_at: Utc::now().fixed_offset(), updated_at: Utc::now().fixed_offset(),
            };
            crate::plugins::bearer::create_jwt_with_audience(&user_model, bearer_config, None).map_err(
                |_| oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to create token"),
            )?
        };
        #[cfg(feature = "diesel-async")]
        let (access_token, _jti) = {
            let jwt_user = crate::plugins::bearer::JwtUser {
                id: user.id,
                email: user.email.clone(),
                role: user.role.clone(),
            };
            crate::plugins::bearer::create_jwt_with_audience_from_fields(&jwt_user, bearer_config, None).map_err(
                |_| oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to create token"),
            )?
        };

        #[cfg(feature = "seaorm")]
        let new_refresh = create_refresh_token_for_oauth2(
            &state.db,
            user.id,
            family_id,
            bearer_config.refresh_token_ttl,
        )
        .await
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create refresh token",
            )
        })?;
        #[cfg(feature = "diesel-async")]
        let new_refresh = {
            let mut conn = state.db.get().await.map_err(|_| {
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?;
            create_refresh_token_for_oauth2_diesel(&mut conn, user.id, family_id, bearer_config.refresh_token_ttl)
                .await
                .map_err(|_| oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to create refresh token"))?
        };

        let expires_in = bearer_config.access_token_ttl.as_secs();

        return Ok(Json(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            refresh_token: new_refresh,
            scope: None,
        }));
    }

    #[cfg(not(feature = "bearer"))]
    {
        Err::<Json<OAuth2TokenResponse>, _>(oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Bearer feature is required for OAuth2 token refresh",
        ))
    }
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591) — POST /register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ClientRegistrationRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Serialize)]
struct ClientRegistrationResponse {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
}

async fn dynamic_client_registration(
    State(state): State<YAuthState>,
    Json(input): Json<ClientRegistrationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let config = &state.oauth2_server_config;

    if !config.allow_dynamic_registration {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Dynamic client registration is disabled",
        ));
    }

    // Validate redirect URIs
    if input.redirect_uris.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "At least one redirect_uri is required",
        ));
    }

    for uri in &input.redirect_uris {
        if url::Url::parse(uri).is_err() {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                &format!("Invalid redirect_uri: {}", uri),
            ));
        }
    }

    let grant_types = input
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into()]);

    let auth_method = input
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("none");

    // Generate client credentials
    let client_id = Uuid::new_v4().to_string();
    let (client_secret, client_secret_hash, is_public) = if auth_method == "none" {
        (None, None, true)
    } else {
        let secret = crypto::generate_token();
        let hash = crypto::hash_token(&secret);
        (Some(secret), Some(hash), false)
    };

    let scopes_json = input
        .scope
        .as_ref()
        .map(|s| serde_json::json!(s.split_whitespace().collect::<Vec<_>>()));

    let now = Utc::now().fixed_offset();

    let redirect_uris_json = serde_json::json!(input.redirect_uris);
    let grant_types_json = serde_json::json!(grant_types);

    #[cfg(feature = "seaorm")]
    {
        let client = yauth_entity::oauth2_clients::ActiveModel {
            id: Set(Uuid::new_v4()),
            client_id: Set(client_id.clone()),
            client_secret_hash: Set(client_secret_hash.clone()),
            redirect_uris: Set(redirect_uris_json),
            client_name: Set(input.client_name.clone()),
            grant_types: Set(grant_types_json),
            scopes: Set(scopes_json),
            is_public: Set(is_public),
            created_at: Set(now),
        };

        client.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to register client: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to register client")
        })?;
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state.db.get().await.map_err(|_| {
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
        diesel_db::insert_client(
            &mut conn,
            Uuid::new_v4(),
            &client_id,
            client_secret_hash.as_deref(),
            &redirect_uris_json,
            input.client_name.as_deref(),
            &grant_types_json,
            scopes_json.as_ref(),
            is_public,
            now,
        ).await.map_err(|e| {
            tracing::error!("Failed to register client: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to register client")
        })?;
    }

    info!(
        event = "oauth2_client_registered",
        client_id = %client_id,
        client_name = ?input.client_name,
        "New OAuth2 client registered"
    );

    Ok((
        StatusCode::CREATED,
        Json(ClientRegistrationResponse {
            client_id,
            client_secret,
            redirect_uris: input.redirect_uris,
            client_name: input.client_name,
            grant_types,
            token_endpoint_auth_method: auth_method.to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Device Authorization Grant (RFC 8628)
// ---------------------------------------------------------------------------

/// Characters for user codes — ambiguity-free (no 0/O/1/I/L).
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Generate an 8-character user code formatted as XXXX-XXXX.
fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: String = (0..8)
        .map(|_| USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// Generate a unique user code, retrying on collision with pending codes.
#[cfg(feature = "seaorm")]
async fn generate_unique_user_code(db: &sea_orm::DatabaseConnection) -> Result<String, ApiError> {
    for _ in 0..10 {
        let code = generate_user_code();
        let existing = yauth_entity::device_codes::Entity::find()
            .filter(yauth_entity::device_codes::Column::UserCode.eq(&code))
            .filter(yauth_entity::device_codes::Column::Status.eq("pending"))
            .one(db)
            .await
            .map_err(|e| {
                tracing::error!("DB error checking user code uniqueness: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        if existing.is_none() {
            return Ok(code);
        }
    }
    Err(api_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to generate unique user code",
    ))
}

/// Generate a unique user code, retrying on collision with pending codes.
#[cfg(feature = "diesel-async")]
async fn generate_unique_user_code_diesel(
    conn: &mut diesel_async_crate::AsyncPgConnection,
) -> Result<String, ApiError> {
    for _ in 0..10 {
        let code = generate_user_code();
        let existing = diesel_db::find_device_code_by_user_code_pending(conn, &code)
            .await
            .map_err(|e| {
                tracing::error!("DB error checking user code uniqueness: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        if existing.is_none() {
            return Ok(code);
        }
    }
    Err(api_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to generate unique user code",
    ))
}

#[derive(Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u32,
}

/// POST /oauth/device/code — Client requests device + user codes.
async fn device_authorization(
    State(state): State<YAuthState>,
    Json(input): Json<DeviceAuthorizationRequest>,
) -> Response {
    // Verify client exists
    if let Err(e) = lookup_client(&state, &input.client_id).await {
        return e.into_response();
    }

    let config = &state.oauth2_server_config;
    let interval = config.device_poll_interval;
    let ttl = config.device_code_ttl;

    // Generate codes
    #[cfg(feature = "diesel-async")]
    let mut conn = match state.db.get().await {
        Ok(c) => c,
        Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
    };

    #[cfg(feature = "seaorm")]
    let user_code = match generate_unique_user_code(&state.db).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    #[cfg(feature = "diesel-async")]
    let user_code = match generate_unique_user_code_diesel(&mut conn).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let raw_device_code = crypto::generate_token();
    let device_code_hash = crypto::hash_token(&raw_device_code);

    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now()
        + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(600)))
    .fixed_offset();

    let scopes_json = input
        .scope
        .as_ref()
        .map(|s| serde_json::json!(s.split_whitespace().collect::<Vec<_>>()));

    #[cfg(feature = "seaorm")]
    {
        let device_code = yauth_entity::device_codes::ActiveModel {
            id: Set(Uuid::new_v4()),
            device_code_hash: Set(device_code_hash),
            user_code: Set(user_code.clone()),
            client_id: Set(input.client_id.clone()),
            scopes: Set(scopes_json),
            user_id: Set(None),
            status: Set("pending".into()),
            interval: Set(interval as i32),
            expires_at: Set(expires_at),
            last_polled_at: Set(None),
            created_at: Set(now),
        };

        if let Err(e) = device_code.insert(&state.db).await {
            tracing::error!("Failed to store device code: {}", e);
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }
    #[cfg(feature = "diesel-async")]
    {
        if let Err(e) = diesel_db::insert_device_code(
            &mut conn,
            Uuid::new_v4(),
            &device_code_hash,
            &user_code,
            &input.client_id,
            scopes_json.as_ref(),
            interval as i32,
            expires_at,
            now,
        ).await {
            tracing::error!("Failed to store device code: {}", e);
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    let verification_uri = config
        .device_verification_uri
        .clone()
        .unwrap_or_else(|| format!("{}/oauth/device", config.issuer));

    let verification_uri_complete = Some(format!("{}?user_code={}", verification_uri, user_code));

    info!(
        event = "device_authorization_initiated",
        client_id = %input.client_id,
        "Device authorization flow initiated"
    );

    state
        .write_audit_log(
            None,
            "device_authorization_initiated",
            Some(serde_json::json!({
                "client_id": input.client_id,
            })),
            None,
        )
        .await;

    Json(DeviceAuthorizationResponse {
        device_code: raw_device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: ttl.as_secs(),
        interval,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct DeviceVerifyQuery {
    #[serde(default)]
    pub user_code: Option<String>,
}

/// GET /oauth/device — Returns JSON for the SPA consent page.
async fn device_verify_get(
    State(state): State<YAuthState>,
    Query(query): Query<DeviceVerifyQuery>,
) -> Response {
    // If a user_code is provided, look up the pending device code
    if let Some(ref code) = query.user_code {
        // Common struct for cross-backend device code data
        struct DcInfo {
            user_code: String,
            client_id: String,
            scopes: Option<serde_json::Value>,
            expires_at: chrono::NaiveDateTime,
        }

        #[cfg(feature = "seaorm")]
        let dc_result: Result<Option<DcInfo>, String> = {
            yauth_entity::device_codes::Entity::find()
                .filter(yauth_entity::device_codes::Column::UserCode.eq(code))
                .filter(yauth_entity::device_codes::Column::Status.eq("pending"))
                .one(&state.db)
                .await
                .map(|opt| opt.map(|dc| DcInfo {
                    user_code: dc.user_code,
                    client_id: dc.client_id,
                    scopes: dc.scopes,
                    expires_at: dc.expires_at.naive_utc(),
                }))
                .map_err(|e| e.to_string())
        };
        #[cfg(feature = "diesel-async")]
        let dc_result: Result<Option<DcInfo>, String> = {
            let mut conn = match state.db.get().await {
                Ok(c) => c,
                Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
            };
            diesel_db::find_device_code_by_user_code_pending(&mut conn, code)
                .await
                .map(|opt| opt.map(|dc| DcInfo {
                    user_code: dc.user_code,
                    client_id: dc.client_id,
                    scopes: dc.scopes,
                    expires_at: dc.expires_at,
                }))
        };

        match dc_result {
            Ok(Some(dc)) => {
                let now_naive = Utc::now().naive_utc();
                if dc.expires_at < now_naive {
                    return Json(serde_json::json!({
                        "type": "device_verification",
                        "error": "expired_token",
                        "error_description": "This device code has expired"
                    }))
                    .into_response();
                }

                // Look up client name
                #[cfg(feature = "seaorm")]
                let client_name = {
                    let client = yauth_entity::oauth2_clients::Entity::find()
                        .filter(yauth_entity::oauth2_clients::Column::ClientId.eq(&dc.client_id))
                        .one(&state.db)
                        .await
                        .ok()
                        .flatten();
                    client.and_then(|c| c.client_name)
                };
                #[cfg(feature = "diesel-async")]
                let client_name = {
                    let mut conn = match state.db.get().await {
                        Ok(c) => c,
                        Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
                    };
                    diesel_db::find_client_by_client_id(&mut conn, &dc.client_id)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|c| c.client_name)
                };

                let scope = dc.scopes.as_ref().and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                });

                return Json(serde_json::json!({
                    "type": "device_verification",
                    "user_code": dc.user_code,
                    "client_id": dc.client_id,
                    "client_name": client_name,
                    "scope": scope,
                    "login_endpoint": format!("{}/login", state.config.base_url),
                    "approve_endpoint": format!("{}/oauth/device", state.config.base_url),
                }))
                .into_response();
            }
            Ok(None) => {
                return Json(serde_json::json!({
                    "type": "device_verification",
                    "error": "invalid_code",
                    "error_description": "Invalid or already used user code"
                }))
                .into_response();
            }
            Err(e) => {
                tracing::error!("DB error looking up device code: {}", e);
                return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    .into_response();
            }
        }
    }

    // No user_code — return a prompt for the user to enter one
    Json(serde_json::json!({
        "type": "device_verification",
        "message": "Enter the code displayed on your device",
        "approve_endpoint": format!("{}/oauth/device", state.config.base_url),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
    pub approved: bool,
}

/// POST /oauth/device — User approves or denies the device authorization.
/// Requires authentication (session cookie or bearer token).
async fn device_verify_post(
    State(state): State<YAuthState>,
    jar: axum_extra::extract::cookie::CookieJar,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeviceVerifyRequest>,
) -> Response {
    // Authenticate the user
    let auth_user = match authenticate_user(&state, &jar, &headers).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "login_required",
                    "error_description": "User must be authenticated to approve device authorization"
                })),
            )
                .into_response();
        }
    };

    // Find the pending device code by user_code
    struct DcInfo {
        id: Uuid,
        expires_at: chrono::NaiveDateTime,
    }

    #[cfg(feature = "seaorm")]
    let dc = {
        let stored = yauth_entity::device_codes::Entity::find()
            .filter(yauth_entity::device_codes::Column::UserCode.eq(&input.user_code))
            .filter(yauth_entity::device_codes::Column::Status.eq("pending"))
            .one(&state.db)
            .await;

        match stored {
            Ok(Some(dc)) => DcInfo { id: dc.id, expires_at: dc.expires_at.naive_utc() },
            Ok(None) => {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid or already used user code",
                );
            }
            Err(e) => {
                tracing::error!("DB error: {}", e);
                return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
            }
        }
    };
    #[cfg(feature = "diesel-async")]
    let dc = {
        let mut conn = match state.db.get().await {
            Ok(c) => c,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
        };
        match diesel_db::find_device_code_by_user_code_pending(&mut conn, &input.user_code).await {
            Ok(Some(dc)) => DcInfo { id: dc.id, expires_at: dc.expires_at },
            Ok(None) => {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid or already used user code",
                );
            }
            Err(e) => {
                tracing::error!("DB error: {}", e);
                return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
            }
        }
    };

    // Check expiration
    let now_naive = Utc::now().naive_utc();
    if dc.expires_at < now_naive {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "Device code has expired",
        );
    }

    let new_status = if input.approved { "approved" } else { "denied" };

    #[cfg(feature = "seaorm")]
    {
        // Re-fetch for SeaORM active model
        let stored = yauth_entity::device_codes::Entity::find_by_id(dc.id)
            .one(&state.db)
            .await;
        if let Ok(Some(stored)) = stored {
            let mut active: yauth_entity::device_codes::ActiveModel = stored.into();
            active.status = Set(new_status.into());
            if input.approved {
                active.user_id = Set(Some(auth_user.id));
            }
            if let Err(e) = active.update(&state.db).await {
                tracing::error!("Failed to update device code status: {}", e);
                return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
            }
        }
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = match state.db.get().await {
            Ok(c) => c,
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
        };
        let user_id = if input.approved { Some(auth_user.id) } else { None };
        if let Err(e) = diesel_db::update_device_code_status(&mut conn, dc.id, new_status, user_id).await {
            tracing::error!("Failed to update device code status: {}", e);
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    info!(
        event = "device_authorization_decision",
        user_id = %auth_user.id,
        approved = input.approved,
        "User {} device authorization", if input.approved { "approved" } else { "denied" }
    );

    state
        .write_audit_log(
            Some(auth_user.id),
            if input.approved {
                "device_authorization_approved"
            } else {
                "device_authorization_denied"
            },
            Some(serde_json::json!({
                "user_code": input.user_code,
            })),
            None,
        )
        .await;

    Json(serde_json::json!({
        "status": new_status,
        "message": if input.approved { "Device authorized successfully" } else { "Device authorization denied" }
    }))
    .into_response()
}

/// Handle the device_code grant type at the token endpoint.
#[allow(unused_variables, clippy::needless_return)]
async fn handle_device_code_grant(
    state: &YAuthState,
    input: &TokenCodeRequest,
) -> Result<impl IntoResponse, Response> {
    let device_code_raw = input.device_code.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'device_code' parameter",
        )
    })?;
    let client_id = input.client_id.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'client_id' parameter",
        )
    })?;

    // Verify client exists
    let _client = lookup_client(state, client_id)
        .await
        .map_err(|e| e.into_response())?;

    // Find device code
    let device_code_hash = crypto::hash_token(device_code_raw);

    // Cross-backend device code info
    struct StoredDc {
        id: Uuid,
        client_id: String,
        scopes: Option<serde_json::Value>,
        user_id: Option<Uuid>,
        status: String,
        interval: i32,
        expires_at: chrono::NaiveDateTime,
        last_polled_at: Option<chrono::NaiveDateTime>,
    }

    #[cfg(feature = "seaorm")]
    let stored = {
        let row = yauth_entity::device_codes::Entity::find()
            .filter(yauth_entity::device_codes::Column::DeviceCodeHash.eq(&device_code_hash))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?
            .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid device code"))?;
        StoredDc {
            id: row.id, client_id: row.client_id, scopes: row.scopes,
            user_id: row.user_id, status: row.status, interval: row.interval,
            expires_at: row.expires_at.naive_utc(),
            last_polled_at: row.last_polled_at.map(|t| t.naive_utc()),
        }
    };
    #[cfg(feature = "diesel-async")]
    let stored = {
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        let row = diesel_db::find_device_code_by_hash(&mut conn, &device_code_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?
            .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid device code"))?;
        StoredDc {
            id: row.id, client_id: row.client_id, scopes: row.scopes,
            user_id: row.user_id, status: row.status, interval: row.interval,
            expires_at: row.expires_at, last_polled_at: row.last_polled_at,
        }
    };

    // Validate client_id matches
    if stored.client_id != client_id {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Client ID mismatch",
        ));
    }

    // Check expiration
    let now = Utc::now().fixed_offset();
    let now_naive = now.naive_utc();
    if stored.expires_at < now_naive {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "Device code has expired",
        ));
    }

    // Enforce polling interval (RFC 8628 §3.5)
    if let Some(last_polled) = stored.last_polled_at {
        let elapsed = now_naive.signed_duration_since(last_polled);
        if elapsed.num_seconds() < stored.interval as i64 {
            // Too fast — increment interval by 5s
            #[cfg(feature = "seaorm")]
            {
                let row = yauth_entity::device_codes::Entity::find_by_id(stored.id)
                    .one(&state.db).await
                    .ok().flatten();
                if let Some(row) = row {
                    let mut active: yauth_entity::device_codes::ActiveModel = row.into();
                    active.interval = Set(stored.interval + 5);
                    active.last_polled_at = Set(Some(now));
                    let _ = active.update(&state.db).await;
                }
            }
            #[cfg(feature = "diesel-async")]
            {
                let mut conn = state.db.get().await.ok();
                if let Some(ref mut conn) = conn {
                    let _ = diesel_db::update_device_code_slow_down(conn, stored.id, stored.interval + 5, now).await;
                }
            }
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "Polling too frequently, slow down",
            ));
        }
    }

    // Update last_polled_at
    let current_status = stored.status.clone();
    #[cfg(feature = "seaorm")]
    {
        let row = yauth_entity::device_codes::Entity::find_by_id(stored.id)
            .one(&state.db).await
            .ok().flatten();
        if let Some(row) = row {
            let mut active: yauth_entity::device_codes::ActiveModel = row.into();
            active.last_polled_at = Set(Some(now));
            let _ = active.update(&state.db).await;
        }
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state.db.get().await.ok();
        if let Some(ref mut conn) = conn {
            let _ = diesel_db::update_device_code_polled(conn, stored.id, now).await;
        }
    }

    match current_status.as_str() {
        "pending" => {
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "The authorization request is still pending",
            ));
        }
        "denied" => {
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "The user denied the authorization request",
            ));
        }
        "used" => {
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Device code has already been used",
            ));
        }
        "approved" => {
            // Continue to issue tokens below
        }
        _ => {
            return Err(oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Unknown device code status",
            ));
        }
    }

    // Get user_id from the stored device code
    let user_id = stored.user_id.ok_or_else(|| {
        oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Approved device code has no user_id",
        )
    })?;

    // Mark as used
    #[cfg(feature = "seaorm")]
    {
        let row = yauth_entity::device_codes::Entity::find_by_id(stored.id)
            .one(&state.db).await
            .map_err(|e| { tracing::error!("DB error: {}", e); oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error") })?
            .ok_or_else(|| oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Device code disappeared"))?;
        let mut active: yauth_entity::device_codes::ActiveModel = row.into();
        active.status = Set("used".into());
        active.update(&state.db).await.map_err(|e| {
            tracing::error!("Failed to mark device code as used: {}", e);
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        diesel_db::update_device_code_status(&mut conn, stored.id, "used", stored.user_id).await.map_err(|e| {
            tracing::error!("Failed to mark device code as used: {}", e);
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
    }

    // Look up user — common struct for cross-backend
    #[allow(dead_code)]
    struct DeviceCodeUser {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        role: String,
        banned: bool,
    }

    #[cfg(feature = "seaorm")]
    let user = {
        let u = yauth_entity::users::Entity::find_by_id(user_id)
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
            })?
            .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;
        DeviceCodeUser {
            id: u.id, email: u.email, display_name: u.display_name,
            email_verified: u.email_verified, role: u.role, banned: u.banned,
        }
    };
    #[cfg(feature = "diesel-async")]
    let user = {
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        let u = diesel_db::find_user_by_id(&mut conn, user_id).await.map_err(|e| {
            tracing::error!("DB error: {}", e);
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?.ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;
        DeviceCodeUser {
            id: u.id, email: u.email, display_name: u.display_name,
            email_verified: u.email_verified, role: u.role, banned: u.banned,
        }
    };

    if user.banned {
        return Err(oauth2_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Account suspended",
        ));
    }

    // Parse scopes
    let scope_str = stored
        .scopes
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });

    // Issue tokens
    #[cfg(all(feature = "bearer", feature = "seaorm"))]
    {
        let bearer_config = &state.bearer_config;

        let user_model = yauth_entity::users::Model {
            id: user.id, email: user.email.clone(), display_name: user.display_name.clone(),
            email_verified: user.email_verified, role: user.role.clone(), banned: user.banned,
            banned_reason: None, banned_until: None,
            created_at: Utc::now().fixed_offset(), updated_at: Utc::now().fixed_offset(),
        };

        let (access_token, _jti) = crate::plugins::bearer::create_jwt_with_audience(
            &user_model,
            bearer_config,
            scope_str.as_deref(),
        )
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create token",
            )
        })?;

        let family_id = Uuid::new_v4();
        let refresh_token = create_refresh_token_for_oauth2(
            &state.db,
            user.id,
            family_id,
            bearer_config.refresh_token_ttl,
        )
        .await
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create refresh token",
            )
        })?;

        let expires_in = bearer_config.access_token_ttl.as_secs();

        info!(
            event = "oauth2_token_issued",
            user_id = %user.id,
            client_id = %client_id,
            "OAuth2 access token issued via device_code grant"
        );

        state
            .write_audit_log(
                Some(user.id),
                "oauth2_token_issued",
                Some(serde_json::json!({
                    "client_id": client_id,
                    "grant_type": "device_code",
                })),
                None,
            )
            .await;

        return Ok(Json(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            refresh_token,
            scope: scope_str,
        }));
    }

    #[cfg(all(feature = "bearer", feature = "diesel-async"))]
    {
        let bearer_config = &state.bearer_config;

        let jwt_user = crate::plugins::bearer::JwtUser {
            id: user.id,
            email: user.email.clone(),
            role: user.role.clone(),
        };

        let (access_token, _jti) = crate::plugins::bearer::create_jwt_with_audience_from_fields(
            &jwt_user,
            bearer_config,
            scope_str.as_deref(),
        )
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create token",
            )
        })?;

        let family_id = Uuid::new_v4();
        let mut conn = state.db.get().await.map_err(|_| {
            oauth2_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error")
        })?;
        let refresh_token = create_refresh_token_for_oauth2_diesel(
            &mut conn,
            user.id,
            family_id,
            bearer_config.refresh_token_ttl,
        )
        .await
        .map_err(|_| {
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create refresh token",
            )
        })?;

        let expires_in = bearer_config.access_token_ttl.as_secs();

        info!(
            event = "oauth2_token_issued",
            user_id = %user.id,
            client_id = %client_id,
            "OAuth2 access token issued via device_code grant"
        );

        state
            .write_audit_log(
                Some(user.id),
                "oauth2_token_issued",
                Some(serde_json::json!({
                    "client_id": client_id,
                    "grant_type": "device_code",
                })),
                None,
            )
            .await;

        return Ok(Json(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            refresh_token,
            scope: scope_str,
        }));
    }

    #[cfg(not(feature = "bearer"))]
    {
        let _ = user;
        Err::<Json<OAuth2TokenResponse>, _>(oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Bearer feature is required for OAuth2 token issuance",
        ))
    }
}

// ---------------------------------------------------------------------------
// Token Introspection (RFC 7662) — POST /oauth/introspect
// ---------------------------------------------------------------------------

async fn introspect_endpoint(
    State(state): State<YAuthState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let input: IntrospectRequest = match parse_json_or_form(&headers, &body) {
        Ok(v) => v,
        Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_request", &msg),
    };

    // Client authentication
    if let Err(e) = authenticate_client(
        &state,
        input.client_id.as_deref(),
        input.client_secret.as_deref(),
    )
    .await
    {
        return e;
    }

    let token = input.token.trim();
    if token.is_empty() {
        return Json(IntrospectResponse::inactive()).into_response();
    }

    // Determine token type to check. Default order: access_token first, then refresh_token.
    let hints = match input.token_type_hint.as_deref() {
        Some("refresh_token") => vec!["refresh_token", "access_token"],
        _ => vec!["access_token", "refresh_token"],
    };

    for hint in hints {
        match hint {
            "access_token" => {
                #[cfg(feature = "bearer")]
                {
                    let config = &state.bearer_config;
                    let mut validation =
                        jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
                    validation.validate_exp = true;
                    if let Some(ref expected_aud) = config.audience {
                        validation.set_audience(&[expected_aud]);
                    } else {
                        validation.validate_aud = false;
                    }

                    if let Ok(token_data) = jsonwebtoken::decode::<serde_json::Value>(
                        token,
                        &jsonwebtoken::DecodingKey::from_secret(config.jwt_secret.as_bytes()),
                        &validation,
                    ) {
                        let claims = &token_data.claims;
                        return Json(IntrospectResponse {
                            active: true,
                            sub: claims.get("sub").and_then(|v| v.as_str()).map(String::from),
                            client_id: claims.get("aud").and_then(|v| v.as_str()).map(String::from),
                            scope: claims
                                .get("scope")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            exp: claims.get("exp").and_then(|v| v.as_u64()),
                            iat: claims.get("iat").and_then(|v| v.as_u64()),
                            token_type: Some("access_token".into()),
                        })
                        .into_response();
                    }
                }
            }
            "refresh_token" => {
                let token_hash = crypto::hash_token(token);

                // Cross-backend: find refresh token and check active
                struct RefreshInfo {
                    user_id: Uuid,
                    expires_at: chrono::NaiveDateTime,
                    created_at: chrono::NaiveDateTime,
                    revoked: bool,
                }

                #[cfg(feature = "seaorm")]
                let rt_opt: Option<RefreshInfo> = {
                    yauth_entity::refresh_tokens::Entity::find()
                        .filter(yauth_entity::refresh_tokens::Column::TokenHash.eq(&token_hash))
                        .one(&state.db)
                        .await
                        .ok()
                        .flatten()
                        .map(|s| RefreshInfo {
                            user_id: s.user_id, expires_at: s.expires_at.naive_utc(),
                            created_at: s.created_at.naive_utc(), revoked: s.revoked,
                        })
                };
                #[cfg(feature = "diesel-async")]
                let rt_opt: Option<RefreshInfo> = {
                    let mut conn = match state.db.get().await {
                        Ok(c) => c,
                        Err(_) => { continue; }
                    };
                    diesel_db::find_refresh_token_by_hash(&mut conn, &token_hash)
                        .await
                        .ok()
                        .flatten()
                        .map(|s| RefreshInfo {
                            user_id: s.user_id, expires_at: s.expires_at,
                            created_at: s.created_at, revoked: s.revoked,
                        })
                };

                if let Some(stored) = rt_opt {
                    if !stored.revoked && stored.expires_at > Utc::now().naive_utc() {
                        return Json(IntrospectResponse {
                            active: true,
                            sub: Some(stored.user_id.to_string()),
                            client_id: None,
                            scope: None,
                            exp: Some(stored.expires_at.and_utc().timestamp() as u64),
                            iat: Some(stored.created_at.and_utc().timestamp() as u64),
                            token_type: Some("refresh_token".into()),
                        })
                        .into_response();
                    }
                }
            }
            _ => {}
        }
    }

    // Invalid or expired token — return inactive per RFC 7662
    Json(IntrospectResponse::inactive()).into_response()
}

// ---------------------------------------------------------------------------
// Token Revocation (RFC 7009) — POST /oauth/revoke
// ---------------------------------------------------------------------------

async fn revoke_endpoint(
    State(state): State<YAuthState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let input: RevokeTokenRequest = match parse_json_or_form(&headers, &body) {
        Ok(v) => v,
        // RFC 7009: always return 200
        Err(_) => return StatusCode::OK.into_response(),
    };

    // Client authentication
    if let Err(e) = authenticate_client(
        &state,
        input.client_id.as_deref(),
        input.client_secret.as_deref(),
    )
    .await
    {
        return e;
    }

    let token = input.token.trim();
    if token.is_empty() {
        return StatusCode::OK.into_response();
    }

    // Determine token type to try revoking. Default order: refresh_token first.
    let hints = match input.token_type_hint.as_deref() {
        Some("access_token") => vec!["access_token", "refresh_token"],
        _ => vec!["refresh_token", "access_token"],
    };

    for hint in &hints {
        match *hint {
            "refresh_token" => {
                let token_hash = crypto::hash_token(token);

                #[allow(dead_code)]
                struct RevokeInfo {
                    id: Uuid,
                    family_id: Uuid,
                    revoked: bool,
                }

                #[cfg(feature = "seaorm")]
                let rt_opt: Option<RevokeInfo> = {
                    yauth_entity::refresh_tokens::Entity::find()
                        .filter(yauth_entity::refresh_tokens::Column::TokenHash.eq(&token_hash))
                        .one(&state.db)
                        .await
                        .ok()
                        .flatten()
                        .map(|s| RevokeInfo { id: s.id, family_id: s.family_id, revoked: s.revoked })
                };
                #[cfg(feature = "diesel-async")]
                let rt_opt: Option<RevokeInfo> = {
                    let mut conn = match state.db.get().await {
                        Ok(c) => c,
                        Err(_) => { continue; }
                    };
                    diesel_db::find_refresh_token_by_hash(&mut conn, &token_hash)
                        .await
                        .ok()
                        .flatten()
                        .map(|s| RevokeInfo { id: s.id, family_id: s.family_id, revoked: s.revoked })
                };

                if let Some(stored) = rt_opt {
                    // Revoke this token and its entire family
                    #[cfg(all(feature = "bearer", feature = "seaorm"))]
                    revoke_family(&state.db, stored.family_id).await;

                    #[cfg(all(feature = "bearer", feature = "diesel-async"))]
                    {
                        let mut conn = state.db.get().await.ok();
                        if let Some(ref mut conn) = conn {
                            let _ = diesel_db::revoke_family(conn, stored.family_id).await;
                        }
                    }

                    #[cfg(not(feature = "bearer"))]
                    {
                        if !stored.revoked {
                            #[cfg(feature = "seaorm")]
                            {
                                if let Ok(Some(found)) = yauth_entity::refresh_tokens::Entity::find_by_id(stored.id)
                                    .one(&state.db).await
                                {
                                    let mut active: yauth_entity::refresh_tokens::ActiveModel = found.into();
                                    active.revoked = Set(true);
                                    let _ = active.update(&state.db).await;
                                }
                            }
                            #[cfg(feature = "diesel-async")]
                            {
                                let mut conn = state.db.get().await.ok();
                                if let Some(ref mut conn) = conn {
                                    let _ = diesel_db::revoke_refresh_token(conn, stored.id).await;
                                }
                            }
                        }
                    }

                    info!(
                        event = "oauth2_token_revoked",
                        token_type = "refresh_token",
                        "OAuth2 refresh token revoked"
                    );
                    return StatusCode::OK.into_response();
                }
            }
            "access_token" => {
                // Stateless JWTs cannot be revoked — just return 200 OK per RFC 7009
                // We still check if it looks like a valid JWT to match the hint
            }
            _ => {}
        }
    }

    // Per RFC 7009, always return 200 OK even for invalid tokens
    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// Client Credentials Grant (RFC 6749 §4.4) — via token_endpoint
// ---------------------------------------------------------------------------

#[allow(unused_variables, clippy::needless_return)]
async fn handle_client_credentials_grant(
    state: &YAuthState,
    input: &TokenCodeRequest,
) -> Result<impl IntoResponse, Response> {
    let client_id = input.client_id.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'client_id' parameter",
        )
    })?;
    let client_secret = input.client_secret.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing 'client_secret' parameter",
        )
    })?;

    // Look up client
    let client = lookup_client(state, client_id)
        .await
        .map_err(|e| e.into_response())?;

    // Authenticate client secret
    let secret_hash = client.client_secret_hash.as_deref().ok_or_else(|| {
        oauth2_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
        )
    })?;

    if !crypto::constant_time_eq(
        crypto::hash_token(client_secret).as_bytes(),
        secret_hash.as_bytes(),
    ) {
        warn!(
            event = "oauth2_client_auth_failed",
            client_id = %client_id,
            "Client credentials authentication failed"
        );
        return Err(oauth2_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
        ));
    }

    // Verify client has "client_credentials" in its grant_types
    let empty_arr = vec![];
    let grant_types = client
        .grant_types
        .as_array()
        .unwrap_or(&empty_arr)
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();

    if !grant_types.contains(&"client_credentials") {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "Client is not authorized for the client_credentials grant type",
        ));
    }

    // Verify requested scopes are a subset of client's registered scopes
    let registered_scopes: Vec<&str> = client
        .scopes
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let requested_scope = input.scope.as_deref();
    if let Some(scope_str) = requested_scope {
        for s in scope_str.split_whitespace() {
            if !registered_scopes.contains(&s) {
                return Err(oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    &format!("Scope '{}' is not registered for this client", s),
                ));
            }
        }
    }

    // Effective scope is only what was explicitly requested (don't auto-grant all scopes)
    let effective_scope = requested_scope;

    // Issue a JWT access token with sub = client_id (not a user ID)
    #[cfg(feature = "bearer")]
    {
        let bearer_config = &state.bearer_config;
        let now = Utc::now();
        let exp = (now + bearer_config.access_token_ttl).timestamp() as usize;
        let iat = now.timestamp() as usize;
        let jti = Uuid::new_v4().to_string();

        #[derive(Serialize)]
        struct ClientCredentialsClaims {
            sub: String,
            exp: usize,
            iat: usize,
            jti: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            aud: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            scope: Option<String>,
            client_id: String,
        }

        let claims = ClientCredentialsClaims {
            sub: client_id.to_string(),
            exp,
            iat,
            jti,
            aud: bearer_config.audience.clone(),
            scope: effective_scope.map(String::from),
            client_id: client_id.to_string(),
        };

        let access_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(bearer_config.jwt_secret.as_bytes()),
        )
        .map_err(|e| {
            tracing::error!("JWT encoding error: {}", e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create token",
            )
        })?;

        let expires_in = bearer_config.access_token_ttl.as_secs();

        info!(
            event = "oauth2_token_issued",
            client_id = %client_id,
            "OAuth2 access token issued via client_credentials grant"
        );

        state
            .write_audit_log(
                None,
                "oauth2_token_issued",
                Some(serde_json::json!({
                    "client_id": client_id,
                    "grant_type": "client_credentials",
                    "scope": effective_scope,
                })),
                None,
            )
            .await;

        return Ok(Json(OAuth2ClientCredentialsTokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            scope: effective_scope.map(String::from),
        }));
    }

    #[cfg(not(feature = "bearer"))]
    {
        Err::<Json<OAuth2ClientCredentialsTokenResponse>, _>(oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Bearer feature is required for client_credentials grant",
        ))
    }
}

// ---------------------------------------------------------------------------
// Client Authentication Helper
// ---------------------------------------------------------------------------

/// Authenticate a client by client_id + client_secret from the request body.
/// If client_id/client_secret are provided, validates them.
/// If neither is provided, succeeds (public client or no auth required).
async fn authenticate_client(
    state: &YAuthState,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> Result<(), Response> {
    match (client_id, client_secret) {
        (Some(cid), Some(secret)) => {
            let client = lookup_client(state, cid)
                .await
                .map_err(|e| e.into_response())?;

            if let Some(ref hash) = client.client_secret_hash
                && !crypto::constant_time_eq(crypto::hash_token(secret).as_bytes(), hash.as_bytes())
            {
                return Err(oauth2_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "Client authentication failed",
                ));
            }
            Ok(())
        }
        (Some(cid), None) => {
            // Client ID provided but no secret — verify client exists (public client)
            let _client = lookup_client(state, cid)
                .await
                .map_err(|e| e.into_response())?;
            Ok(())
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// PKCE S256 challenge: BASE64URL(SHA256(code_verifier))
fn pkce_s256_challenge(code_verifier: &str) -> String {
    use base64::Engine;
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

fn validate_authorize_params(params: &AuthorizeParams) -> Result<(), ApiError> {
    if params.response_type != "code" {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Only 'code' response_type is supported",
        ));
    }
    if params.code_challenge_method != "S256" {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Only 'S256' code_challenge_method is supported (PKCE required)",
        ));
    }
    if params.code_challenge.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "code_challenge is required (PKCE)",
        ));
    }
    Ok(())
}

fn validate_authorize_params_from_consent(input: &AuthorizeConsentRequest) -> Result<(), ApiError> {
    if input.response_type != "code" {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Only 'code' response_type is supported",
        ));
    }
    if input.code_challenge_method != "S256" {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Only 'S256' code_challenge_method is supported (PKCE required)",
        ));
    }
    if input.code_challenge.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "code_challenge is required (PKCE)",
        ));
    }
    Ok(())
}

/// Common client info struct used by both SeaORM and Diesel backends.
struct ClientInfo {
    client_id: String,
    client_secret_hash: Option<String>,
    redirect_uris: serde_json::Value,
    client_name: Option<String>,
    grant_types: serde_json::Value,
    scopes: Option<serde_json::Value>,
    #[allow(dead_code)]
    is_public: bool,
}

async fn lookup_client(
    state: &YAuthState,
    client_id: &str,
) -> Result<ClientInfo, ApiError> {
    #[cfg(feature = "seaorm")]
    {
        let m = yauth_entity::oauth2_clients::Entity::find()
            .filter(yauth_entity::oauth2_clients::Column::ClientId.eq(client_id))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error looking up client: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Unknown client_id"))?;
        Ok(ClientInfo {
            client_id: m.client_id, client_secret_hash: m.client_secret_hash,
            redirect_uris: m.redirect_uris, client_name: m.client_name,
            grant_types: m.grant_types, scopes: m.scopes, is_public: m.is_public,
        })
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state.db.get().await.map_err(|_| {
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
        let m = diesel_db::find_client_by_client_id(&mut conn, client_id)
            .await
            .map_err(|e| {
                tracing::error!("DB error looking up client: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Unknown client_id"))?;
        Ok(ClientInfo {
            client_id: m.client_id, client_secret_hash: m.client_secret_hash,
            redirect_uris: m.redirect_uris, client_name: m.client_name,
            grant_types: m.grant_types, scopes: m.scopes, is_public: m.is_public,
        })
    }
}

/// Resolve redirect_uri: if provided, validate against registered URIs.
/// If omitted, default to the client's single registered URI (RFC 6749 §3.1.2.3).
fn resolve_redirect_uri(
    client: &ClientInfo,
    redirect_uri: Option<&str>,
) -> Result<String, ApiError> {
    let empty = vec![];
    let registered_uris: Vec<&str> = client
        .redirect_uris
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    match redirect_uri {
        Some(uri) => {
            if !registered_uris.contains(&uri) {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "redirect_uri does not match any registered URIs",
                ));
            }
            Ok(uri.to_string())
        }
        None => {
            if registered_uris.len() == 1 {
                Ok(registered_uris[0].to_string())
            } else {
                Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "redirect_uri is required when multiple URIs are registered",
                ))
            }
        }
    }
}

fn validate_redirect_uri(
    client: &ClientInfo,
    redirect_uri: &str,
) -> Result<(), ApiError> {
    resolve_redirect_uri(client, Some(redirect_uri)).map(|_| ())
}

/// Authenticate a user from the request (session cookie or bearer token).
#[allow(clippy::collapsible_if)]
async fn authenticate_user(
    state: &YAuthState,
    jar: &axum_extra::extract::cookie::CookieJar,
    headers: &axum::http::HeaderMap,
) -> Result<AuthUser, ()> {
    // Try session cookie
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let token = cookie.value();
        if let Ok(Some(session_user)) =
            crate::auth::session::validate_session(state, token, None, None).await
        {
            #[cfg(feature = "seaorm")]
            if let Ok(Some(user)) = yauth_entity::users::Entity::find_by_id(session_user.user_id)
                .one(&state.db)
                .await
            {
                if !user.banned {
                    return Ok(AuthUser {
                        id: user.id,
                        email: user.email,
                        display_name: user.display_name,
                        email_verified: user.email_verified,
                        role: user.role,
                        banned: user.banned,
                        auth_method: crate::middleware::AuthMethod::Session,
                        scopes: None,
                    });
                }
            }
            #[cfg(feature = "diesel-async")]
            {
                let mut conn = match state.db.get().await {
                    Ok(c) => c,
                    Err(_) => return Err(()),
                };
                if let Ok(Some(user)) = diesel_db::find_user_by_id(&mut conn, session_user.user_id).await {
                    if !user.banned {
                        return Ok(AuthUser {
                            id: user.id,
                            email: user.email,
                            display_name: user.display_name,
                            email_verified: user.email_verified,
                            role: user.role,
                            banned: user.banned,
                            auth_method: crate::middleware::AuthMethod::Session,
                            scopes: None,
                        });
                    }
                }
            }
        }
    }

    // Try bearer token
    // Note: nested ifs are intentional — collapsing causes type inference failures (E0282)
    #[cfg(feature = "bearer")]
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                if let Ok(auth_user) = crate::plugins::bearer::validate_jwt(token, state).await {
                    return Ok(auth_user);
                }
            }
        }
    }

    let _ = headers;
    Err(())
}

async fn save_consent(
    state: &YAuthState,
    user_id: Uuid,
    client_id: &str,
    scopes: Option<serde_json::Value>,
) {
    #[cfg(feature = "seaorm")]
    {
        // Check if consent already exists and update, or create new
        let existing = yauth_entity::consents::Entity::find()
            .filter(yauth_entity::consents::Column::UserId.eq(user_id))
            .filter(yauth_entity::consents::Column::ClientId.eq(client_id))
            .one(&state.db)
            .await;

        match existing {
            Ok(Some(existing)) => {
                let mut active: yauth_entity::consents::ActiveModel = existing.into();
                active.scopes = Set(scopes);
                active.created_at = Set(Utc::now().fixed_offset());
                if let Err(e) = active.update(&state.db).await {
                    tracing::error!("Failed to update consent: {}", e);
                }
            }
            _ => {
                let consent = yauth_entity::consents::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user_id),
                    client_id: Set(client_id.to_string()),
                    scopes: Set(scopes),
                    created_at: Set(Utc::now().fixed_offset()),
                };
                if let Err(e) = consent.insert(&state.db).await {
                    tracing::error!("Failed to save consent: {}", e);
                }
            }
        }
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = match state.db.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Pool error saving consent: {}", e);
                return;
            }
        };
        let existing = diesel_db::find_consent(&mut conn, user_id, client_id).await;
        let now = Utc::now().fixed_offset();
        match existing {
            Ok(Some(existing)) => {
                if let Err(e) = diesel_db::update_consent(&mut conn, existing.id, scopes.as_ref(), now).await {
                    tracing::error!("Failed to update consent: {}", e);
                }
            }
            _ => {
                if let Err(e) = diesel_db::insert_consent(
                    &mut conn, Uuid::new_v4(), user_id, client_id, scopes.as_ref(), now,
                ).await {
                    tracing::error!("Failed to save consent: {}", e);
                }
            }
        }
    }
}

/// Create a refresh token for the OAuth2 flow (reuses bearer token storage).
#[cfg(all(feature = "bearer", feature = "seaorm"))]
async fn create_refresh_token_for_oauth2(
    db: &sea_orm::DatabaseConnection,
    user_id: Uuid,
    family_id: Uuid,
    ttl: std::time::Duration,
) -> Result<String, ApiError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::hash_token(&raw_token);
    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now()
        + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7)))
    .fixed_offset();

    let refresh = yauth_entity::refresh_tokens::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        token_hash: Set(token_hash),
        family_id: Set(family_id),
        expires_at: Set(expires_at),
        revoked: Set(false),
        created_at: Set(now),
    };

    refresh.insert(db).await.map_err(|e| {
        tracing::error!("Failed to create refresh token: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok(raw_token)
}

/// Create a refresh token for the OAuth2 flow (diesel-async backend).
#[cfg(all(feature = "bearer", feature = "diesel-async"))]
async fn create_refresh_token_for_oauth2_diesel(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    user_id: Uuid,
    family_id: Uuid,
    ttl: std::time::Duration,
) -> Result<String, ApiError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::hash_token(&raw_token);
    let now = Utc::now().fixed_offset();
    let expires_at = (Utc::now()
        + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7)))
    .fixed_offset();

    diesel_db::insert_refresh_token(
        conn, Uuid::new_v4(), user_id, &token_hash, family_id, expires_at, now,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create refresh token: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok(raw_token)
}

/// Revoke all refresh tokens in a family.
#[cfg(all(feature = "bearer", feature = "seaorm"))]
async fn revoke_family(db: &sea_orm::DatabaseConnection, family_id: Uuid) {
    use sea_orm::sea_query::Expr;

    if let Err(e) = yauth_entity::refresh_tokens::Entity::update_many()
        .col_expr(
            yauth_entity::refresh_tokens::Column::Revoked,
            Expr::value(true),
        )
        .filter(yauth_entity::refresh_tokens::Column::FamilyId.eq(family_id))
        .exec(db)
        .await
    {
        tracing::error!("Failed to revoke token family: {}", e);
    }
}

/// Return an OAuth2-compliant error response.
fn oauth2_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_spec() {
        // RFC 7636 Appendix B example
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_s256_different_verifiers_produce_different_challenges() {
        let c1 = pkce_s256_challenge("verifier-1");
        let c2 = pkce_s256_challenge("verifier-2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn validate_response_type_must_be_code() {
        let params = AuthorizeParams {
            response_type: "token".into(),
            client_id: "test".into(),
            redirect_uri: Some("http://localhost".into()),
            scope: None,
            state: None,
            code_challenge: "abc".into(),
            code_challenge_method: "S256".into(),
        };
        assert!(validate_authorize_params(&params).is_err());
    }

    #[test]
    fn validate_code_challenge_method_must_be_s256() {
        let params = AuthorizeParams {
            response_type: "code".into(),
            client_id: "test".into(),
            redirect_uri: Some("http://localhost".into()),
            scope: None,
            state: None,
            code_challenge: "abc".into(),
            code_challenge_method: "plain".into(),
        };
        assert!(validate_authorize_params(&params).is_err());
    }

    #[test]
    fn validate_valid_authorize_params() {
        let params = AuthorizeParams {
            response_type: "code".into(),
            client_id: "test".into(),
            redirect_uri: Some("http://localhost".into()),
            scope: Some("read write".into()),
            state: Some("xyz".into()),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            code_challenge_method: "S256".into(),
        };
        assert!(validate_authorize_params(&params).is_ok());
    }

    #[test]
    fn user_code_format_is_xxxx_dash_xxxx() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9); // 4 + 1 + 4
        assert_eq!(&code[4..5], "-");
    }

    #[test]
    fn user_code_uses_only_ambiguity_free_chars() {
        for _ in 0..100 {
            let code = generate_user_code();
            for ch in code.chars() {
                if ch == '-' {
                    continue;
                }
                assert!(
                    USER_CODE_ALPHABET.contains(&(ch as u8)),
                    "Unexpected character '{}' in user code",
                    ch
                );
            }
        }
    }

    #[test]
    fn user_code_excludes_ambiguous_chars() {
        // Run many iterations to check no 0, O, 1, I, L appear
        let ambiguous = b"0O1IL";
        for _ in 0..1000 {
            let code = generate_user_code();
            for ch in code.bytes() {
                if ch == b'-' {
                    continue;
                }
                assert!(
                    !ambiguous.contains(&ch),
                    "Ambiguous character '{}' in user code",
                    ch as char
                );
            }
        }
    }

    #[test]
    fn user_codes_are_unique() {
        let codes: std::collections::HashSet<String> =
            (0..100).map(|_| generate_user_code()).collect();
        // With 30^8 space, 100 codes should all be unique
        assert_eq!(codes.len(), 100);
    }

    #[test]
    fn introspect_response_inactive_has_false_active_and_none_fields() {
        let resp = IntrospectResponse::inactive();
        assert!(!resp.active);
        assert!(resp.sub.is_none());
        assert!(resp.client_id.is_none());
        assert!(resp.scope.is_none());
        assert!(resp.exp.is_none());
        assert!(resp.iat.is_none());
        assert!(resp.token_type.is_none());

        // Verify JSON serialization omits None fields
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json, serde_json::json!({"active": false}));
    }

    #[test]
    fn introspect_request_deserialization_json() {
        let json = r#"{"token":"abc123","token_type_hint":"access_token","client_id":"myapp","client_secret":"s3cret"}"#;
        let req: IntrospectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token, "abc123");
        assert_eq!(req.token_type_hint.as_deref(), Some("access_token"));
        assert_eq!(req.client_id.as_deref(), Some("myapp"));
        assert_eq!(req.client_secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn introspect_request_deserialization_json_minimal() {
        let json = r#"{"token":"xyz"}"#;
        let req: IntrospectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token, "xyz");
        assert!(req.token_type_hint.is_none());
        assert!(req.client_id.is_none());
        assert!(req.client_secret.is_none());
    }

    #[test]
    fn introspect_request_deserialization_form_urlencoded() {
        let form = "token=abc123&token_type_hint=access_token&client_id=myapp&client_secret=s3cret";
        let req: IntrospectRequest = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(req.token, "abc123");
        assert_eq!(req.token_type_hint.as_deref(), Some("access_token"));
        assert_eq!(req.client_id.as_deref(), Some("myapp"));
        assert_eq!(req.client_secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn introspect_request_deserialization_form_urlencoded_minimal() {
        let form = "token=xyz";
        let req: IntrospectRequest = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(req.token, "xyz");
        assert!(req.token_type_hint.is_none());
        assert!(req.client_id.is_none());
        assert!(req.client_secret.is_none());
    }

    #[test]
    fn revoke_token_request_deserialization_json() {
        let json = r#"{"token":"tok_abc","token_type_hint":"refresh_token","client_id":"app1","client_secret":"sec"}"#;
        let req: RevokeTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token, "tok_abc");
        assert_eq!(req.token_type_hint.as_deref(), Some("refresh_token"));
        assert_eq!(req.client_id.as_deref(), Some("app1"));
        assert_eq!(req.client_secret.as_deref(), Some("sec"));
    }

    #[test]
    fn revoke_token_request_deserialization_json_minimal() {
        let json = r#"{"token":"tok_xyz"}"#;
        let req: RevokeTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token, "tok_xyz");
        assert!(req.token_type_hint.is_none());
        assert!(req.client_id.is_none());
        assert!(req.client_secret.is_none());
    }

    #[test]
    fn revoke_token_request_deserialization_form_urlencoded() {
        let form = "token=tok_abc&token_type_hint=refresh_token&client_id=app1&client_secret=sec";
        let req: RevokeTokenRequest = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(req.token, "tok_abc");
        assert_eq!(req.token_type_hint.as_deref(), Some("refresh_token"));
        assert_eq!(req.client_id.as_deref(), Some("app1"));
        assert_eq!(req.client_secret.as_deref(), Some("sec"));
    }
}
