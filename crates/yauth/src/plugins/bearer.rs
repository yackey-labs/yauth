use axum::{
    Extension, Json, Router, extract::State, http::StatusCode, response::IntoResponse,
    routing::post,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, password};
use crate::config::BearerConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::{AuthMethod, AuthUser};
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct BearerPlugin;

impl BearerPlugin {
    pub fn new(_config: BearerConfig) -> Self {
        Self
    }
}

impl YAuthPlugin for BearerPlugin {
    fn name(&self) -> &'static str {
        "bearer"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/token", post(create_token))
                .route("/token/refresh", post(refresh_token)),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/token/revoke", post(revoke_token)))
    }
}

// ---------------------------------------------------------------------------
// Diesel-async helpers
// ---------------------------------------------------------------------------

mod diesel_db {
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;
    use uuid::Uuid;

    type Conn = diesel_async_crate::AsyncPgConnection;
    type DbResult<T> = Result<T, String>;

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
    pub struct PasswordRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub password_hash: String,
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
    }

    pub async fn find_user_by_email(conn: &mut Conn, email: &str) -> DbResult<Option<UserRow>> {
        diesel::sql_query(
            "SELECT id, email, display_name, email_verified, role, banned FROM yauth_users WHERE email = $1",
        )
        .bind::<diesel::sql_types::Text, _>(email)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

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

    pub async fn find_password(conn: &mut Conn, user_id: Uuid) -> DbResult<Option<PasswordRow>> {
        diesel::sql_query("SELECT password_hash FROM yauth_passwords WHERE user_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(user_id)
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
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at) VALUES ($1, $2, $3, $4, $5, false, $6)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .bind::<diesel::sql_types::Uuid, _>(family_id)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn find_refresh_token_by_hash(
        conn: &mut Conn,
        token_hash: &str,
    ) -> DbResult<Option<RefreshTokenRow>> {
        diesel::sql_query(
            "SELECT id, user_id, token_hash, family_id, expires_at, revoked FROM yauth_refresh_tokens WHERE token_hash = $1",
        )
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
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
        diesel::sql_query("UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = $1")
            .bind::<diesel::sql_types::Uuid, _>(family_id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JWT Claims
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    role: String,
    exp: usize,
    iat: usize,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenRequest {
    pub email: String,
    pub password: String,
    /// Optional space-separated OAuth2 scopes (e.g. "read:runs write:runs").
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// JWT user info struct used for cross-backend JWT creation
pub struct JwtUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

/// Create a JWT from a JwtUser struct (backend-agnostic).
pub fn create_jwt_with_audience_from_fields(
    user: &JwtUser,
    config: &BearerConfig,
    scope: Option<&str>,
) -> Result<(String, String), ApiError> {
    create_jwt_internal(user, config, scope)
}

fn create_jwt_internal(
    user: &JwtUser,
    config: &BearerConfig,
    scope: Option<&str>,
) -> Result<(String, String), ApiError> {
    let now = Utc::now();
    let jti = Uuid::new_v4().to_string();
    let exp = (now + config.access_token_ttl).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        role: user.role.clone(),
        exp,
        iat,
        jti: jti.clone(),
        aud: config.audience.clone(),
        scope: scope.map(|s| s.to_string()),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| {
        tracing::error!("JWT encoding error: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok((token, jti))
}

async fn create_refresh_token_diesel(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    user_id: Uuid,
    family_id: Uuid,
    ttl: std::time::Duration,
) -> Result<String, ApiError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::hash_token(&raw_token);
    let expires_at = (Utc::now()
        + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7)))
    .fixed_offset();

    diesel_db::insert_refresh_token(
        conn,
        Uuid::new_v4(),
        user_id,
        &token_hash,
        family_id,
        expires_at,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create refresh token: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok(raw_token)
}

// ---------------------------------------------------------------------------
// POST /token
// ---------------------------------------------------------------------------

async fn create_token(
    State(state): State<YAuthState>,
    Json(input): Json<TokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let email = input.email.trim().to_lowercase();

    if !state
        .rate_limiter
        .check(&format!("bearer_login:{}", email))
        .await
    {
        warn!(event = "yauth.bearer.login.rate_limited", email = %email, "Bearer login rate limited");
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    struct TokenUser {
        id: Uuid,
        email: String,
        role: String,
        banned: bool,
        email_verified: bool,
    }

    let (user_opt, hash) = {
        let user = diesel_db::find_user_by_email(&mut conn, &email)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        match &user {
            Some(u) => {
                let pwd = diesel_db::find_password(&mut conn, u.id)
                    .await
                    .map_err(|e| {
                        tracing::error!("DB error: {}", e);
                        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;
                let h = pwd
                    .map(|p| p.password_hash)
                    .unwrap_or_else(|| state.dummy_hash.clone());
                (
                    Some(TokenUser {
                        id: u.id,
                        email: u.email.clone(),
                        role: u.role.clone(),
                        banned: u.banned,
                        email_verified: u.email_verified,
                    }),
                    h,
                )
            }
            None => (None, state.dummy_hash.clone()),
        }
    };

    let valid = password::verify_password(&input.password, &hash).unwrap_or(false);

    match (user_opt, valid) {
        (Some(u), true) => {
            if u.banned {
                warn!(event = "yauth.bearer.login.banned", email = %u.email, "Bearer login attempt by banned user");
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            if !u.email_verified {
                warn!(event = "yauth.bearer.login.email_not_verified", email = %u.email, "Bearer login attempt with unverified email");
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Email not verified. Please check your inbox or request a new verification email.",
                ));
            }

            let config = &state.bearer_config;
            let scope_str = input.scope.as_deref();
            let jwt_user = JwtUser {
                id: u.id,
                email: u.email.clone(),
                role: u.role.clone(),
            };
            let (access_token, _jti) = create_jwt_internal(&jwt_user, config, scope_str)?;

            let family_id = Uuid::new_v4();

            let refresh_token =
                create_refresh_token_diesel(&mut conn, u.id, family_id, config.refresh_token_ttl)
                    .await?;

            let expires_in = config.access_token_ttl.as_secs();

            info!(
                event = "yauth.bearer.login",
                email = %u.email,
                user_id = %u.id,
                "User authenticated via bearer token"
            );

            state
                .write_audit_log(
                    Some(u.id),
                    "login_succeeded",
                    Some(serde_json::json!({ "method": "bearer" })),
                    None,
                )
                .await;

            Ok(Json(TokenResponse {
                access_token,
                refresh_token,
                token_type: "Bearer".to_string(),
                expires_in,
            }))
        }
        _ => {
            warn!(event = "yauth.bearer.login.failed", email = %email, "Failed bearer login attempt");
            state.write_audit_log(
                None, "login_failed",
                Some(serde_json::json!({ "email": email, "method": "bearer", "reason": "invalid_credentials" })),
                None,
            ).await;
            Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Invalid email or password",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /token/refresh
// ---------------------------------------------------------------------------

async fn refresh_token(
    State(state): State<YAuthState>,
    Json(input): Json<RefreshRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let raw_token = input.refresh_token.trim();
    if raw_token.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Refresh token is required",
        ));
    }

    let token_hash = crypto::hash_token(raw_token);

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    struct StoredToken {
        id: Uuid,
        user_id: Uuid,
        family_id: Uuid,
        expires_at: chrono::NaiveDateTime,
        revoked: bool,
    }

    let stored = {
        let found = diesel_db::find_refresh_token_by_hash(&mut conn, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        match found {
            Some(t) => StoredToken {
                id: t.id,
                user_id: t.user_id,
                family_id: t.family_id,
                expires_at: t.expires_at,
                revoked: t.revoked,
            },
            None => {
                warn!(
                    event = "yauth.bearer.refresh.invalid",
                    "Refresh token not found"
                );
                return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid refresh token"));
            }
        }
    };

    if stored.revoked {
        warn!(
            event = "yauth.bearer.refresh.reuse_detected", family_id = %stored.family_id,
            user_id = %stored.user_id, "Refresh token reuse detected — revoking entire family"
        );
        {
            let _ = diesel_db::revoke_family(&mut conn, stored.family_id).await;
        }
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Refresh token has been revoked",
        ));
    }

    let now_naive = Utc::now().naive_utc();
    if stored.expires_at < now_naive {
        warn!(event = "yauth.bearer.refresh.expired", user_id = %stored.user_id, "Expired refresh token used");
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Refresh token has expired",
        ));
    }

    let family_id = stored.family_id;
    let user_id = stored.user_id;

    // Revoke old token
    {
        diesel_db::revoke_refresh_token(&mut conn, stored.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke old refresh token: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    // Look up user
    struct RefreshUser {
        id: Uuid,
        email: String,
        role: String,
        banned: bool,
    }

    let user = {
        let u = diesel_db::find_user_by_id(&mut conn, user_id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "User not found"))?;
        RefreshUser {
            id: u.id,
            email: u.email,
            role: u.role,
            banned: u.banned,
        }
    };

    if user.banned {
        warn!(event = "yauth.bearer.refresh.banned", user_id = %user.id, "Refresh attempt by banned user");
        return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
    }

    let config = &state.bearer_config;
    let jwt_user = JwtUser {
        id: user.id,
        email: user.email,
        role: user.role,
    };
    let (access_token, _jti) = create_jwt_internal(&jwt_user, config, None)?;

    let new_refresh =
        create_refresh_token_diesel(&mut conn, jwt_user.id, family_id, config.refresh_token_ttl)
            .await?;

    let expires_in = config.access_token_ttl.as_secs();

    info!(
        event = "yauth.bearer.refresh", user_id = %jwt_user.id,
        family_id = %family_id, "Refresh token rotated"
    );

    Ok(Json(TokenResponse {
        access_token,
        refresh_token: new_refresh,
        token_type: "Bearer".to_string(),
        expires_in,
    }))
}

// ---------------------------------------------------------------------------
// POST /token/revoke
// ---------------------------------------------------------------------------

async fn revoke_token(
    State(state): State<YAuthState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(input): Json<RevokeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let raw_token = input.refresh_token.trim();
    if raw_token.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Refresh token is required",
        ));
    }

    let token_hash = crypto::hash_token(raw_token);

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    struct StoredInfo {
        user_id: Uuid,
        revoked: bool,
        id: Uuid,
    }

    let stored_opt = {
        let found = diesel_db::find_refresh_token_by_hash(&mut conn, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        found.map(|t| StoredInfo {
            user_id: t.user_id,
            revoked: t.revoked,
            id: t.id,
        })
    };

    let stored = match stored_opt {
        Some(t) => t,
        None => return Ok(Json(serde_json::json!({ "success": true }))),
    };

    if stored.user_id != auth_user.id && auth_user.role != "admin" {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Cannot revoke another user's token",
        ));
    }

    if !stored.revoked {
        {
            diesel_db::revoke_refresh_token(&mut conn, stored.id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to revoke refresh token: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;
        }
    }

    info!(event = "yauth.bearer.revoked", user_id = %auth_user.id, "Refresh token revoked");
    state
        .write_audit_log(Some(auth_user.id), "bearer_token_revoked", None, None)
        .await;

    Ok(Json(serde_json::json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// JWT validation — called from auth middleware
// ---------------------------------------------------------------------------

pub async fn validate_jwt(token: &str, state: &YAuthState) -> Result<AuthUser, String> {
    let config = &state.bearer_config;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    if let Some(ref expected_aud) = config.audience {
        validation.set_audience(&[expected_aud]);
    } else {
        validation.validate_aud = false;
    }

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| format!("JWT validation failed: {}", e))?;

    let claims = token_data.claims;
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| "Invalid user ID in JWT".to_string())?;

    let scopes = claims
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect());

    let user = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|e| format!("Pool error: {}", e))?;
        diesel_db::find_user_by_id(&mut conn, user_id)
            .await
            .map_err(|e| format!("DB error during JWT validation: {}", e))?
            .ok_or_else(|| "User not found".to_string())?
    };

    if user.banned {
        return Err("Account suspended".to_string());
    }

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        role: user.role,
        banned: user.banned,
        auth_method: AuthMethod::Bearer,
        scopes,
    })
}
