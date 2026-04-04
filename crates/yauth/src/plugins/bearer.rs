use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
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

    fn schema(&self) -> Vec<crate::schema::TableDef> {
        crate::schema::plugin_schemas::bearer_schema()
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TokenRequest {
    pub email: String,
    pub password: String,
    /// Optional space-separated OAuth2 scopes (e.g. "read:runs write:runs").
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
        crate::otel::record_error("jwt_encoding_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok((token, jti))
}

async fn create_refresh_token_repo(
    state: &YAuthState,
    user_id: Uuid,
    family_id: Uuid,
    ttl: std::time::Duration,
) -> Result<String, ApiError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::hash_token(&raw_token);
    let expires_at = (Utc::now()
        + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7)))
    .naive_utc();

    let new_token = crate::domain::NewRefreshToken {
        id: Uuid::new_v4(),
        user_id,
        token_hash,
        family_id,
        expires_at,
        revoked: false,
        created_at: Utc::now().naive_utc(),
    };

    state
        .repos
        .refresh_tokens
        .create(new_token)
        .await
        .map_err(|e| {
            crate::otel::record_error("refresh_token_create_failed", &e);
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
        crate::otel::add_event(
            "bearer_login_rate_limited",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    let (user_opt, hash) = {
        let user = state.repos.users.find_by_email(&email).await.map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        match user {
            Some(u) => {
                let pwd_hash = state
                    .repos
                    .refresh_tokens
                    .find_password_hash_by_user_id(u.id)
                    .await
                    .map_err(|e| {
                        crate::otel::record_error("db_error", &e);
                        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;
                let h = pwd_hash.unwrap_or_else(|| state.dummy_hash.clone());
                (Some(u), h)
            }
            None => (None, state.dummy_hash.clone()),
        }
    };

    let valid = password::verify_password(&input.password, &hash)
        .await
        .unwrap_or(false);

    match (user_opt, valid) {
        (Some(u), true) => {
            if u.banned {
                crate::otel::add_event(
                    "bearer_login_banned_user",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.email", u.email.clone())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            if !u.email_verified {
                crate::otel::add_event(
                    "bearer_login_email_not_verified",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.email", u.email.clone())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
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
                create_refresh_token_repo(&state, u.id, family_id, config.refresh_token_ttl)
                    .await?;

            let expires_in = config.access_token_ttl.as_secs();

            crate::otel::add_event(
                "bearer_login_succeeded",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("user.email", u.email.clone()),
                    opentelemetry::KeyValue::new("user.id", u.id.to_string()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
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
            crate::otel::add_event(
                "bearer_login_failed",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("user.email", email.clone())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
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

    let stored = state
        .repos
        .refresh_tokens
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let stored = match stored {
        Some(t) => t,
        None => {
            crate::otel::add_event("bearer_refresh_token_not_found", vec![]);
            return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid refresh token"));
        }
    };

    if stored.revoked {
        crate::otel::add_event(
            "bearer_refresh_token_reuse_detected",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("token.family_id", stored.family_id.to_string()),
                opentelemetry::KeyValue::new("user.id", stored.user_id.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        let _ = state
            .repos
            .refresh_tokens
            .revoke_family(stored.family_id)
            .await;
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Refresh token has been revoked",
        ));
    }

    let now_naive = Utc::now().naive_utc();
    if stored.expires_at < now_naive {
        crate::otel::add_event(
            "bearer_refresh_token_expired",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "user.id",
                stored.user_id.to_string(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Refresh token has expired",
        ));
    }

    let family_id = stored.family_id;
    let user_id = stored.user_id;

    // Revoke old token
    state
        .repos
        .refresh_tokens
        .revoke(stored.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("refresh_token_revoke_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // Look up user
    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "User not found"))?;

    if user.banned {
        crate::otel::add_event(
            "bearer_refresh_banned_user",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.id", user.id.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
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
        create_refresh_token_repo(&state, jwt_user.id, family_id, config.refresh_token_ttl).await?;

    let expires_in = config.access_token_ttl.as_secs();

    crate::otel::add_event(
        "bearer_refresh_token_rotated",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", jwt_user.id.to_string()),
            opentelemetry::KeyValue::new("token.family_id", family_id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
    headers: HeaderMap,
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

    let stored_opt = state
        .repos
        .refresh_tokens
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

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
        state
            .repos
            .refresh_tokens
            .revoke(stored.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("refresh_token_revoke_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    // Revoke the caller's access token JTI so it cannot be used for the
    // remainder of its TTL.  We extract the JTI from the Authorization
    // header that was used to authenticate this request.
    if let Some(jti) = extract_jti_from_auth_header(&headers, &state) {
        let ttl = state.bearer_config.access_token_ttl;
        if let Err(e) = state.revocation_store.revoke(&jti, ttl).await {
            crate::otel::record_error("bearer_jti_revoke_failed", &e);
        }
    }

    crate::otel::add_event(
        "bearer_token_revoked",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new(
            "user.id",
            auth_user.id.to_string(),
        )],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
    state
        .write_audit_log(Some(auth_user.id), "bearer_token_revoked", None, None)
        .await;

    Ok(Json(serde_json::json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// JTI extraction helper
// ---------------------------------------------------------------------------

/// Extract the `jti` claim from the Bearer token in the Authorization header.
/// Returns `None` if the header is absent, malformed, or the JWT cannot be decoded.
fn extract_jti_from_auth_header(headers: &HeaderMap, state: &YAuthState) -> Option<String> {
    let auth_header = headers.get("authorization")?;
    let header_str = auth_header.to_str().ok()?;
    let token = header_str.strip_prefix("Bearer ")?;

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
    .ok()?;

    Some(token_data.claims.jti)
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

    // Check JTI revocation before accepting the token
    if state
        .revocation_store
        .is_revoked(&claims.jti)
        .await
        .unwrap_or(false)
    {
        return Err("Token has been revoked".to_string());
    }

    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| "Invalid user ID in JWT".to_string())?;

    let scopes = claims
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect());

    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| format!("DB error during JWT validation: {}", e))?
        .ok_or_else(|| "User not found".to_string())?;

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
