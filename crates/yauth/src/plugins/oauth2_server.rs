use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::Utc;
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
                .route("/oauth/token", post(token_authorization_code))
                .route("/oauth/register", post(dynamic_client_registration)),
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
    registration_endpoint: Option<String>,
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

    Json(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", issuer),
        token_endpoint: format!("{}/oauth/token", issuer),
        registration_endpoint,
        scopes_supported: config.scopes_supported.clone(),
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
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
/// redirect_uri with the code.
async fn authorize_post(
    State(state): State<YAuthState>,
    jar: axum_extra::extract::cookie::CookieJar,
    headers: axum::http::HeaderMap,
    Json(input): Json<AuthorizeConsentRequest>,
) -> Response {
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

    let auth_code = yauth_entity::authorization_codes::ActiveModel {
        id: Set(Uuid::new_v4()),
        code_hash: Set(code_hash),
        client_id: Set(input.client_id.clone()),
        user_id: Set(auth_user.id),
        scopes: Set(scopes_json),
        redirect_uri: Set(input.redirect_uri.clone()),
        code_challenge: Set(input.code_challenge.clone()),
        code_challenge_method: Set(input.code_challenge_method.clone()),
        expires_at: Set(expires_at),
        used: Set(false),
        created_at: Set(now),
    };

    if let Err(e) = auth_code.insert(&state.db).await {
        tracing::error!("Failed to store authorization code: {}", e);
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
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

async fn token_authorization_code(
    State(state): State<YAuthState>,
    Json(input): Json<TokenCodeRequest>,
) -> Response {
    match input.grant_type.as_str() {
        "authorization_code" => match handle_authorization_code_grant(&state, &input).await {
            Ok(resp) => resp.into_response(),
            Err(e) => e,
        },
        "refresh_token" => match handle_oauth2_refresh_token(&state, &input).await {
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
    let stored_code = yauth_entity::authorization_codes::Entity::find()
        .filter(yauth_entity::authorization_codes::Column::CodeHash.eq(&code_hash))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?
        .ok_or_else(|| {
            warn!(
                event = "oauth2_invalid_code",
                "Authorization code not found"
            );
            oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid authorization code",
            )
        })?;

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
    let now = Utc::now().fixed_offset();
    if stored_code.expires_at < now {
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
    let mut active: yauth_entity::authorization_codes::ActiveModel = stored_code.clone().into();
    active.used = Set(true);
    active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to mark auth code as used: {}", e);
        oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Internal error",
        )
    })?;

    // Look up user
    let user = yauth_entity::users::Entity::find_by_id(stored_code.user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?
        .ok_or_else(|| oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found"))?;

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
    #[cfg(feature = "bearer")]
    {
        let bearer_config = &state.bearer_config;

        let (access_token, _jti) = crate::plugins::bearer::create_jwt_with_audience(
            &user,
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

    #[cfg(not(feature = "bearer"))]
    {
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

        // Find the refresh token
        let stored = yauth_entity::refresh_tokens::Entity::find()
            .filter(yauth_entity::refresh_tokens::Column::TokenHash.eq(&token_hash))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal error",
                )
            })?
            .ok_or_else(|| {
                oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Invalid refresh token",
                )
            })?;

        if stored.revoked {
            warn!(
                event = "oauth2_refresh_reuse",
                family_id = %stored.family_id,
                "Refresh token reuse detected — revoking family"
            );
            revoke_family(&state.db, stored.family_id).await;
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token has been revoked",
            ));
        }

        let now = Utc::now().fixed_offset();
        if stored.expires_at < now {
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token has expired",
            ));
        }

        // Revoke old token
        let family_id = stored.family_id;
        let user_id = stored.user_id;
        let mut active: yauth_entity::refresh_tokens::ActiveModel = stored.into();
        active.revoked = Set(true);
        active.update(&state.db).await.map_err(|e| {
            tracing::error!("Failed to revoke old refresh token: {}", e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?;

        // Look up user
        let user = yauth_entity::users::Entity::find_by_id(user_id)
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                oauth2_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal error",
                )
            })?
            .ok_or_else(|| {
                oauth2_error(StatusCode::BAD_REQUEST, "invalid_grant", "User not found")
            })?;

        if user.banned {
            return Err(oauth2_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Account suspended",
            ));
        }

        let bearer_config = &state.bearer_config;
        let (access_token, _jti) =
            crate::plugins::bearer::create_jwt_with_audience(&user, bearer_config, None).map_err(
                |_| {
                    oauth2_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "Failed to create token",
                    )
                },
            )?;

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

    let client = yauth_entity::oauth2_clients::ActiveModel {
        id: Set(Uuid::new_v4()),
        client_id: Set(client_id.clone()),
        client_secret_hash: Set(client_secret_hash),
        redirect_uris: Set(serde_json::json!(input.redirect_uris)),
        client_name: Set(input.client_name.clone()),
        grant_types: Set(serde_json::json!(grant_types)),
        scopes: Set(scopes_json),
        is_public: Set(is_public),
        created_at: Set(now),
    };

    client.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to register client: {}", e);
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to register client",
        )
    })?;

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

async fn lookup_client(
    state: &YAuthState,
    client_id: &str,
) -> Result<yauth_entity::oauth2_clients::Model, ApiError> {
    yauth_entity::oauth2_clients::Entity::find()
        .filter(yauth_entity::oauth2_clients::Column::ClientId.eq(client_id))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error looking up client: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Unknown client_id"))
}

/// Resolve redirect_uri: if provided, validate against registered URIs.
/// If omitted, default to the client's single registered URI (RFC 6749 §3.1.2.3).
fn resolve_redirect_uri(
    client: &yauth_entity::oauth2_clients::Model,
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
    client: &yauth_entity::oauth2_clients::Model,
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
            crate::auth::session::validate_session(&state.db, token).await
        {
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

/// Create a refresh token for the OAuth2 flow (reuses bearer token storage).
#[cfg(feature = "bearer")]
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

/// Revoke all refresh tokens in a family.
#[cfg(feature = "bearer")]
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
}
