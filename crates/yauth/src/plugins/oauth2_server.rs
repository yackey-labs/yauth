use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::crypto;
use crate::config::OAuth2ServerConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

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

    // Resolve redirect_uri
    let redirect_uri = match resolve_redirect_uri(&client, params.redirect_uri.as_deref()) {
        Ok(uri) => uri,
        Err(e) => return e.into_response(),
    };

    // If a consent UI URL is configured and the request is from a browser, redirect
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

/// POST /oauth/authorize — user submits consent decision.
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
    let now = Utc::now();
    let expires_at = now
        + chrono::Duration::from_std(state.oauth2_server_config.authorization_code_ttl)
            .unwrap_or(chrono::Duration::seconds(60));

    let new_code = crate::domain::NewAuthorizationCode {
        id: Uuid::now_v7(),
        code_hash,
        client_id: input.client_id.clone(),
        user_id: auth_user.id,
        scopes: scopes_json,
        redirect_uri: input.redirect_uri.clone(),
        code_challenge: input.code_challenge.clone(),
        code_challenge_method: input.code_challenge_method.clone(),
        expires_at: expires_at.naive_utc(),
        used: false,
        nonce: None,
        created_at: now.naive_utc(),
    };

    if let Err(e) = state.repos.authorization_codes.create(new_code).await {
        crate::otel::record_error("oauth2_auth_code_store_failed", &e);
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
    }

    crate::otel::add_event(
        "oauth2_authorize_approved",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", auth_user.id.to_string()),
            opentelemetry::KeyValue::new("client.id", input.client_id.clone()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
    #[serde(deserialize_with = "deserialize_bool_or_string")]
    pub approved: bool,
}

// ---------------------------------------------------------------------------
// Token Endpoint (POST /oauth/token)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenCodeRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub device_code: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
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

    let stored_code = state
        .repos
        .authorization_codes
        .find_by_code_hash(&code_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?
        .ok_or_else(|| {
            crate::otel::add_event("oauth2_invalid_code", vec![]);
            oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid authorization code",
            )
        })?;

    // Check if code was already used
    if stored_code.used {
        crate::otel::add_event(
            "oauth2_code_reuse_detected",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("client.id", stored_code.client_id.clone()),
                opentelemetry::KeyValue::new("user.id", stored_code.user_id.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
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
        crate::otel::add_event("oauth2_code_expired", vec![]);
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
        crate::otel::add_event("oauth2_pkce_mismatch", vec![]);
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        ));
    }

    // Mark code as used
    state
        .repos
        .authorization_codes
        .mark_used(stored_code.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_auth_code_mark_used_failed", &e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?;

    // Look up user
    let user = state
        .repos
        .users
        .find_by_id(stored_code.user_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
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

    #[allow(unused_variables)]
    let has_openid_scope = scope_str
        .as_deref()
        .map(|s| s.split_whitespace().any(|sc| sc == "openid"))
        .unwrap_or(false);

    // Issue tokens using the bearer config (requires bearer feature)
    #[cfg(feature = "bearer")]
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

        let family_id = Uuid::now_v7();
        let refresh_token = create_refresh_token_for_oauth2(
            state,
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

        crate::otel::add_event(
            "oauth2_token_issued_auth_code",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                opentelemetry::KeyValue::new("client.id", client_id.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
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

        // Generate OIDC id_token when openid scope is present
        #[cfg(feature = "oidc")]
        let id_token = if has_openid_scope {
            Some(
                crate::plugins::oidc::generate_id_token_from_fields(
                    &user.id,
                    &user.email,
                    user.email_verified,
                    user.display_name.as_deref(),
                    state,
                    client_id,
                    stored_code.nonce.as_deref(),
                )
                .map_err(|e| {
                    crate::otel::record_error("oauth2_id_token_generate_failed", &e);
                    oauth2_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "Failed to generate id_token",
                    )
                })?,
            )
        } else {
            None
        };
        #[cfg(not(feature = "oidc"))]
        let id_token: Option<String> = None;

        return Ok(Json(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in,
            refresh_token,
            scope: scope_str,
            id_token,
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

        let stored = state
            .repos
            .refresh_tokens
            .find_by_token_hash(&token_hash)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
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
            crate::otel::add_event(
                "oauth2_refresh_token_reuse_detected",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new(
                    "token.family_id",
                    stored.family_id.to_string(),
                )],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            let _ = state
                .repos
                .refresh_tokens
                .revoke_family(stored.family_id)
                .await;
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
        state
            .repos
            .refresh_tokens
            .revoke(stored.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth2_refresh_token_revoke_failed", &e);
                oauth2_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal error",
                )
            })?;

        // Look up user
        let user = state
            .repos
            .users
            .find_by_id(user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
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

        let (access_token, _jti) = {
            let jwt_user = crate::plugins::bearer::JwtUser {
                id: user.id,
                email: user.email.clone(),
                role: user.role.clone(),
            };
            crate::plugins::bearer::create_jwt_with_audience_from_fields(
                &jwt_user,
                bearer_config,
                None,
            )
            .map_err(|_| {
                oauth2_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to create token",
                )
            })?
        };

        let new_refresh = create_refresh_token_for_oauth2(
            state,
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
            id_token: None,
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

    let client_id = Uuid::now_v7().to_string();
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

    let now = Utc::now();

    let new_client = crate::domain::NewOauth2Client {
        id: Uuid::now_v7(),
        client_id: client_id.clone(),
        client_secret_hash,
        redirect_uris: serde_json::json!(input.redirect_uris),
        client_name: input.client_name.clone(),
        grant_types: serde_json::json!(grant_types),
        scopes: scopes_json,
        is_public,
        created_at: now.naive_utc(),
    };

    state
        .repos
        .oauth2_clients
        .create(new_client)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_register_failed", &e);
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to register client",
            )
        })?;

    crate::otel::add_event(
        "oauth2_client_registered",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("client.id", client_id.to_string()),
            opentelemetry::KeyValue::new("client.name", format!("{:?}", input.client_name)),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
async fn generate_unique_user_code(state: &YAuthState) -> Result<String, ApiError> {
    for _ in 0..10 {
        let code = generate_user_code();
        let existing = state
            .repos
            .device_codes
            .find_by_user_code_pending(&code)
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth2_user_code_uniqueness_check_error", &e);
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

/// POST /oauth/device/code
async fn device_authorization(
    State(state): State<YAuthState>,
    Json(input): Json<DeviceAuthorizationRequest>,
) -> Response {
    if let Err(e) = lookup_client(&state, &input.client_id).await {
        return e.into_response();
    }

    let config = &state.oauth2_server_config;
    let interval = config.device_poll_interval;
    let ttl = config.device_code_ttl;

    let user_code = match generate_unique_user_code(&state).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let raw_device_code = crypto::generate_token();
    let device_code_hash = crypto::hash_token(&raw_device_code);

    let now = Utc::now();
    let expires_at =
        now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(600));

    let scopes_json = input
        .scope
        .as_ref()
        .map(|s| serde_json::json!(s.split_whitespace().collect::<Vec<_>>()));

    let new_dc = crate::domain::NewDeviceCode {
        id: Uuid::now_v7(),
        device_code_hash,
        user_code: user_code.clone(),
        client_id: input.client_id.clone(),
        scopes: scopes_json,
        user_id: None,
        status: "pending".to_string(),
        interval: interval as i32,
        expires_at: expires_at.naive_utc(),
        created_at: now.naive_utc(),
    };

    if let Err(e) = state.repos.device_codes.create(new_dc).await {
        crate::otel::record_error("oauth2_device_code_store_failed", &e);
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
    }

    let verification_uri = config
        .device_verification_uri
        .clone()
        .unwrap_or_else(|| format!("{}/oauth/device", config.issuer));

    let verification_uri_complete = Some(format!("{}?user_code={}", verification_uri, user_code));

    crate::otel::add_event(
        "oauth2_device_auth_initiated",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new(
            "client.id",
            input.client_id.clone(),
        )],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            None,
            "device_authorization_initiated",
            Some(serde_json::json!({ "client_id": input.client_id })),
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

/// GET /oauth/device
async fn device_verify_get(
    State(state): State<YAuthState>,
    Query(query): Query<DeviceVerifyQuery>,
) -> Response {
    if let Some(ref code) = query.user_code {
        let dc_result = state
            .repos
            .device_codes
            .find_by_user_code_pending(code)
            .await;

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
                let client_name = state
                    .repos
                    .oauth2_clients
                    .find_by_client_id(&dc.client_id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|c| c.client_name);

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
                crate::otel::record_error("oauth2_device_code_lookup_error", &e);
                return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    .into_response();
            }
        }
    }

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

/// POST /oauth/device
async fn device_verify_post(
    State(state): State<YAuthState>,
    jar: axum_extra::extract::cookie::CookieJar,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeviceVerifyRequest>,
) -> Response {
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

    let dc = match state
        .repos
        .device_codes
        .find_by_user_code_pending(&input.user_code)
        .await
    {
        Ok(Some(dc)) => dc,
        Ok(None) => {
            return oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or already used user code",
            );
        }
        Err(e) => {
            crate::otel::record_error("db_error", &e);
            return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let now_naive = Utc::now().naive_utc();
    if dc.expires_at < now_naive {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "Device code has expired",
        );
    }

    let new_status = if input.approved { "approved" } else { "denied" };
    let user_id = if input.approved {
        Some(auth_user.id)
    } else {
        None
    };

    if let Err(e) = state
        .repos
        .device_codes
        .update_status(dc.id, new_status, user_id)
        .await
    {
        crate::otel::record_error("oauth2_device_code_update_failed", &e);
        return api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
    }

    crate::otel::add_event(
        "oauth2_device_auth_decision",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", auth_user.id.to_string()),
            opentelemetry::KeyValue::new("approved", input.approved),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    state
        .write_audit_log(
            Some(auth_user.id),
            if input.approved {
                "device_authorization_approved"
            } else {
                "device_authorization_denied"
            },
            Some(serde_json::json!({ "user_code": input.user_code })),
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

    let _client = lookup_client(state, client_id)
        .await
        .map_err(|e| e.into_response())?;

    let device_code_hash = crypto::hash_token(device_code_raw);

    let stored = state
        .repos
        .device_codes
        .find_by_device_code_hash(&device_code_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
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
                "Invalid device code",
            )
        })?;

    if stored.client_id != client_id {
        return Err(oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Client ID mismatch",
        ));
    }

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
            let _ = state
                .repos
                .device_codes
                .update_interval(stored.id, stored.interval + 5)
                .await;
            return Err(oauth2_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "Polling too frequently, slow down",
            ));
        }
    }

    // Update last_polled_at
    let _ = state.repos.device_codes.update_last_polled(stored.id).await;

    match stored.status.as_str() {
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

    let user_id = stored.user_id.ok_or_else(|| {
        oauth2_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Approved device code has no user_id",
        )
    })?;

    // Mark as used
    state
        .repos
        .device_codes
        .update_status(stored.id, "used", stored.user_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_device_code_mark_used_failed", &e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?;

    // Look up user
    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
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

    #[cfg(feature = "bearer")]
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

        let family_id = Uuid::now_v7();
        let refresh_token = create_refresh_token_for_oauth2(
            state,
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

        crate::otel::add_event(
            "oauth2_token_issued_device_code",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                opentelemetry::KeyValue::new("client.id", client_id.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
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
            id_token: None,
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

                let rt_opt = state
                    .repos
                    .refresh_tokens
                    .find_by_token_hash(&token_hash)
                    .await
                    .ok()
                    .flatten();

                if let Some(stored) = rt_opt
                    && !stored.revoked
                    && stored.expires_at > Utc::now().naive_utc()
                {
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
            _ => {}
        }
    }

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
        Err(_) => return StatusCode::OK.into_response(),
    };

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

    let hints = match input.token_type_hint.as_deref() {
        Some("access_token") => vec!["access_token", "refresh_token"],
        _ => vec!["refresh_token", "access_token"],
    };

    for hint in &hints {
        match *hint {
            "refresh_token" => {
                let token_hash = crypto::hash_token(token);

                let rt_opt = state
                    .repos
                    .refresh_tokens
                    .find_by_token_hash(&token_hash)
                    .await
                    .ok()
                    .flatten();

                if let Some(stored) = rt_opt {
                    // Revoke this token and its entire family
                    #[cfg(feature = "bearer")]
                    {
                        let _ = state
                            .repos
                            .refresh_tokens
                            .revoke_family(stored.family_id)
                            .await;
                    }

                    #[cfg(not(feature = "bearer"))]
                    {
                        if !stored.revoked {
                            let _ = state.repos.refresh_tokens.revoke(stored.id).await;
                        }
                    }

                    crate::otel::add_event(
                        "oauth2_token_revoked",
                        #[cfg(feature = "telemetry")]
                        vec![opentelemetry::KeyValue::new("token.type", "refresh_token")],
                        #[cfg(not(feature = "telemetry"))]
                        vec![],
                    );
                    return StatusCode::OK.into_response();
                }
            }
            "access_token" => {
                // Stateless JWTs cannot be revoked — just return 200 OK per RFC 7009
            }
            _ => {}
        }
    }

    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// Client Credentials Grant (RFC 6749 §4.4)
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

    let client = lookup_client(state, client_id)
        .await
        .map_err(|e| e.into_response())?;

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
        crate::otel::add_event(
            "oauth2_client_auth_failed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "client.id",
                client_id.to_string(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(oauth2_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
        ));
    }

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

    let effective_scope = requested_scope;

    #[cfg(feature = "bearer")]
    {
        let bearer_config = &state.bearer_config;
        let now = Utc::now();
        let exp = (now + bearer_config.access_token_ttl).timestamp() as usize;
        let iat = now.timestamp() as usize;
        let jti = Uuid::now_v7().to_string();

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
            crate::otel::record_error("jwt_encoding_error", &e);
            oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to create token",
            )
        })?;

        let expires_in = bearer_config.access_token_ttl.as_secs();

        crate::otel::add_event(
            "oauth2_token_issued_client_credentials",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "client.id",
                client_id.to_string(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
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

async fn lookup_client(
    state: &YAuthState,
    client_id: &str,
) -> Result<crate::domain::Oauth2Client, ApiError> {
    state
        .repos
        .oauth2_clients
        .find_by_client_id(client_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth2_client_lookup_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Unknown client_id"))
}

fn resolve_redirect_uri(
    client: &crate::domain::Oauth2Client,
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
    client: &crate::domain::Oauth2Client,
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
            if let Ok(Some(user)) = state.repos.users.find_by_id(session_user.user_id).await {
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
    let existing = state
        .repos
        .consents
        .find_by_user_and_client(user_id, client_id)
        .await;
    match existing {
        Ok(Some(existing)) => {
            if let Err(e) = state
                .repos
                .consents
                .update_scopes(existing.id, scopes)
                .await
            {
                crate::otel::record_error("oauth2_consent_update_failed", &e);
            }
        }
        _ => {
            let new_consent = crate::domain::NewConsent {
                id: Uuid::now_v7(),
                user_id,
                client_id: client_id.to_string(),
                scopes,
                created_at: Utc::now().naive_utc(),
            };
            if let Err(e) = state.repos.consents.create(new_consent).await {
                crate::otel::record_error("oauth2_consent_save_failed", &e);
            }
        }
    }
}

/// Create a refresh token for the OAuth2 flow.
#[cfg(feature = "bearer")]
async fn create_refresh_token_for_oauth2(
    state: &YAuthState,
    user_id: Uuid,
    family_id: Uuid,
    ttl: std::time::Duration,
) -> Result<String, ApiError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::hash_token(&raw_token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

    let new_token = crate::domain::NewRefreshToken {
        id: Uuid::now_v7(),
        user_id,
        token_hash,
        family_id,
        expires_at: expires_at.naive_utc(),
        revoked: false,
        created_at: now.naive_utc(),
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
        assert_eq!(code.len(), 9);
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
