use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{crypto, session};
use crate::config::OAuthProviderConfig;
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

const STATE_EXPIRY_MINUTES: i64 = 10;

pub struct OAuthPlugin;

impl YAuthPlugin for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/oauth/{provider}/authorize", get(authorize))
                .route("/oauth/{provider}/callback", get(callback_get))
                .route("/oauth/{provider}/callback", post(callback_post)),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/oauth/accounts", get(list_accounts))
                .route("/oauth/{provider}", delete(unlink_provider))
                .route("/oauth/{provider}/link", post(start_link)),
        )
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ApiError = (StatusCode, Json<serde_json::Value>);

fn api_err(status: StatusCode, msg: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    redirect_url: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct CallbackBody {
    code: String,
    state: String,
}

/// Common userinfo fields parsed from the provider's response.
#[derive(Debug, Deserialize)]
struct ProviderUserInfo {
    id: String,
    email: Option<String>,
    name: Option<String>,
}

#[derive(Serialize)]
struct OAuthAccountResponse {
    id: String,
    provider: String,
    provider_user_id: String,
    created_at: String,
}

#[derive(Serialize)]
struct AuthResponse {
    user_id: String,
    email: String,
    display_name: Option<String>,
    email_verified: bool,
}

#[derive(Serialize)]
struct AuthorizeResponse {
    auth_url: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_provider_config<'a>(
    state: &'a YAuthState,
    provider: &str,
) -> Result<&'a OAuthProviderConfig, ApiError> {
    state
        .oauth_config
        .providers
        .iter()
        .find(|p| p.name == provider)
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "Unknown OAuth provider"))
}

fn build_oauth_client(
    provider_config: &OAuthProviderConfig,
    redirect_uri: &str,
) -> Result<
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    ApiError,
> {
    let client = BasicClient::new(ClientId::new(provider_config.client_id.clone()))
        .set_client_secret(ClientSecret::new(provider_config.client_secret.clone()))
        .set_auth_uri(AuthUrl::new(provider_config.auth_url.clone()).map_err(|e| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Invalid auth URL: {}", e),
            )
        })?)
        .set_token_uri(
            TokenUrl::new(provider_config.token_url.clone()).map_err(|e| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Invalid token URL: {}", e),
                )
            })?,
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).map_err(|e| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Invalid redirect URL: {}", e),
            )
        })?);
    Ok(client)
}

/// Store a state parameter in the database with a 10-minute expiry.
async fn store_state(
    state: &YAuthState,
    state_token: &str,
    provider: &str,
    redirect_url: Option<&str>,
) -> Result<(), ApiError> {
    let now = chrono::Utc::now().fixed_offset();
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::minutes(STATE_EXPIRY_MINUTES)).fixed_offset();

    let oauth_state = yauth_entity::oauth_states::ActiveModel {
        state: Set(state_token.to_string()),
        provider: Set(provider.to_string()),
        redirect_url: Set(redirect_url.map(|s| s.to_string())),
        expires_at: Set(expires_at),
        created_at: Set(now),
    };

    oauth_state.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to store OAuth state: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok(())
}

/// Validate and consume a state parameter from the database.
/// Returns the stored state row on success, deleting it (one-time use).
async fn consume_state(
    state: &YAuthState,
    state_token: &str,
    expected_provider: &str,
) -> Result<yauth_entity::oauth_states::Model, ApiError> {
    let stored = yauth_entity::oauth_states::Entity::find_by_id(state_token.to_string())
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error looking up OAuth state: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            warn!(
                event = "oauth_state_invalid",
                "OAuth state parameter not found"
            );
            api_err(
                StatusCode::BAD_REQUEST,
                "Invalid or expired state parameter",
            )
        })?;

    // Delete the state immediately (one-time use)
    yauth_entity::oauth_states::Entity::delete_by_id(state_token.to_string())
        .exec(&state.db)
        .await
        .ok();

    // Check expiry
    let now = chrono::Utc::now().fixed_offset();
    if stored.expires_at < now {
        warn!(
            event = "oauth_state_expired",
            "OAuth state parameter expired"
        );
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "State parameter has expired. Please try again.",
        ));
    }

    // Check provider matches
    if stored.provider != expected_provider {
        warn!(
            event = "oauth_state_provider_mismatch",
            expected = %expected_provider,
            actual = %stored.provider,
            "OAuth state provider mismatch"
        );
        return Err(api_err(StatusCode::BAD_REQUEST, "State parameter mismatch"));
    }

    Ok(stored)
}

/// Parse the userinfo JSON response from a provider into a common struct.
fn parse_userinfo(provider: &str, json: &serde_json::Value) -> Result<ProviderUserInfo, ApiError> {
    let id = match provider {
        "github" => {
            // GitHub returns `id` as a number
            json.get("id")
                .and_then(|v| {
                    if v.is_number() {
                        Some(v.to_string())
                    } else {
                        v.as_str().map(|s| s.to_string())
                    }
                })
                .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "Missing id from provider"))?
        }
        "google" => {
            // Google uses `sub`
            json.get("sub")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "Missing sub from provider"))?
        }
        _ => {
            // Generic: try `id`, then `sub`
            json.get("id")
                .or_else(|| json.get("sub"))
                .and_then(|v| {
                    if v.is_string() {
                        v.as_str().map(|s| s.to_string())
                    } else {
                        Some(v.to_string())
                    }
                })
                .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "Missing id from provider"))?
        }
    };

    let email = json
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let name = json
        .get("name")
        .or_else(|| json.get("login"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(ProviderUserInfo { id, email, name })
}

/// Fetch user info from the provider using the access token.
async fn fetch_userinfo(
    provider_config: &OAuthProviderConfig,
    access_token: &str,
) -> Result<serde_json::Value, ApiError> {
    let http_client = reqwest::Client::new();
    let resp = http_client
        .get(&provider_config.userinfo_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        // GitHub API requires a User-Agent header
        .header("User-Agent", "yauth")
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch userinfo: {}", e);
            api_err(
                StatusCode::BAD_GATEWAY,
                "Failed to fetch user info from provider",
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(
            event = "oauth_userinfo_error",
            status = %status,
            body = %body,
            "Provider userinfo endpoint returned error"
        );
        return Err(api_err(
            StatusCode::BAD_GATEWAY,
            "Provider returned an error when fetching user info",
        ));
    }

    resp.json::<serde_json::Value>().await.map_err(|e| {
        tracing::error!("Failed to parse userinfo JSON: {}", e);
        api_err(StatusCode::BAD_GATEWAY, "Invalid response from provider")
    })
}

fn session_set_cookie(state: &YAuthState, token: &str) -> String {
    let max_age = state.config.session_ttl.as_secs();
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        state.config.session_cookie_name, token, max_age
    );
    if state.config.secure_cookies {
        cookie.push_str("; Secure");
    }
    if let Some(ref domain) = state.config.cookie_domain {
        cookie.push_str(&format!("; Domain={}", domain));
    }
    cookie
}

/// Core callback logic shared by GET and POST handlers.
/// Returns `(user_id, email, display_name, email_verified, session_token, redirect_url)`.
async fn handle_callback(
    state: &YAuthState,
    provider: &str,
    code: &str,
    state_param: &str,
) -> Result<(String, String, Option<String>, bool, String, Option<String>), ApiError> {
    // 1. Validate and consume state
    let stored_state = consume_state(state, state_param, provider).await?;

    // 2. Find provider config
    let provider_config = find_provider_config(state, provider)?;

    // 3. Build redirect URI for the token exchange
    let redirect_uri = format!(
        "{}/oauth/{}/callback",
        state.config.base_url.trim_end_matches('/'),
        provider
    );

    // 4. Build OAuth client and exchange code for token
    let client = build_oauth_client(provider_config, &redirect_uri)?;

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build HTTP client: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!(event = "oauth_token_exchange_error", error = %e, "OAuth token exchange failed");
            api_err(StatusCode::BAD_GATEWAY, "Failed to exchange authorization code")
        })?;

    let access_token = token_result.access_token().secret().clone();
    let refresh_token = token_result.refresh_token().map(|t| t.secret().clone());

    // 5. Fetch user info from provider
    let userinfo_json = fetch_userinfo(provider_config, &access_token).await?;
    let userinfo = parse_userinfo(provider, &userinfo_json)?;

    // 6. Check if this is an account-linking callback
    //    We encode `link:<user_id>` in the redirect_url field for linking flows
    let link_to_user_id = stored_state
        .redirect_url
        .as_deref()
        .and_then(|url| url.strip_prefix("link:"))
        .and_then(|id| Uuid::parse_str(id).ok());

    if let Some(link_user_id) = link_to_user_id {
        // Account linking flow: link this OAuth account to the existing user
        let existing_link = yauth_entity::oauth_accounts::Entity::find()
            .filter(yauth_entity::oauth_accounts::Column::Provider.eq(provider))
            .filter(yauth_entity::oauth_accounts::Column::ProviderUserId.eq(&userinfo.id))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        if existing_link.is_some() {
            return Err(api_err(
                StatusCode::CONFLICT,
                "This provider account is already linked to a user",
            ));
        }

        let now = chrono::Utc::now().fixed_offset();
        let oauth_account = yauth_entity::oauth_accounts::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(link_user_id),
            provider: Set(provider.to_string()),
            provider_user_id: Set(userinfo.id.clone()),
            access_token_enc: Set(Some(access_token)),
            refresh_token_enc: Set(refresh_token),
            created_at: Set(now),
        };

        oauth_account.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to link OAuth account: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        // Look up the user to return info
        let user = yauth_entity::users::Entity::find_by_id(link_user_id)
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

        let (token, _session_id) = session::create_session(&state.db, user.id, None, None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create session: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        info!(
            event = "oauth_account_linked",
            user_id = %user.id,
            provider = %provider,
            "OAuth account linked"
        );

        return Ok((
            user.id.to_string(),
            user.email,
            user.display_name,
            user.email_verified,
            token,
            None, // no redirect for linking flow
        ));
    }

    // 7. Look up existing OAuth account
    let existing_account = yauth_entity::oauth_accounts::Entity::find()
        .filter(yauth_entity::oauth_accounts::Column::Provider.eq(provider))
        .filter(yauth_entity::oauth_accounts::Column::ProviderUserId.eq(&userinfo.id))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let (user_id, email, display_name, email_verified) = if let Some(account) = existing_account {
        // Existing OAuth account — update tokens and create session
        let mut active: yauth_entity::oauth_accounts::ActiveModel = account.clone().into();
        active.access_token_enc = Set(Some(access_token));
        active.refresh_token_enc = Set(refresh_token);
        active.update(&state.db).await.map_err(|e| {
            tracing::error!("Failed to update OAuth tokens: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        let user = yauth_entity::users::Entity::find_by_id(account.user_id)
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

        if user.banned {
            warn!(event = "oauth_login_banned", provider = %provider, user_id = %user.id, "OAuth login attempt by banned user");
            return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
        }

        info!(
            event = "oauth_login_success",
            user_id = %user.id,
            provider = %provider,
            "User logged in via OAuth"
        );

        (user.id, user.email, user.display_name, user.email_verified)
    } else {
        // New user — create user and OAuth account
        let email = userinfo.email.ok_or_else(|| {
            warn!(event = "oauth_no_email", provider = %provider, "OAuth provider did not return email");
            api_err(
                StatusCode::BAD_REQUEST,
                "Email not provided by OAuth provider. Please ensure your account has a verified email.",
            )
        })?;
        let email = email.trim().to_lowercase();

        let now = chrono::Utc::now().fixed_offset();
        let user_id = Uuid::new_v4();

        // Check if a user with this email already exists
        let existing_user = yauth_entity::users::Entity::find()
            .filter(yauth_entity::users::Column::Email.eq(&email))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let (uid, display_name, email_verified) = if let Some(existing) = existing_user {
            // User exists with same email — link OAuth account to existing user
            (existing.id, existing.display_name, existing.email_verified)
        } else {
            // Create new user
            let user = yauth_entity::users::ActiveModel {
                id: Set(user_id),
                email: Set(email.clone()),
                display_name: Set(userinfo.name.clone()),
                email_verified: Set(true), // OAuth emails are considered verified
                role: Set("user".to_string()),
                banned: Set(false),
                banned_reason: Set(None),
                banned_until: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };

            user.insert(&state.db).await.map_err(|e| {
                tracing::error!("Failed to create user: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

            (user_id, userinfo.name.clone(), true)
        };

        // Create OAuth account link
        let oauth_account = yauth_entity::oauth_accounts::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(uid),
            provider: Set(provider.to_string()),
            provider_user_id: Set(userinfo.id.clone()),
            access_token_enc: Set(Some(access_token)),
            refresh_token_enc: Set(refresh_token),
            created_at: Set(now),
        };

        oauth_account.insert(&state.db).await.map_err(|e| {
            tracing::error!("Failed to create OAuth account: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        info!(
            event = "oauth_register_success",
            user_id = %uid,
            provider = %provider,
            "New user registered via OAuth"
        );

        (uid, email, display_name, email_verified)
    };

    // 8. Create session
    let (token, _session_id) = session::create_session(&state.db, user_id, None, None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    Ok((
        user_id.to_string(),
        email,
        display_name,
        email_verified,
        token,
        stored_state.redirect_url,
    ))
}

// ---------------------------------------------------------------------------
// Public routes
// ---------------------------------------------------------------------------

/// GET /oauth/{provider}/authorize — Generate auth URL, redirect user
async fn authorize(
    State(state): State<YAuthState>,
    Path(provider): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let provider_config = find_provider_config(&state, &provider)?;

    // Generate state token
    let state_token = crypto::generate_token();

    // Store state in DB
    store_state(
        &state,
        &state_token,
        &provider,
        query.redirect_url.as_deref(),
    )
    .await?;

    // Build redirect URI
    let redirect_uri = format!(
        "{}/oauth/{}/callback",
        state.config.base_url.trim_end_matches('/'),
        provider
    );

    let client = build_oauth_client(provider_config, &redirect_uri)?;

    // Build authorization URL
    let state_token_clone = state_token.clone();
    let mut auth_request = client.authorize_url(move || CsrfToken::new(state_token_clone));

    for scope in &provider_config.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, _csrf_token) = auth_request.url();

    info!(
        event = "oauth_authorize_start",
        provider = %provider,
        "OAuth authorization flow started"
    );

    Ok(Redirect::temporary(auth_url.as_str()))
}

/// GET /oauth/{provider}/callback — Handle OAuth callback (browser redirect)
async fn callback_get(
    State(state): State<YAuthState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // Check for error from provider
    if let Some(ref error) = query.error {
        let desc = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        warn!(
            event = "oauth_callback_error",
            provider = %provider,
            error = %error,
            description = %desc,
            "OAuth provider returned error"
        );
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!("OAuth error: {} - {}", error, desc),
        ));
    }

    let code = query
        .code
        .as_deref()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Missing authorization code"))?;

    let state_param = query
        .state
        .as_deref()
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Missing state parameter"))?;

    let (user_id, email, display_name, email_verified, token, redirect_url) =
        handle_callback(&state, &provider, code, state_param).await?;

    // If a redirect_url was stored (and it's not a link: prefix), redirect there
    if let Some(ref url) = redirect_url
        && !url.starts_with("link:")
    {
        let separator = if url.contains('?') { '&' } else { '?' };
        let redirect_with_session = format!("{}{}authenticated=true", url, separator);
        return Ok((
            [(SET_COOKIE, session_set_cookie(&state, &token))],
            Redirect::temporary(&redirect_with_session),
        )
            .into_response());
    }

    // Default: return JSON with session cookie
    Ok((
        [(SET_COOKIE, session_set_cookie(&state, &token))],
        Json(AuthResponse {
            user_id,
            email,
            display_name,
            email_verified,
        }),
    )
        .into_response())
}

/// POST /oauth/{provider}/callback — Handle OAuth callback (SPA/mobile)
async fn callback_post(
    State(state): State<YAuthState>,
    Path(provider): Path<String>,
    Json(body): Json<CallbackBody>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, email, display_name, email_verified, token, _redirect_url) =
        handle_callback(&state, &provider, &body.code, &body.state).await?;

    Ok((
        [(SET_COOKIE, session_set_cookie(&state, &token))],
        Json(AuthResponse {
            user_id,
            email,
            display_name,
            email_verified,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Protected routes
// ---------------------------------------------------------------------------

/// GET /oauth/accounts — List linked OAuth accounts for the current user
async fn list_accounts(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<OAuthAccountResponse>>, ApiError> {
    let accounts = yauth_entity::oauth_accounts::Entity::find()
        .filter(yauth_entity::oauth_accounts::Column::UserId.eq(user.id))
        .all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list OAuth accounts: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let response: Vec<OAuthAccountResponse> = accounts
        .into_iter()
        .map(|a| OAuthAccountResponse {
            id: a.id.to_string(),
            provider: a.provider,
            provider_user_id: a.provider_user_id,
            created_at: a.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

/// DELETE /oauth/{provider} — Unlink an OAuth provider from the current user
async fn unlink_provider(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let account = yauth_entity::oauth_accounts::Entity::find()
        .filter(yauth_entity::oauth_accounts::Column::UserId.eq(user.id))
        .filter(yauth_entity::oauth_accounts::Column::Provider.eq(&provider))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to find OAuth account: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let account = account.ok_or_else(|| {
        api_err(
            StatusCode::NOT_FOUND,
            "OAuth provider not linked to your account",
        )
    })?;

    yauth_entity::oauth_accounts::Entity::delete_by_id(account.id)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to unlink OAuth account: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    info!(
        event = "oauth_account_unlinked",
        user_id = %user.id,
        provider = %provider,
        "OAuth account unlinked"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// POST /oauth/{provider}/link — Start OAuth flow to link a new provider (returns auth URL)
async fn start_link(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
) -> Result<Json<AuthorizeResponse>, ApiError> {
    let provider_config = find_provider_config(&state, &provider)?;

    // Check if already linked
    let existing = yauth_entity::oauth_accounts::Entity::find()
        .filter(yauth_entity::oauth_accounts::Column::UserId.eq(user.id))
        .filter(yauth_entity::oauth_accounts::Column::Provider.eq(&provider))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        return Err(api_err(
            StatusCode::CONFLICT,
            "This provider is already linked to your account",
        ));
    }

    // Generate state token
    let state_token = crypto::generate_token();

    // Store state with `link:<user_id>` as the redirect_url to signal linking mode
    let link_marker = format!("link:{}", user.id);
    store_state(&state, &state_token, &provider, Some(&link_marker)).await?;

    // Build redirect URI
    let redirect_uri = format!(
        "{}/oauth/{}/callback",
        state.config.base_url.trim_end_matches('/'),
        provider
    );

    let client = build_oauth_client(provider_config, &redirect_uri)?;

    let state_token_clone = state_token.clone();
    let mut auth_request = client.authorize_url(move || CsrfToken::new(state_token_clone));

    for scope in &provider_config.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, _csrf_token) = auth_request.url();

    info!(
        event = "oauth_link_start",
        user_id = %user.id,
        provider = %provider,
        "OAuth account linking flow started"
    );

    Ok(Json(AuthorizeResponse {
        auth_url: auth_url.to_string(),
    }))
}
