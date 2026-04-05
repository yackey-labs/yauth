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
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::session::session_set_cookie;
use crate::auth::{crypto, session};
use crate::config::OAuthProviderConfig;
use crate::error::{ApiError, api_err};
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

    fn schema(&self) -> Vec<crate::schema::TableDef> {
        crate::schema::plugin_schemas::oauth_schema()
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthorizeQuery {
    pub redirect_url: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CallbackBody {
    pub code: String,
    pub state: String,
}

/// Common userinfo fields parsed from the provider's response.
#[derive(Debug, Deserialize)]
struct ProviderUserInfo {
    id: String,
    email: Option<String>,
    name: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuthAccountResponse {
    pub id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuthAuthResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthorizeResponse {
    pub auth_url: String,
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
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(STATE_EXPIRY_MINUTES);

    let new_state = crate::domain::NewOauthState {
        state: state_token.to_string(),
        provider: provider.to_string(),
        redirect_url: redirect_url.map(|s| s.to_string()),
        expires_at: expires_at.naive_utc(),
        created_at: chrono::Utc::now().naive_utc(),
    };

    state
        .repos
        .oauth_states
        .create(new_state)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_state_store_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    Ok(())
}

/// Common struct for consumed state data used by both backends.
struct ConsumedState {
    provider: String,
    redirect_url: Option<String>,
    expires_at: chrono::DateTime<chrono::FixedOffset>,
}

/// Validate and consume a state parameter from the database.
/// Returns the stored state data on success, deleting it (one-time use).
async fn consume_state(
    state: &YAuthState,
    state_token: &str,
    expected_provider: &str,
) -> Result<ConsumedState, ApiError> {
    let s = state
        .repos
        .oauth_states
        .find_and_delete(state_token)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_state_lookup_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            crate::otel::add_event("oauth_state_invalid", vec![]);
            api_err(
                StatusCode::BAD_REQUEST,
                "Invalid or expired state parameter",
            )
        })?;

    use chrono::TimeZone;
    let stored = ConsumedState {
        provider: s.provider,
        redirect_url: s.redirect_url,
        expires_at: chrono::Utc.from_utc_datetime(&s.expires_at).fixed_offset(),
    };

    // Check expiry
    let now = chrono::Utc::now().fixed_offset();
    if stored.expires_at < now {
        crate::otel::add_event("oauth_state_expired", vec![]);
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "State parameter has expired. Please try again.",
        ));
    }

    // Check provider matches
    if stored.provider != expected_provider {
        crate::otel::add_event(
            "oauth_state_provider_mismatch",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("expected_provider", expected_provider.to_string()),
                opentelemetry::KeyValue::new("actual_provider", stored.provider.clone()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(StatusCode::BAD_REQUEST, "State parameter mismatch"));
    }

    Ok(stored)
}

/// Parse the userinfo JSON response from a provider into a common struct.
fn parse_userinfo(provider: &str, json: &serde_json::Value) -> Result<ProviderUserInfo, ApiError> {
    let id = match provider {
        "github" => json
            .get("id")
            .and_then(|v| {
                if v.is_number() {
                    Some(v.to_string())
                } else {
                    v.as_str().map(|s| s.to_string())
                }
            })
            .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "Missing id from provider"))?,
        "google" => json
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "Missing sub from provider"))?,
        _ => json
            .get("id")
            .or_else(|| json.get("sub"))
            .and_then(|v| {
                if v.is_string() {
                    v.as_str().map(|s| s.to_string())
                } else {
                    Some(v.to_string())
                }
            })
            .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "Missing id from provider"))?,
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
        .header("User-Agent", "yauth")
        .send()
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_userinfo_fetch_failed", &e);
            api_err(
                StatusCode::BAD_GATEWAY,
                "Failed to fetch user info from provider",
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        crate::otel::add_event(
            "oauth_userinfo_error",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("http.status", status.to_string()),
                opentelemetry::KeyValue::new("response.body", body.clone()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(
            StatusCode::BAD_GATEWAY,
            "Provider returned an error when fetching user info",
        ));
    }

    resp.json::<serde_json::Value>().await.map_err(|e| {
        crate::otel::record_error("oauth_userinfo_parse_failed", &e);
        api_err(StatusCode::BAD_GATEWAY, "Invalid response from provider")
    })
}

/// Fetch the user's primary verified email from a provider's emails endpoint.
async fn fetch_primary_email(emails_url: &str, access_token: &str) -> Result<String, ApiError> {
    let http_client = reqwest::Client::new();
    let resp = http_client
        .get(emails_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "yauth")
        .send()
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_emails_fetch_failed", &e);
            api_err(
                StatusCode::BAD_GATEWAY,
                "Failed to fetch emails from provider",
            )
        })?;

    if !resp.status().is_success() {
        return Err(api_err(
            StatusCode::BAD_GATEWAY,
            "Emails endpoint returned error",
        ));
    }

    let emails: Vec<serde_json::Value> = resp.json().await.map_err(|e| {
        crate::otel::record_error("oauth_emails_parse_failed", &e);
        api_err(StatusCode::BAD_GATEWAY, "Invalid emails response")
    })?;

    let primary = emails.iter().find(|e| {
        e.get("primary").and_then(|v| v.as_bool()).unwrap_or(false)
            && e.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
    });
    let verified = emails
        .iter()
        .find(|e| e.get("verified").and_then(|v| v.as_bool()).unwrap_or(false));

    primary
        .or(verified)
        .and_then(|e| {
            e.get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| api_err(StatusCode::BAD_GATEWAY, "No verified email found"))
}

/// Core callback logic shared by GET and POST handlers.
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
            crate::otel::record_error("oauth_http_client_build_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_token_exchange_failed", &e);
            api_err(
                StatusCode::BAD_GATEWAY,
                "Failed to exchange authorization code",
            )
        })?;

    let access_token = token_result.access_token().secret().clone();
    let refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
    let expires_at = token_result
        .expires_in()
        .map(|d| chrono::Utc::now() + chrono::Duration::seconds(d.as_secs() as i64));

    // 5. Fetch user info from provider
    let userinfo_json = fetch_userinfo(provider_config, &access_token).await?;
    let mut userinfo = parse_userinfo(provider, &userinfo_json)?;

    // 5b. If email is missing and an emails_url is configured, try fetching from there.
    if let (None, Some(emails_url)) = (&userinfo.email, &provider_config.emails_url) {
        userinfo.email = fetch_primary_email(emails_url, &access_token).await.ok();
    }

    // 6. Check if this is an account-linking callback
    let link_to_user_id = stored_state
        .redirect_url
        .as_deref()
        .and_then(|url| url.strip_prefix("link:"))
        .and_then(|id| Uuid::parse_str(id).ok());

    if let Some(link_user_id) = link_to_user_id {
        // Account linking flow
        let existing_link = state
            .repos
            .oauth_accounts
            .find_by_provider_and_provider_user_id(provider, &userinfo.id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        if existing_link.is_some() {
            return Err(api_err(
                StatusCode::CONFLICT,
                "This provider account is already linked to a user",
            ));
        }

        let now = chrono::Utc::now().naive_utc();
        let new_account = crate::domain::NewOauthAccount {
            id: Uuid::now_v7(),
            user_id: link_user_id,
            provider: provider.to_string(),
            provider_user_id: userinfo.id.clone(),
            access_token_enc: Some(access_token.clone()),
            refresh_token_enc: refresh_token.clone(),
            created_at: now,
            expires_at: expires_at.map(|dt| dt.naive_utc()),
            updated_at: now,
        };

        state
            .repos
            .oauth_accounts
            .create(new_account)
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth_account_link_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let user = state
            .repos
            .users
            .find_by_id(link_user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

        let (token, _session_id) =
            session::create_session(state, user.id, None, None, state.config.session_ttl)
                .await
                .map_err(|e| {
                    crate::otel::record_error("session_create_failed", &e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

        crate::otel::add_event(
            "oauth_account_linked",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        state
            .write_audit_log(
                Some(user.id),
                "oauth_linked",
                Some(serde_json::json!({ "provider": provider })),
                None,
            )
            .await;

        return Ok((
            user.id.to_string(),
            user.email,
            user.display_name,
            user.email_verified,
            token,
            None,
        ));
    }

    // 7. Look up existing OAuth account
    let existing_account = state
        .repos
        .oauth_accounts
        .find_by_provider_and_provider_user_id(provider, &userinfo.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    struct CallbackUserInfo {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
    }

    let user_info = if let Some(account) = existing_account {
        // Existing OAuth account — update tokens
        state
            .repos
            .oauth_accounts
            .update_tokens(
                account.id,
                Some(&access_token),
                refresh_token.as_deref(),
                expires_at.map(|dt| dt.naive_utc()),
            )
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth_tokens_update_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        let user = state
            .repos
            .users
            .find_by_id(account.user_id)
            .await
            .map_err(|e| {
                crate::otel::record_error("db_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;

        if user.banned {
            crate::otel::add_event(
                "oauth_login_banned_user",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
                    opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
        }

        crate::otel::add_event(
            "oauth_login_succeeded",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.id", user.id.to_string()),
                opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        state
            .write_audit_log(
                Some(user.id),
                "login_succeeded",
                Some(serde_json::json!({ "method": "oauth", "provider": provider })),
                None,
            )
            .await;

        CallbackUserInfo {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            email_verified: user.email_verified,
        }
    } else {
        // New user — create user and OAuth account
        let email = userinfo.email.ok_or_else(|| {
            crate::otel::add_event(
            "oauth_no_email",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("oauth.provider", provider.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
            api_err(StatusCode::BAD_REQUEST, "Email not provided by OAuth provider. Please ensure your account has a verified email.")
        })?;
        let email = email.trim().to_lowercase();

        let existing_user = state.repos.users.find_by_email(&email).await.map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

        let (uid, display_name, email_verified) = if let Some(existing) = existing_user {
            (existing.id, existing.display_name, existing.email_verified)
        } else {
            if !state.config.allow_signups {
                crate::otel::add_event(
                    "oauth_signup_disabled",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new("user.email", email.clone())],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Registration is currently disabled",
                ));
            }
            let user_id = Uuid::now_v7();
            let now = chrono::Utc::now().naive_utc();
            let new_user = crate::domain::NewUser {
                id: user_id,
                email: email.clone(),
                display_name: userinfo.name.clone(),
                email_verified: true,
                role: "user".to_string(),
                banned: false,
                banned_reason: None,
                banned_until: None,
                created_at: now,
                updated_at: now,
            };
            state.repos.users.create(new_user).await.map_err(|e| {
                crate::otel::record_error("user_create_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
            (user_id, userinfo.name.clone(), true)
        };

        let now = chrono::Utc::now().naive_utc();
        let new_account = crate::domain::NewOauthAccount {
            id: Uuid::now_v7(),
            user_id: uid,
            provider: provider.to_string(),
            provider_user_id: userinfo.id.clone(),
            access_token_enc: Some(access_token.clone()),
            refresh_token_enc: refresh_token.clone(),
            created_at: now,
            expires_at: expires_at.map(|dt| dt.naive_utc()),
            updated_at: now,
        };

        state
            .repos
            .oauth_accounts
            .create(new_account)
            .await
            .map_err(|e| {
                crate::otel::record_error("oauth_account_create_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

        crate::otel::add_event(
            "oauth_user_registered",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("user.id", uid.to_string()),
                opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        state
            .write_audit_log(
                Some(uid),
                "user_registered",
                Some(serde_json::json!({ "method": "oauth", "provider": provider })),
                None,
            )
            .await;

        CallbackUserInfo {
            id: uid,
            email: email.clone(),
            display_name,
            email_verified,
        }
    };

    // 8. Create session
    let (token, _session_id) =
        session::create_session(state, user_info.id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                crate::otel::record_error("session_create_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

    Ok((
        user_info.id.to_string(),
        user_info.email,
        user_info.display_name,
        user_info.email_verified,
        token,
        stored_state.redirect_url,
    ))
}

// ---------------------------------------------------------------------------
// Token refresh
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Public routes
// ---------------------------------------------------------------------------

async fn authorize(
    State(state): State<YAuthState>,
    Path(provider): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let provider_config = find_provider_config(&state, &provider)?;

    // Validate redirect_url against trusted origins to prevent open redirects
    if let Some(ref url) = query.redirect_url {
        let trusted = state
            .config
            .trusted_origins
            .iter()
            .any(|origin| url.starts_with(origin));
        if !trusted {
            return Err(api_err(StatusCode::BAD_REQUEST, "Invalid redirect URL"));
        }
    }

    let state_token = crypto::generate_token();
    store_state(
        &state,
        &state_token,
        &provider,
        query.redirect_url.as_deref(),
    )
    .await?;

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

    crate::otel::add_event(
        "oauth_authorize_start",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new(
            "oauth.provider",
            provider.to_string(),
        )],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
    Ok(Redirect::temporary(auth_url.as_str()))
}

async fn callback_get(
    State(state): State<YAuthState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(ref error) = query.error {
        let desc = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        crate::otel::add_event(
            "oauth_callback_error",
            #[cfg(feature = "telemetry")]
            vec![
                opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
                opentelemetry::KeyValue::new("error", error.clone()),
                opentelemetry::KeyValue::new("error.description", desc.to_string()),
            ],
            #[cfg(not(feature = "telemetry"))]
            vec![],
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

    if let Some(ref url) = redirect_url
        && !url.starts_with("link:")
    {
        let separator = if url.contains('?') { '&' } else { '?' };
        let redirect_with_session = format!("{}{}authenticated=true", url, separator);
        return Ok((
            [(
                SET_COOKIE,
                session_set_cookie(&state, &token, state.config.session_ttl),
            )],
            Redirect::temporary(&redirect_with_session),
        )
            .into_response());
    }

    Ok((
        [(
            SET_COOKIE,
            session_set_cookie(&state, &token, state.config.session_ttl),
        )],
        Json(OAuthAuthResponse {
            user_id,
            email,
            display_name,
            email_verified,
        }),
    )
        .into_response())
}

async fn callback_post(
    State(state): State<YAuthState>,
    Path(provider): Path<String>,
    Json(body): Json<CallbackBody>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, email, display_name, email_verified, token, _redirect_url) =
        handle_callback(&state, &provider, &body.code, &body.state).await?;

    Ok((
        [(
            SET_COOKIE,
            session_set_cookie(&state, &token, state.config.session_ttl),
        )],
        Json(OAuthAuthResponse {
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

async fn list_accounts(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<OAuthAccountResponse>>, ApiError> {
    let accounts = state
        .repos
        .oauth_accounts
        .find_by_user_id(user.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_accounts_list_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    use chrono::TimeZone;
    let response = accounts
        .into_iter()
        .map(|a| OAuthAccountResponse {
            id: a.id.to_string(),
            provider: a.provider,
            provider_user_id: a.provider_user_id,
            created_at: chrono::Utc.from_utc_datetime(&a.created_at).to_rfc3339(),
        })
        .collect::<Vec<_>>();

    Ok(Json(response))
}

async fn unlink_provider(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let account = state
        .repos
        .oauth_accounts
        .find_by_user_and_provider(user.id, &provider)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_account_find_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            api_err(
                StatusCode::NOT_FOUND,
                "OAuth provider not linked to your account",
            )
        })?;

    state
        .repos
        .oauth_accounts
        .delete(account.id)
        .await
        .map_err(|e| {
            crate::otel::record_error("oauth_account_unlink_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    crate::otel::add_event(
        "oauth_account_unlinked",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );
    state
        .write_audit_log(
            Some(user.id),
            "oauth_unlinked",
            Some(serde_json::json!({ "provider": provider })),
            None,
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

async fn start_link(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
) -> Result<Json<AuthorizeResponse>, ApiError> {
    let provider_config = find_provider_config(&state, &provider)?;

    let existing = state
        .repos
        .oauth_accounts
        .find_by_user_and_provider(user.id, &provider)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if existing.is_some() {
        return Err(api_err(
            StatusCode::CONFLICT,
            "This provider is already linked to your account",
        ));
    }

    let state_token = crypto::generate_token();
    let link_marker = format!("link:{}", user.id);
    store_state(&state, &state_token, &provider, Some(&link_marker)).await?;

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

    crate::otel::add_event(
        "oauth_link_start",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.id", user.id.to_string()),
            opentelemetry::KeyValue::new("oauth.provider", provider.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

    Ok(Json(AuthorizeResponse {
        auth_url: auth_url.to_string(),
    }))
}
