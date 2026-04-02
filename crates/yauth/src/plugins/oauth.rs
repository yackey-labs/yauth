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
use tracing::{info, warn};
use uuid::Uuid;

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;

use crate::auth::session::session_set_cookie;
use crate::auth::{crypto, session};
use crate::config::OAuthProviderConfig;
use crate::db::models::{NewOauthAccount, NewOauthState, NewUser, OauthAccount, OauthState};
use crate::db::schema::{yauth_oauth_accounts, yauth_oauth_states, yauth_users};
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

const STATE_EXPIRY_MINUTES: i64 = 10;

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

use crate::db::{find_user_by_email, find_user_by_id};

async fn db_insert_user(
    conn: &mut Conn,
    id: Uuid,
    email: &str,
    display_name: Option<&str>,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_user = NewUser {
        id,
        email: email.to_string(),
        display_name: display_name.map(|s| s.to_string()),
        email_verified: true,
        role: "user".to_string(),
        banned: false,
        banned_reason: None,
        banned_until: None,
        created_at: now,
        updated_at: now,
    };
    diesel::insert_into(yauth_users::table)
        .values(&new_user)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_find_oauth_account_by_provider(
    conn: &mut Conn,
    provider: &str,
    provider_user_id: &str,
) -> DbResult<Option<OauthAccount>> {
    yauth_oauth_accounts::table
        .filter(
            yauth_oauth_accounts::provider
                .eq(provider)
                .and(yauth_oauth_accounts::provider_user_id.eq(provider_user_id)),
        )
        .select(OauthAccount::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_find_oauth_accounts_by_user(
    conn: &mut Conn,
    user_id: Uuid,
) -> DbResult<Vec<OauthAccount>> {
    yauth_oauth_accounts::table
        .filter(yauth_oauth_accounts::user_id.eq(user_id))
        .select(OauthAccount::as_select())
        .load(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn db_find_oauth_account_by_user_and_provider(
    conn: &mut Conn,
    user_id: Uuid,
    provider: &str,
) -> DbResult<Option<OauthAccount>> {
    yauth_oauth_accounts::table
        .filter(
            yauth_oauth_accounts::user_id
                .eq(user_id)
                .and(yauth_oauth_accounts::provider.eq(provider)),
        )
        .select(OauthAccount::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
async fn db_insert_oauth_account(
    conn: &mut Conn,
    id: Uuid,
    user_id: Uuid,
    provider: &str,
    provider_user_id: &str,
    access_token_enc: Option<&str>,
    refresh_token_enc: Option<&str>,
    expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_account = NewOauthAccount {
        id,
        user_id,
        provider: provider.to_string(),
        provider_user_id: provider_user_id.to_string(),
        access_token_enc: access_token_enc.map(|s| s.to_string()),
        refresh_token_enc: refresh_token_enc.map(|s| s.to_string()),
        created_at: now,
        expires_at: expires_at.map(|dt| dt.naive_utc()),
        updated_at: now,
    };
    diesel::insert_into(yauth_oauth_accounts::table)
        .values(&new_account)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_update_oauth_account_tokens(
    conn: &mut Conn,
    id: Uuid,
    access_token_enc: Option<&str>,
    refresh_token_enc: Option<&str>,
    expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    diesel::update(yauth_oauth_accounts::table.find(id))
        .set((
            yauth_oauth_accounts::access_token_enc.eq(access_token_enc),
            yauth_oauth_accounts::refresh_token_enc.eq(refresh_token_enc),
            yauth_oauth_accounts::expires_at.eq(expires_at.map(|dt| dt.naive_utc())),
            yauth_oauth_accounts::updated_at.eq(now),
        ))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_delete_oauth_account(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_oauth_accounts::table.find(id))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_insert_oauth_state(
    conn: &mut Conn,
    state_token: &str,
    provider: &str,
    redirect_url: Option<&str>,
    expires_at: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_state = NewOauthState {
        state: state_token.to_string(),
        provider: provider.to_string(),
        redirect_url: redirect_url.map(|s| s.to_string()),
        expires_at: expires_at.naive_utc(),
        created_at: now,
    };
    diesel::insert_into(yauth_oauth_states::table)
        .values(&new_state)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_find_and_delete_oauth_state(
    conn: &mut Conn,
    state_token: &str,
) -> DbResult<Option<OauthState>> {
    let row: Option<OauthState> = yauth_oauth_states::table
        .find(state_token)
        .select(OauthState::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())?;

    if row.is_some() {
        let _ = diesel::delete(yauth_oauth_states::table.find(state_token))
            .execute(conn)
            .await;
    }

    Ok(row)
}

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
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::minutes(STATE_EXPIRY_MINUTES)).fixed_offset();

    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        db_insert_oauth_state(&mut conn, state_token, provider, redirect_url, expires_at)
            .await
            .map_err(|e| {
                tracing::error!("Failed to store OAuth state: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

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
    let stored = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let s = db_find_and_delete_oauth_state(&mut conn, state_token)
            .await
            .map_err(|e| {
                tracing::error!("DB error looking up OAuth state: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| {
                warn!(
                    event = "yauth.oauth.state_invalid",
                    "OAuth state parameter not found"
                );
                api_err(
                    StatusCode::BAD_REQUEST,
                    "Invalid or expired state parameter",
                )
            })?;

        use chrono::TimeZone;
        ConsumedState {
            provider: s.provider,
            redirect_url: s.redirect_url,
            expires_at: chrono::Utc.from_utc_datetime(&s.expires_at).fixed_offset(),
        }
    };

    // Check expiry
    let now = chrono::Utc::now().fixed_offset();
    if stored.expires_at < now {
        warn!(
            event = "yauth.oauth.state_expired",
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
            event = "yauth.oauth.state_mismatch",
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
            event = "yauth.oauth.userinfo_error",
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
            tracing::warn!("Failed to fetch emails endpoint: {}", e);
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
        tracing::warn!("Failed to parse emails JSON: {}", e);
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
            tracing::error!("Failed to build HTTP client: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!(event = "yauth.oauth.token_exchange_error", error = %e, "OAuth token exchange failed");
            api_err(StatusCode::BAD_GATEWAY, "Failed to exchange authorization code")
        })?;

    let access_token = token_result.access_token().secret().clone();
    let refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
    let expires_at = token_result.expires_in().map(|d| {
        (chrono::Utc::now() + chrono::Duration::seconds(d.as_secs() as i64)).fixed_offset()
    });

    // 5. Fetch user info from provider
    let userinfo_json = fetch_userinfo(provider_config, &access_token).await?;
    let mut userinfo = parse_userinfo(provider, &userinfo_json)?;

    // 5b. If email is missing and an emails_url is configured, try fetching from there.
    if let (None, Some(emails_url)) = (&userinfo.email, &provider_config.emails_url) {
        userinfo.email = fetch_primary_email(emails_url, &access_token).await.ok();
    }

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    // 6. Check if this is an account-linking callback
    let link_to_user_id = stored_state
        .redirect_url
        .as_deref()
        .and_then(|url| url.strip_prefix("link:"))
        .and_then(|id| Uuid::parse_str(id).ok());

    if let Some(link_user_id) = link_to_user_id {
        // Account linking flow
        let existing_link = {
            db_find_oauth_account_by_provider(&mut conn, provider, &userinfo.id)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
        };

        if existing_link.is_some() {
            return Err(api_err(
                StatusCode::CONFLICT,
                "This provider account is already linked to a user",
            ));
        }

        {
            db_insert_oauth_account(
                &mut conn,
                Uuid::new_v4(),
                link_user_id,
                provider,
                &userinfo.id,
                Some(&access_token),
                refresh_token.as_deref(),
                expires_at,
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to link OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        }

        struct LinkUserInfo {
            id: Uuid,
            email: String,
            display_name: Option<String>,
            email_verified: bool,
        }

        let user = {
            let u = find_user_by_id(&mut conn, link_user_id)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
                .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
            LinkUserInfo {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                email_verified: u.email_verified,
            }
        };

        let (token, _session_id) =
            session::create_session(state, user.id, None, None, state.config.session_ttl)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create session: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

        info!(event = "yauth.oauth.account_linked", user_id = %user.id, provider = %provider, "OAuth account linked");
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
    let existing_account = {
        db_find_oauth_account_by_provider(&mut conn, provider, &userinfo.id)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };

    struct CallbackUserInfo {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
    }

    let user_info = if let Some(account) = existing_account {
        // Existing OAuth account — update tokens
        {
            db_update_oauth_account_tokens(
                &mut conn,
                account.id,
                Some(&access_token),
                refresh_token.as_deref(),
                expires_at,
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to update OAuth tokens: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        }

        let user = {
            let u = find_user_by_id(&mut conn, account.user_id)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
                .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
            if u.banned {
                warn!(event = "yauth.oauth.login.banned", provider = %provider, user_id = %u.id, "OAuth login attempt by banned user");
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            CallbackUserInfo {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                email_verified: u.email_verified,
            }
        };

        info!(event = "yauth.oauth.login", user_id = %user.id, provider = %provider, "User logged in via OAuth");
        state
            .write_audit_log(
                Some(user.id),
                "login_succeeded",
                Some(serde_json::json!({ "method": "oauth", "provider": provider })),
                None,
            )
            .await;

        user
    } else {
        // New user — create user and OAuth account
        let email = userinfo.email.ok_or_else(|| {
            warn!(event = "yauth.oauth.no_email", provider = %provider, "OAuth provider did not return email");
            api_err(StatusCode::BAD_REQUEST, "Email not provided by OAuth provider. Please ensure your account has a verified email.")
        })?;
        let email = email.trim().to_lowercase();

        let existing_user = {
            find_user_by_email(&mut conn, &email).await.map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
        };

        let (uid, display_name, email_verified) = if let Some(existing) = existing_user {
            (existing.id, existing.display_name, existing.email_verified)
        } else {
            if !state.config.allow_signups {
                warn!(event = "yauth.oauth.signup_disabled", email = %email, "OAuth signup attempted while signups are disabled");
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Registration is currently disabled",
                ));
            }
            let user_id = Uuid::new_v4();
            {
                db_insert_user(&mut conn, user_id, &email, userinfo.name.as_deref())
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to create user: {}", e);
                        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;
            }
            (user_id, userinfo.name.clone(), true)
        };

        {
            db_insert_oauth_account(
                &mut conn,
                Uuid::new_v4(),
                uid,
                provider,
                &userinfo.id,
                Some(&access_token),
                refresh_token.as_deref(),
                expires_at,
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        }

        info!(event = "yauth.oauth.register", user_id = %uid, provider = %provider, "New user registered via OAuth");
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
                tracing::error!("Failed to create session: {}", e);
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

    info!(event = "yauth.oauth.authorize_start", provider = %provider, "OAuth authorization flow started");
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
        warn!(event = "yauth.oauth.callback_error", provider = %provider, error = %error, description = %desc, "OAuth provider returned error");
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
    let response = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let accounts = db_find_oauth_accounts_by_user(&mut conn, user.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list OAuth accounts: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        use chrono::TimeZone;
        accounts
            .into_iter()
            .map(|a| OAuthAccountResponse {
                id: a.id.to_string(),
                provider: a.provider,
                provider_user_id: a.provider_user_id,
                created_at: chrono::Utc.from_utc_datetime(&a.created_at).to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };

    Ok(Json(response))
}

async fn unlink_provider(
    State(state): State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let account = db_find_oauth_account_by_user_and_provider(&mut conn, user.id, &provider)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| {
                api_err(
                    StatusCode::NOT_FOUND,
                    "OAuth provider not linked to your account",
                )
            })?;
        db_delete_oauth_account(&mut conn, account.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to unlink OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    info!(event = "yauth.oauth.account_unlinked", user_id = %user.id, provider = %provider, "OAuth account unlinked");
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

    let existing = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        db_find_oauth_account_by_user_and_provider(&mut conn, user.id, &provider)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };

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

    info!(event = "yauth.oauth.link_start", user_id = %user.id, provider = %provider, "OAuth account linking flow started");

    Ok(Json(AuthorizeResponse {
        auth_url: auth_url.to_string(),
    }))
}
