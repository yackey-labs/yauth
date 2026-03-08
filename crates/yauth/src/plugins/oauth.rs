use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
};
#[cfg(feature = "seaorm")]
use oauth2::RefreshToken;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
#[cfg(feature = "seaorm")]
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::session::session_set_cookie;
use crate::auth::{crypto, session};
use crate::config::OAuthProviderConfig;
use crate::error::{ApiError, api_err};
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

const STATE_EXPIRY_MINUTES: i64 = 10;

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
    pub struct OauthAccountRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub user_id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub provider: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub provider_user_id: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub access_token_enc: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub refresh_token_enc: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
        pub expires_at: Option<chrono::NaiveDateTime>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub updated_at: chrono::NaiveDateTime,
    }

    #[derive(diesel::QueryableByName, Clone)]
    #[allow(dead_code)]
    pub struct OauthStateRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub state: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub provider: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        pub redirect_url: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub expires_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub created_at: chrono::NaiveDateTime,
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

    pub async fn insert_user(
        conn: &mut Conn,
        id: Uuid,
        email: &str,
        display_name: Option<&str>,
    ) -> DbResult<()> {
        let now = chrono::Utc::now();
        diesel::sql_query(
            "INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at) VALUES ($1, $2, $3, true, 'user', false, NULL, NULL, $4, $4)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Text, _>(email)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(display_name)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn find_oauth_account_by_provider(
        conn: &mut Conn,
        provider: &str,
        provider_user_id: &str,
    ) -> DbResult<Option<OauthAccountRow>> {
        diesel::sql_query(
            "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at FROM yauth_oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
        )
        .bind::<diesel::sql_types::Text, _>(provider)
        .bind::<diesel::sql_types::Text, _>(provider_user_id)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn find_oauth_accounts_by_user(
        conn: &mut Conn,
        user_id: Uuid,
    ) -> DbResult<Vec<OauthAccountRow>> {
        diesel::sql_query(
            "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at FROM yauth_oauth_accounts WHERE user_id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .load(conn)
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn find_oauth_account_by_user_and_provider(
        conn: &mut Conn,
        user_id: Uuid,
        provider: &str,
    ) -> DbResult<Option<OauthAccountRow>> {
        diesel::sql_query(
            "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at FROM yauth_oauth_accounts WHERE user_id = $1 AND provider = $2",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(provider)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_oauth_account(
        conn: &mut Conn,
        id: Uuid,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        access_token_enc: Option<&str>,
        refresh_token_enc: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    ) -> DbResult<()> {
        let now = chrono::Utc::now();
        diesel::sql_query(
            "INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(provider)
        .bind::<diesel::sql_types::Text, _>(provider_user_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(access_token_enc)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(refresh_token_enc)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(expires_at)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn update_oauth_account_tokens(
        conn: &mut Conn,
        id: Uuid,
        access_token_enc: Option<&str>,
        refresh_token_enc: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    ) -> DbResult<()> {
        let now = chrono::Utc::now();
        diesel::sql_query(
            "UPDATE yauth_oauth_accounts SET access_token_enc = $2, refresh_token_enc = $3, expires_at = $4, updated_at = $5 WHERE id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(access_token_enc)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(refresh_token_enc)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn delete_oauth_account(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("DELETE FROM yauth_oauth_accounts WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn insert_oauth_state(
        conn: &mut Conn,
        state_token: &str,
        provider: &str,
        redirect_url: Option<&str>,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        let now = chrono::Utc::now();
        diesel::sql_query(
            "INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind::<diesel::sql_types::Text, _>(state_token)
        .bind::<diesel::sql_types::Text, _>(provider)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(redirect_url)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn find_and_delete_oauth_state(
        conn: &mut Conn,
        state_token: &str,
    ) -> DbResult<Option<OauthStateRow>> {
        let row: Option<OauthStateRow> = diesel::sql_query(
            "SELECT state, provider, redirect_url, expires_at, created_at FROM yauth_oauth_states WHERE state = $1",
        )
        .bind::<diesel::sql_types::Text, _>(state_token)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())?;

        if row.is_some() {
            let _ = diesel::sql_query("DELETE FROM yauth_oauth_states WHERE state = $1")
                .bind::<diesel::sql_types::Text, _>(state_token)
                .execute(conn)
                .await;
        }

        Ok(row)
    }
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

#[derive(Deserialize, TS)]
#[ts(export)]
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

#[derive(Deserialize, TS)]
#[ts(export)]
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

#[derive(Serialize, TS)]
#[ts(export)]
pub struct OAuthAccountResponse {
    pub id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: String,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct OAuthAuthResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
}

#[derive(Serialize, TS)]
#[ts(export)]
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

    #[cfg(feature = "seaorm")]
    {
        let now = chrono::Utc::now().fixed_offset();
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
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        diesel_db::insert_oauth_state(&mut conn, state_token, provider, redirect_url, expires_at)
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
    #[cfg(feature = "seaorm")]
    let stored = {
        let s = yauth_entity::oauth_states::Entity::find_by_id(state_token.to_string())
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

        ConsumedState {
            provider: s.provider,
            redirect_url: s.redirect_url,
            expires_at: s.expires_at,
        }
    };
    #[cfg(feature = "diesel-async")]
    let stored = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let s = diesel_db::find_and_delete_oauth_state(&mut conn, state_token)
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
            tracing::error!(event = "oauth_token_exchange_error", error = %e, "OAuth token exchange failed");
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

    #[cfg(feature = "diesel-async")]
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
        #[cfg(feature = "seaorm")]
        let existing_link = {
            yauth_entity::oauth_accounts::Entity::find()
                .filter(yauth_entity::oauth_accounts::Column::Provider.eq(provider))
                .filter(yauth_entity::oauth_accounts::Column::ProviderUserId.eq(&userinfo.id))
                .one(&state.db)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
        };
        #[cfg(feature = "diesel-async")]
        let existing_link = {
            diesel_db::find_oauth_account_by_provider(&mut conn, provider, &userinfo.id)
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

        #[cfg(feature = "seaorm")]
        {
            let now = chrono::Utc::now().fixed_offset();
            let oauth_account = yauth_entity::oauth_accounts::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(link_user_id),
                provider: Set(provider.to_string()),
                provider_user_id: Set(userinfo.id.clone()),
                access_token_enc: Set(Some(access_token.clone())),
                refresh_token_enc: Set(refresh_token.clone()),
                created_at: Set(now),
                expires_at: Set(expires_at),
                updated_at: Set(now),
            };
            oauth_account.insert(&state.db).await.map_err(|e| {
                tracing::error!("Failed to link OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        }
        #[cfg(feature = "diesel-async")]
        {
            diesel_db::insert_oauth_account(
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

        #[cfg(feature = "seaorm")]
        let user = {
            let u = yauth_entity::users::Entity::find_by_id(link_user_id)
                .one(&state.db)
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
        #[cfg(feature = "diesel-async")]
        let user = {
            let u = diesel_db::find_user_by_id(&mut conn, link_user_id)
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
            session::create_session(&state.db, user.id, None, None, state.config.session_ttl)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create session: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;

        info!(event = "oauth_account_linked", user_id = %user.id, provider = %provider, "OAuth account linked");
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
    #[cfg(feature = "seaorm")]
    let existing_account = {
        yauth_entity::oauth_accounts::Entity::find()
            .filter(yauth_entity::oauth_accounts::Column::Provider.eq(provider))
            .filter(yauth_entity::oauth_accounts::Column::ProviderUserId.eq(&userinfo.id))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };
    #[cfg(feature = "diesel-async")]
    let existing_account = {
        diesel_db::find_oauth_account_by_provider(&mut conn, provider, &userinfo.id)
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
        #[cfg(feature = "seaorm")]
        {
            let mut active: yauth_entity::oauth_accounts::ActiveModel = account.clone().into();
            active.access_token_enc = Set(Some(access_token.clone()));
            active.refresh_token_enc = Set(refresh_token.clone());
            active.expires_at = Set(expires_at);
            active.updated_at = Set(chrono::Utc::now().fixed_offset());
            active.update(&state.db).await.map_err(|e| {
                tracing::error!("Failed to update OAuth tokens: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        }
        #[cfg(feature = "diesel-async")]
        {
            diesel_db::update_oauth_account_tokens(
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

        #[cfg(feature = "seaorm")]
        let user = {
            let u = yauth_entity::users::Entity::find_by_id(account.user_id)
                .one(&state.db)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
                .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
            if u.banned {
                warn!(event = "oauth_login_banned", provider = %provider, user_id = %u.id, "OAuth login attempt by banned user");
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            CallbackUserInfo {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                email_verified: u.email_verified,
            }
        };
        #[cfg(feature = "diesel-async")]
        let user = {
            let u = diesel_db::find_user_by_id(&mut conn, account.user_id)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
                .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
            if u.banned {
                warn!(event = "oauth_login_banned", provider = %provider, user_id = %u.id, "OAuth login attempt by banned user");
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            CallbackUserInfo {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                email_verified: u.email_verified,
            }
        };

        info!(event = "oauth_login_success", user_id = %user.id, provider = %provider, "User logged in via OAuth");
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
            warn!(event = "oauth_no_email", provider = %provider, "OAuth provider did not return email");
            api_err(StatusCode::BAD_REQUEST, "Email not provided by OAuth provider. Please ensure your account has a verified email.")
        })?;
        let email = email.trim().to_lowercase();

        #[cfg(feature = "seaorm")]
        let existing_user = {
            yauth_entity::users::Entity::find()
                .filter(yauth_entity::users::Column::Email.eq(&email))
                .one(&state.db)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
        };
        #[cfg(feature = "diesel-async")]
        let existing_user = {
            diesel_db::find_user_by_email(&mut conn, &email)
                .await
                .map_err(|e| {
                    tracing::error!("DB error: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?
        };

        let (uid, display_name, email_verified) = if let Some(existing) = existing_user {
            (existing.id, existing.display_name, existing.email_verified)
        } else {
            let user_id = Uuid::new_v4();
            #[cfg(feature = "seaorm")]
            {
                let now = chrono::Utc::now().fixed_offset();
                let user = yauth_entity::users::ActiveModel {
                    id: Set(user_id),
                    email: Set(email.clone()),
                    display_name: Set(userinfo.name.clone()),
                    email_verified: Set(true),
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
            }
            #[cfg(feature = "diesel-async")]
            {
                diesel_db::insert_user(&mut conn, user_id, &email, userinfo.name.as_deref())
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to create user: {}", e);
                        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;
            }
            (user_id, userinfo.name.clone(), true)
        };

        #[cfg(feature = "seaorm")]
        {
            let now = chrono::Utc::now().fixed_offset();
            let oauth_account = yauth_entity::oauth_accounts::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(uid),
                provider: Set(provider.to_string()),
                provider_user_id: Set(userinfo.id.clone()),
                access_token_enc: Set(Some(access_token.clone())),
                refresh_token_enc: Set(refresh_token.clone()),
                created_at: Set(now),
                expires_at: Set(expires_at),
                updated_at: Set(now),
            };
            oauth_account.insert(&state.db).await.map_err(|e| {
                tracing::error!("Failed to create OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        }
        #[cfg(feature = "diesel-async")]
        {
            diesel_db::insert_oauth_account(
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

        info!(event = "oauth_register_success", user_id = %uid, provider = %provider, "New user registered via OAuth");
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
    let (token, _session_id) = session::create_session(
        &state.db,
        user_info.id,
        None,
        None,
        state.config.session_ttl,
    )
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

#[cfg(feature = "seaorm")]
pub async fn refresh_oauth_token(
    state: &YAuthState,
    account: &yauth_entity::oauth_accounts::Model,
) -> Result<String, ApiError> {
    let access_token = account
        .access_token_enc
        .as_deref()
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "No access token available"))?;

    let now = chrono::Utc::now().fixed_offset();
    let buffer = chrono::Duration::minutes(5);
    if let Some(expires_at) = account.expires_at {
        if expires_at > now + buffer {
            return Ok(access_token.to_string());
        }
    } else {
        return Ok(access_token.to_string());
    }

    let refresh_token_str = account.refresh_token_enc.as_deref().ok_or_else(|| {
        api_err(
            StatusCode::UNAUTHORIZED,
            "Token expired and no refresh token available. Please re-connect your account.",
        )
    })?;

    let provider_config = find_provider_config(state, &account.provider)?;
    let redirect_uri = format!(
        "{}/oauth/{}/callback",
        state.config.base_url.trim_end_matches('/'),
        account.provider
    );
    let client = build_oauth_client(provider_config, &redirect_uri)?;

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build HTTP client for token refresh: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let token_result = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token_str.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!(event = "oauth_token_refresh_error", provider = %account.provider, error = %e, "OAuth token refresh failed");
            api_err(StatusCode::UNAUTHORIZED, "Token refresh failed. Please re-connect your account.")
        })?;

    let new_access_token = token_result.access_token().secret().clone();
    let new_refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
    let new_expires_at = token_result.expires_in().map(|d| {
        (chrono::Utc::now() + chrono::Duration::seconds(d.as_secs() as i64)).fixed_offset()
    });

    let mut active: yauth_entity::oauth_accounts::ActiveModel = account.clone().into();
    active.access_token_enc = Set(Some(new_access_token.clone()));
    if let Some(rt) = new_refresh_token {
        active.refresh_token_enc = Set(Some(rt));
    }
    active.expires_at = Set(new_expires_at);
    active.updated_at = Set(chrono::Utc::now().fixed_offset());
    active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to update refreshed OAuth tokens: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    info!(event = "oauth_token_refreshed", provider = %account.provider, user_id = %account.user_id, "OAuth token refreshed successfully");

    Ok(new_access_token)
}

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

    info!(event = "oauth_authorize_start", provider = %provider, "OAuth authorization flow started");
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
        warn!(event = "oauth_callback_error", provider = %provider, error = %error, description = %desc, "OAuth provider returned error");
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
    #[cfg(feature = "seaorm")]
    let response = {
        let accounts = yauth_entity::oauth_accounts::Entity::find()
            .filter(yauth_entity::oauth_accounts::Column::UserId.eq(user.id))
            .all(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list OAuth accounts: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        accounts
            .into_iter()
            .map(|a| OAuthAccountResponse {
                id: a.id.to_string(),
                provider: a.provider,
                provider_user_id: a.provider_user_id,
                created_at: a.created_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    #[cfg(feature = "diesel-async")]
    let response = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let accounts = diesel_db::find_oauth_accounts_by_user(&mut conn, user.id)
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
    #[cfg(feature = "seaorm")]
    {
        let account = yauth_entity::oauth_accounts::Entity::find()
            .filter(yauth_entity::oauth_accounts::Column::UserId.eq(user.id))
            .filter(yauth_entity::oauth_accounts::Column::Provider.eq(&provider))
            .one(&state.db)
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
        yauth_entity::oauth_accounts::Entity::delete_by_id(account.id)
            .exec(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to unlink OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }
    #[cfg(feature = "diesel-async")]
    {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        let account =
            diesel_db::find_oauth_account_by_user_and_provider(&mut conn, user.id, &provider)
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
        diesel_db::delete_oauth_account(&mut conn, account.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to unlink OAuth account: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    info!(event = "oauth_account_unlinked", user_id = %user.id, provider = %provider, "OAuth account unlinked");
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

    #[cfg(feature = "seaorm")]
    let existing = {
        yauth_entity::oauth_accounts::Entity::find()
            .filter(yauth_entity::oauth_accounts::Column::UserId.eq(user.id))
            .filter(yauth_entity::oauth_accounts::Column::Provider.eq(&provider))
            .one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
    };
    #[cfg(feature = "diesel-async")]
    let existing = {
        let mut conn = state
            .db
            .get()
            .await
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;
        diesel_db::find_oauth_account_by_user_and_provider(&mut conn, user.id, &provider)
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

    info!(event = "oauth_link_start", user_id = %user.id, provider = %provider, "OAuth account linking flow started");

    Ok(Json(AuthorizeResponse {
        auth_url: auth_url.to_string(),
    }))
}
