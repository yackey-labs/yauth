use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::session::session_set_cookie;
use crate::auth::{crypto, session};
use crate::config::MagicLinkConfig;
use crate::error::{ApiError, api_err};
use crate::plugin::{AuthEvent, PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub struct MagicLinkPlugin;

impl MagicLinkPlugin {
    pub fn new(_config: MagicLinkConfig) -> Self {
        Self
    }
}

impl YAuthPlugin for MagicLinkPlugin {
    fn name(&self) -> &'static str {
        "magic-link"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route("/magic-link/send", post(send_magic_link))
                .route("/magic-link/verify", post(verify_magic_link)),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
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
    pub struct MagicLinkRow {
        #[diesel(sql_type = diesel::sql_types::Uuid)]
        pub id: Uuid,
        #[diesel(sql_type = diesel::sql_types::Text)]
        pub email: String,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        pub expires_at: chrono::NaiveDateTime,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pub used: bool,
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

    pub async fn delete_unused_magic_links_for_email(conn: &mut Conn, email: &str) -> DbResult<()> {
        diesel::sql_query("DELETE FROM yauth_magic_links WHERE email = $1 AND used = false")
            .bind::<diesel::sql_types::Text, _>(email)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn insert_magic_link(
        conn: &mut Conn,
        id: Uuid,
        email: &str,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> DbResult<()> {
        diesel::sql_query(
            "INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, used, created_at) VALUES ($1, $2, $3, $4, false, $5)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Text, _>(email)
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
        .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn find_unused_magic_link_by_token(
        conn: &mut Conn,
        token_hash: &str,
    ) -> DbResult<Option<MagicLinkRow>> {
        diesel::sql_query(
            "SELECT id, email, expires_at, used FROM yauth_magic_links WHERE token_hash = $1 AND used = false",
        )
        .bind::<diesel::sql_types::Text, _>(token_hash)
        .get_result(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
    }

    pub async fn delete_magic_link(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("DELETE FROM yauth_magic_links WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn mark_magic_link_used(conn: &mut Conn, id: Uuid) -> DbResult<()> {
        diesel::sql_query("UPDATE yauth_magic_links SET used = true WHERE id = $1")
            .bind::<diesel::sql_types::Uuid, _>(id)
            .execute(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn insert_user(conn: &mut Conn, id: Uuid, email: &str, role: &str) -> DbResult<()> {
        let now = chrono::Utc::now();
        diesel::sql_query(
            "INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, created_at, updated_at) VALUES ($1, $2, NULL, true, $3, false, $4, $4)",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<diesel::sql_types::Text, _>(email)
        .bind::<diesel::sql_types::Text, _>(role)
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn set_user_email_verified(conn: &mut Conn, user_id: Uuid) -> DbResult<()> {
        diesel::sql_query(
            "UPDATE yauth_users SET email_verified = true, updated_at = $1 WHERE id = $2",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct MagicLinkSendRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct MagicLinkVerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct MagicLinkMessageResponse {
    pub message: String,
}

// ---------------------------------------------------------------------------
// POST /magic-link/send
// ---------------------------------------------------------------------------

async fn send_magic_link(
    State(state): State<YAuthState>,
    Json(input): Json<MagicLinkSendRequest>,
) -> Result<Json<MagicLinkMessageResponse>, ApiError> {
    let email = input.email.trim().to_lowercase();

    if !state
        .rate_limiter
        .check(&format!("magic-link:{}", email))
        .await
    {
        warn!(event = "yauth.magic_link.rate_limited", email = %email, "Magic link rate limited");
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    if email.is_empty() || !email.contains('@') {
        return Err(api_err(StatusCode::BAD_REQUEST, "Valid email is required"));
    }

    let success_msg = Json(MagicLinkMessageResponse {
        message: "If an account exists with that email, a magic link has been sent.".to_string(),
    });

    let ml_config = &state.magic_link_config;

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    struct UserInfo {
        banned: bool,
    }

    let user_opt = {
        let user = diesel_db::find_user_by_email(&mut conn, &email)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
        user.map(|u| UserInfo { banned: u.banned })
    };

    if user_opt.is_none() && (!ml_config.allow_signup || !state.config.allow_signups) {
        info!(event = "yauth.magic_link.no_user", email = %email, "Magic link requested for non-existent email (signup disabled)");
        return Ok(success_msg);
    }

    if let Some(ref u) = user_opt
        && u.banned
    {
        warn!(event = "yauth.magic_link.banned", email = %email, "Magic link requested for banned user");
        return Ok(success_msg);
    }

    // Delete old unused magic links
    {
        diesel_db::delete_unused_magic_links_for_email(&mut conn, &email)
            .await
            .ok();
    }

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(ml_config.link_ttl.as_secs() as i64))
    .fixed_offset();

    {
        diesel_db::insert_magic_link(&mut conn, Uuid::new_v4(), &email, &token_hash, expires_at)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create magic link: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_magic_link_email(&email, &token)
    {
        tracing::error!("Failed to send magic link email: {}", e);
    }

    state.emit_event(&AuthEvent::MagicLinkSent {
        email: email.clone(),
    });
    info!(event = "yauth.magic_link.sent", email = %email, "Magic link sent");

    Ok(success_msg)
}

// ---------------------------------------------------------------------------
// POST /magic-link/verify
// ---------------------------------------------------------------------------

async fn verify_magic_link(
    State(state): State<YAuthState>,
    Json(input): Json<MagicLinkVerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = input.token.trim();
    if token.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "Token is required"));
    }

    let token_hash = crypto::hash_token(token);

    let mut conn = state
        .db
        .get()
        .await
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))?;

    struct MlInfo {
        id: Uuid,
        email: String,
        expires_at: chrono::NaiveDateTime,
    }

    let ml_info = {
        let ml = diesel_db::find_unused_magic_link_by_token(&mut conn, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired magic link"))?;
        MlInfo {
            id: ml.id,
            email: ml.email,
            expires_at: ml.expires_at,
        }
    };

    let now_naive = chrono::Utc::now().naive_utc();
    if ml_info.expires_at < now_naive {
        {
            diesel_db::delete_magic_link(&mut conn, ml_info.id)
                .await
                .ok();
        }
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Magic link has expired. Please request a new one.",
        ));
    }

    // Mark as used
    let ml_id = ml_info.id;
    {
        diesel_db::mark_magic_link_used(&mut conn, ml_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to mark magic link as used: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    let email = &ml_info.email;
    let ml_config = &state.magic_link_config;

    struct VerifyUser {
        id: Uuid,
        email: String,
        display_name: Option<String>,
        email_verified: bool,
        banned: bool,
    }

    let user_opt = {
        diesel_db::find_user_by_email(&mut conn, email)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .map(|u| VerifyUser {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                email_verified: u.email_verified,
                banned: u.banned,
            })
    };

    let (user_model, is_new_user) = match user_opt {
        Some(u) => {
            if u.banned {
                warn!(event = "yauth.magic_link.verify_banned", email = %email, "Magic link verify for banned user");
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            (u, false)
        }
        None => {
            if !ml_config.allow_signup || !state.config.allow_signups {
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Account does not exist. Registration is disabled.",
                ));
            }

            let user_id = Uuid::new_v4();
            let role = if state.should_auto_admin().await {
                tracing::info!(event = "yauth.register.auto_admin", email = %email, "First user — assigning admin role");
                "admin".to_string()
            } else {
                ml_config
                    .default_role
                    .as_deref()
                    .unwrap_or("user")
                    .to_string()
            };

            {
                diesel_db::insert_user(&mut conn, user_id, email, &role)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to create user via magic link: {}", e);
                        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                    })?;
            }

            info!(event = "yauth.magic_link.user_created", email = %email, user_id = %user_id, "User auto-created via magic link");
            state.emit_event(&AuthEvent::UserRegistered {
                user_id,
                email: email.clone(),
            });

            (
                VerifyUser {
                    id: user_id,
                    email: email.clone(),
                    display_name: None,
                    email_verified: true,
                    banned: false,
                },
                true,
            )
        }
    };

    if !user_model.email_verified {
        {
            diesel_db::set_user_email_verified(&mut conn, user_model.id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to update user email_verified: {}", e);
                    api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                })?;
        }
    }

    let (session_token, _session_id) = session::create_session(
        &state.db,
        user_model.id,
        None,
        None,
        state.config.session_ttl,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create session: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    state.emit_event(&AuthEvent::MagicLinkVerified {
        user_id: user_model.id,
        is_new_user,
    });
    state.emit_event(&AuthEvent::LoginSucceeded {
        user_id: user_model.id,
        method: "magic-link".to_string(),
    });

    info!(
        event = "yauth.magic_link.verified", email = %email, user_id = %user_model.id,
        is_new_user = is_new_user, magic_link_id = %ml_id, "Magic link verified, session created"
    );

    Ok((
        [(
            SET_COOKIE,
            session_set_cookie(&state, &session_token, state.config.session_ttl),
        )],
        Json(serde_json::json!({
            "user_id": user_model.id.to_string(),
            "email": user_model.email,
            "display_name": user_model.display_name,
            "email_verified": true,
            "is_new_user": is_new_user,
        })),
    ))
}
