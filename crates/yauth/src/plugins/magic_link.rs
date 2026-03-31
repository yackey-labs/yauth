use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::post,
};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::session::session_set_cookie;
use crate::auth::{crypto, session};
use crate::config::MagicLinkConfig;
use crate::db::models::{MagicLink, NewMagicLink, NewUser, User};
use crate::db::schema::{yauth_magic_links, yauth_users};
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
// Database helpers
// ---------------------------------------------------------------------------

type Conn = diesel_async_crate::AsyncPgConnection;
type DbResult<T> = Result<T, String>;

async fn db_find_user_by_email(conn: &mut Conn, email: &str) -> DbResult<Option<User>> {
    yauth_users::table
        .filter(yauth_users::email.eq(email))
        .select(User::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_delete_unused_magic_links_for_email(conn: &mut Conn, email: &str) -> DbResult<()> {
    diesel::delete(
        yauth_magic_links::table.filter(
            yauth_magic_links::email
                .eq(email)
                .and(yauth_magic_links::used.eq(false)),
        ),
    )
    .execute(conn)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_insert_magic_link(
    conn: &mut Conn,
    id: Uuid,
    email: &str,
    token_hash: &str,
    expires_at: chrono::DateTime<chrono::FixedOffset>,
) -> DbResult<()> {
    let new_link = NewMagicLink {
        id,
        email: email.to_string(),
        token_hash: token_hash.to_string(),
        expires_at: expires_at.naive_utc(),
        created_at: chrono::Utc::now().naive_utc(),
    };
    diesel::insert_into(yauth_magic_links::table)
        .values(&new_link)
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_find_unused_magic_link_by_token(
    conn: &mut Conn,
    token_hash: &str,
) -> DbResult<Option<MagicLink>> {
    yauth_magic_links::table
        .filter(
            yauth_magic_links::token_hash
                .eq(token_hash)
                .and(yauth_magic_links::used.eq(false)),
        )
        .select(MagicLink::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

async fn db_delete_magic_link(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::delete(yauth_magic_links::table.filter(yauth_magic_links::id.eq(id)))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_mark_magic_link_used(conn: &mut Conn, id: Uuid) -> DbResult<()> {
    diesel::update(yauth_magic_links::table.filter(yauth_magic_links::id.eq(id)))
        .set(yauth_magic_links::used.eq(true))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn db_insert_user(conn: &mut Conn, id: Uuid, email: &str, role: &str) -> DbResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let new_user = NewUser {
        id,
        email: email.to_string(),
        display_name: None,
        email_verified: true,
        role: role.to_string(),
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

async fn db_set_user_email_verified(conn: &mut Conn, user_id: Uuid) -> DbResult<()> {
    diesel::update(yauth_users::table.filter(yauth_users::id.eq(user_id)))
        .set((
            yauth_users::email_verified.eq(true),
            yauth_users::updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MagicLinkSendRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MagicLinkVerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

    let user_opt = {
        db_find_user_by_email(&mut conn, &email)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
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
        db_delete_unused_magic_links_for_email(&mut conn, &email)
            .await
            .ok();
    }

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(ml_config.link_ttl.as_secs() as i64))
    .fixed_offset();

    {
        db_insert_magic_link(&mut conn, Uuid::new_v4(), &email, &token_hash, expires_at)
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

    let ml = {
        db_find_unused_magic_link_by_token(&mut conn, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!("DB error: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?
            .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired magic link"))?
    };

    let now_naive = chrono::Utc::now().naive_utc();
    if ml.expires_at < now_naive {
        {
            db_delete_magic_link(&mut conn, ml.id).await.ok();
        }
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Magic link has expired. Please request a new one.",
        ));
    }

    // Mark as used
    let ml_id = ml.id;
    {
        db_mark_magic_link_used(&mut conn, ml_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to mark magic link as used: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    let email = &ml.email;
    let ml_config = &state.magic_link_config;

    let user_opt = {
        db_find_user_by_email(&mut conn, email).await.map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
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
                db_insert_user(&mut conn, user_id, email, &role)
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

            let now = chrono::Utc::now().naive_utc();
            (
                User {
                    id: user_id,
                    email: email.clone(),
                    display_name: None,
                    email_verified: true,
                    role,
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: now,
                    updated_at: now,
                },
                true,
            )
        }
    };

    if !user_model.email_verified {
        {
            db_set_user_email_verified(&mut conn, user_model.id)
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
