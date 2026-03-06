use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::post,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ts_rs::TS;
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

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct MagicLinkSendRequest {
    pub email: String,
}

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct MagicLinkVerifyRequest {
    pub token: String,
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct MagicLinkMessageResponse {
    pub message: String,
}

async fn send_magic_link(
    State(state): State<YAuthState>,
    Json(input): Json<MagicLinkSendRequest>,
) -> Result<Json<MagicLinkMessageResponse>, ApiError> {
    let email = input.email.trim().to_lowercase();

    // Rate limit per email
    if !state
        .rate_limiter
        .check(&format!("magic-link:{}", email))
        .await
    {
        warn!(
            event = "magic_link_rate_limited",
            email = %email,
            "Magic link rate limited"
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    if email.is_empty() || !email.contains('@') {
        return Err(api_err(StatusCode::BAD_REQUEST, "Valid email is required"));
    }

    // Always return success to prevent email enumeration.
    // We still generate a token and send the email if the user exists (or signup is allowed).
    let success_msg = Json(MagicLinkMessageResponse {
        message: "If an account exists with that email, a magic link has been sent.".to_string(),
    });

    let ml_config = &state.magic_link_config;

    // Check if user exists
    let user = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    // If no user and signup not allowed, return success silently (prevent enumeration)
    if user.is_none() && !ml_config.allow_signup {
        info!(
            event = "magic_link_no_user",
            email = %email,
            "Magic link requested for non-existent email (signup disabled)"
        );
        return Ok(success_msg);
    }

    // If user is banned, return success silently
    if let Some(ref u) = user
        && u.banned
    {
        warn!(
            event = "magic_link_banned",
            email = %email,
            "Magic link requested for banned user"
        );
        return Ok(success_msg);
    }

    // Delete old unused magic links for this email
    yauth_entity::magic_links::Entity::delete_many()
        .filter(yauth_entity::magic_links::Column::Email.eq(&email))
        .filter(yauth_entity::magic_links::Column::Used.eq(false))
        .exec(&state.db)
        .await
        .ok();

    // Generate token
    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let now = chrono::Utc::now().fixed_offset();
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(ml_config.link_ttl.as_secs() as i64))
    .fixed_offset();

    let magic_link = yauth_entity::magic_links::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email.clone()),
        token_hash: Set(token_hash),
        expires_at: Set(expires_at),
        used: Set(false),
        created_at: Set(now),
    };

    magic_link.insert(&state.db).await.map_err(|e| {
        tracing::error!("Failed to create magic link: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    // Send email
    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_magic_link_email(&email, &token)
    {
        tracing::error!("Failed to send magic link email: {}", e);
    }

    // Emit event
    state.emit_event(&AuthEvent::MagicLinkSent {
        email: email.clone(),
    });

    info!(
        event = "magic_link_sent",
        email = %email,
        "Magic link sent"
    );

    Ok(success_msg)
}

async fn verify_magic_link(
    State(state): State<YAuthState>,
    Json(input): Json<MagicLinkVerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = input.token.trim();
    if token.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "Token is required"));
    }

    let token_hash = crypto::hash_token(token);

    // Find the magic link
    let magic_link = yauth_entity::magic_links::Entity::find()
        .filter(yauth_entity::magic_links::Column::TokenHash.eq(&token_hash))
        .filter(yauth_entity::magic_links::Column::Used.eq(false))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired magic link"))?;

    // Check expiry
    let now = chrono::Utc::now().fixed_offset();
    if magic_link.expires_at < now {
        // Clean up expired token
        yauth_entity::magic_links::Entity::delete_by_id(magic_link.id)
            .exec(&state.db)
            .await
            .ok();
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Magic link has expired. Please request a new one.",
        ));
    }

    // Mark as used
    let ml_id = magic_link.id;
    let mut ml_active: yauth_entity::magic_links::ActiveModel = magic_link.clone().into();
    ml_active.used = Set(true);
    ml_active.update(&state.db).await.map_err(|e| {
        tracing::error!("Failed to mark magic link as used: {}", e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let email = &magic_link.email;
    let ml_config = &state.magic_link_config;

    // Find or create user
    let user = yauth_entity::users::Entity::find()
        .filter(yauth_entity::users::Column::Email.eq(email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let (user_model, is_new_user) = match user {
        Some(u) => {
            if u.banned {
                warn!(
                    event = "magic_link_verify_banned",
                    email = %email,
                    "Magic link verify for banned user"
                );
                return Err(api_err(StatusCode::FORBIDDEN, "Account suspended"));
            }
            (u, false)
        }
        None => {
            if !ml_config.allow_signup {
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Account does not exist. Registration via magic link is disabled.",
                ));
            }

            // Auto-create user
            let user_id = Uuid::new_v4();
            let role = if state.should_auto_admin().await {
                tracing::info!(event = "auto_admin_first_user", email = %email, "First user — assigning admin role");
                "admin".to_string()
            } else {
                ml_config
                    .default_role
                    .as_deref()
                    .unwrap_or("user")
                    .to_string()
            };

            let new_user = yauth_entity::users::ActiveModel {
                id: Set(user_id),
                email: Set(email.clone()),
                display_name: Set(None),
                email_verified: Set(true), // Verified by magic link
                role: Set(role),
                banned: Set(false),
                banned_reason: Set(None),
                banned_until: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };

            let inserted = new_user.insert(&state.db).await.map_err(|e| {
                tracing::error!("Failed to create user via magic link: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

            info!(
                event = "magic_link_user_created",
                email = %email,
                user_id = %user_id,
                "User auto-created via magic link"
            );

            state.emit_event(&AuthEvent::UserRegistered {
                user_id,
                email: email.clone(),
            });

            (inserted, true)
        }
    };

    // Ensure email is verified (in case user existed but wasn't verified)
    if !user_model.email_verified {
        let mut user_active: yauth_entity::users::ActiveModel = user_model.clone().into();
        user_active.email_verified = Set(true);
        user_active.updated_at = Set(now);
        user_active.update(&state.db).await.map_err(|e| {
            tracing::error!("Failed to update user email_verified: {}", e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
    }

    // Create session
    let (session_token, _session_id) =
        session::create_session(&state.db, user_model.id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create session: {}", e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

    // Emit events
    state.emit_event(&AuthEvent::MagicLinkVerified {
        user_id: user_model.id,
        is_new_user,
    });

    state.emit_event(&AuthEvent::LoginSucceeded {
        user_id: user_model.id,
        method: "magic-link".to_string(),
    });

    info!(
        event = "magic_link_verified",
        email = %email,
        user_id = %user_model.id,
        is_new_user = is_new_user,
        magic_link_id = %ml_id,
        "Magic link verified, session created"
    );

    Ok((
        [(SET_COOKIE, session_set_cookie(&state, &session_token, state.config.session_ttl))],
        Json(serde_json::json!({
            "user_id": user_model.id.to_string(),
            "email": user_model.email,
            "display_name": user_model.display_name,
            "email_verified": true,
            "is_new_user": is_new_user,
        })),
    ))
}
