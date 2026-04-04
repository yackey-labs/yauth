use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::SET_COOKIE},
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
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

    fn schema(&self) -> Vec<crate::schema::TableDef> {
        crate::schema::plugin_schemas::magic_link_schema()
    }
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
        .repos
        .rate_limits
        .check_rate_limit(&format!("magic-link:{}", email), 10, 60)
        .await
        .map(|r| r.allowed)
        .unwrap_or(true)
    {
        crate::otel::add_event(
            "magic_link_rate_limited",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Err(api_err(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }

    if email.is_empty() || !email.contains('@') {
        return Err(api_err(StatusCode::BAD_REQUEST, "Valid email is required"));
    }

    let success_msg = Json(MagicLinkMessageResponse {
        message: "If an account exists with that email, a magic link has been sent.".to_string(),
    });

    let ml_config = &state.magic_link_config;

    let user_opt = state.repos.users.find_by_email(&email).await.map_err(|e| {
        crate::otel::record_error("db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    if user_opt.is_none() && (!ml_config.allow_signup || !state.config.allow_signups) {
        crate::otel::add_event(
            "magic_link_no_user",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Ok(success_msg);
    }

    if let Some(ref u) = user_opt
        && u.banned
    {
        crate::otel::add_event(
            "magic_link_banned_user",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("user.email", email.clone())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return Ok(success_msg);
    }

    // Delete old unused magic links
    let _ = state
        .repos
        .magic_links
        .delete_unused_for_email(&email)
        .await;

    let token = crypto::generate_token();
    let token_hash = crypto::hash_token(&token);
    let expires_at = (chrono::Utc::now()
        + chrono::Duration::seconds(ml_config.link_ttl.as_secs() as i64))
    .naive_utc();

    let new_link = crate::domain::NewMagicLink {
        id: Uuid::new_v4(),
        email: email.clone(),
        token_hash,
        expires_at,
        created_at: chrono::Utc::now().naive_utc(),
    };

    state
        .repos
        .magic_links
        .create(new_link)
        .await
        .map_err(|e| {
            crate::otel::record_error("magic_link_create_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    if let Some(ref email_service) = state.email_service
        && let Err(e) = email_service.send_magic_link_email(&email, &token)
    {
        crate::otel::record_error("send_magic_link_email_failed", &e);
    }

    state.emit_event(&AuthEvent::MagicLinkSent {
        email: email.clone(),
    });
    crate::otel::add_event(
        "magic_link_sent",
        #[cfg(feature = "telemetry")]
        vec![opentelemetry::KeyValue::new("user.email", email.clone())],
        #[cfg(not(feature = "telemetry"))]
        vec![],
    );

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

    let ml = state
        .repos
        .magic_links
        .find_unused_by_token_hash(&token_hash)
        .await
        .map_err(|e| {
            crate::otel::record_error("db_error", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Invalid or expired magic link"))?;

    let now_naive = chrono::Utc::now().naive_utc();
    if ml.expires_at < now_naive {
        let _ = state.repos.magic_links.delete(ml.id).await;
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Magic link has expired. Please request a new one.",
        ));
    }

    // Mark as used
    let ml_id = ml.id;
    state
        .repos
        .magic_links
        .mark_used(ml_id)
        .await
        .map_err(|e| {
            crate::otel::record_error("magic_link_mark_used_failed", &e);
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;

    let email = &ml.email;
    let ml_config = &state.magic_link_config;

    let user_opt = state.repos.users.find_by_email(email).await.map_err(|e| {
        crate::otel::record_error("db_error", &e);
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let (user_model, is_new_user) = match user_opt {
        Some(u) => {
            if u.banned {
                crate::otel::add_event(
                    "magic_link_verify_banned_user",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new(
                        "user.email",
                        email.to_string(),
                    )],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
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
                crate::otel::add_event(
                    "register_auto_admin",
                    #[cfg(feature = "telemetry")]
                    vec![opentelemetry::KeyValue::new(
                        "user.email",
                        email.to_string(),
                    )],
                    #[cfg(not(feature = "telemetry"))]
                    vec![],
                );
                "admin".to_string()
            } else {
                ml_config
                    .default_role
                    .as_deref()
                    .unwrap_or("user")
                    .to_string()
            };

            let now = chrono::Utc::now().naive_utc();
            let new_user = crate::domain::NewUser {
                id: user_id,
                email: email.clone(),
                display_name: None,
                email_verified: true,
                role: role.clone(),
                banned: false,
                banned_reason: None,
                banned_until: None,
                created_at: now,
                updated_at: now,
            };

            let created_user = state.repos.users.create(new_user).await.map_err(|e| {
                crate::otel::record_error("magic_link_user_create_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;

            crate::otel::add_event(
                "magic_link_user_created",
                #[cfg(feature = "telemetry")]
                vec![
                    opentelemetry::KeyValue::new("user.email", email.to_string()),
                    opentelemetry::KeyValue::new("user.id", user_id.to_string()),
                ],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            state.emit_event(&AuthEvent::UserRegistered {
                user_id,
                email: email.clone(),
            });

            (created_user, true)
        }
    };

    if !user_model.email_verified {
        let changeset = crate::domain::UpdateUser {
            email_verified: Some(true),
            updated_at: Some(chrono::Utc::now().naive_utc()),
            ..Default::default()
        };
        state
            .repos
            .users
            .update(user_model.id, changeset)
            .await
            .map_err(|e| {
                crate::otel::record_error("user_email_verified_update_failed", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            })?;
    }

    let (session_token, _session_id) =
        session::create_session(&state, user_model.id, None, None, state.config.session_ttl)
            .await
            .map_err(|e| {
                crate::otel::record_error("session_create_failed", &e);
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

    crate::otel::add_event(
        "magic_link_verified",
        #[cfg(feature = "telemetry")]
        vec![
            opentelemetry::KeyValue::new("user.email", email.to_string()),
            opentelemetry::KeyValue::new("user.id", user_model.id.to_string()),
            opentelemetry::KeyValue::new("is_new_user", is_new_user),
            opentelemetry::KeyValue::new("magic_link.id", ml_id.to_string()),
        ],
        #[cfg(not(feature = "telemetry"))]
        vec![],
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
