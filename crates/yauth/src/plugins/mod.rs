#[cfg(feature = "email-password")]
pub mod email_password;

#[cfg(feature = "passkey")]
pub mod passkey;

#[cfg(feature = "mfa")]
pub mod mfa;

#[cfg(feature = "oauth")]
pub mod oauth;

#[cfg(feature = "bearer")]
pub mod bearer;

#[cfg(feature = "api-key")]
pub mod api_key;

#[cfg(feature = "magic-link")]
pub mod magic_link;

#[cfg(feature = "admin")]
pub mod admin;

use axum::{
    Extension, Json, Router,
    http::StatusCode,
    routing::{get, patch, post},
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::Deserialize;
use ts_rs::TS;

use crate::middleware::AuthUser;
use crate::plugin::PluginContext;
use crate::state::YAuthState;

/// Core routes that are always available (session + logout + profile update)
pub fn core_routes(_ctx: &PluginContext) -> Router<YAuthState> {
    Router::new()
        .route("/session", get(get_session))
        .route("/logout", post(logout))
        .route("/me", patch(update_profile))
}

async fn get_session(Extension(user): Extension<AuthUser>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "email_verified": user.email_verified,
            "role": user.role,
            "banned": user.banned,
            "auth_method": format!("{:?}", user.auth_method).to_lowercase(),
        }
    }))
}

#[derive(Deserialize, TS)]
#[ts(export)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
}

async fn update_profile(
    axum::extract::State(state): axum::extract::State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    Json(input): Json<UpdateProfileRequest>,
) -> impl axum::response::IntoResponse {
    let db_user = match yauth_entity::users::Entity::find_by_id(user.id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "User not found" })),
            );
        }
        Err(e) => {
            tracing::error!("DB error fetching user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal error" })),
            );
        }
    };

    let mut active: yauth_entity::users::ActiveModel = db_user.into();

    if let Some(display_name) = input.display_name {
        let trimmed = display_name.trim().to_string();
        active.display_name = Set(if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        });
    }

    active.updated_at = Set(Utc::now().fixed_offset());

    match active.update(&state.db).await {
        Ok(updated) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "user": {
                    "id": updated.id,
                    "email": updated.email,
                    "display_name": updated.display_name,
                    "email_verified": updated.email_verified,
                    "role": updated.role,
                    "banned": updated.banned,
                }
            })),
        ),
        Err(e) => {
            tracing::error!("DB error updating profile: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal error" })),
            )
        }
    }
}

async fn logout(
    axum::extract::State(state): axum::extract::State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> impl axum::response::IntoResponse {
    // Delete session if cookie-based auth
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let _ = crate::auth::session::delete_session(&state.db, cookie.value()).await;
    }

    state
        .write_audit_log(Some(user.id), "logout", None, None)
        .await;

    let clear_cookie = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        state.config.session_cookie_name
    );

    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, clear_cookie)],
        Json(serde_json::json!({ "success": true })),
    )
}
