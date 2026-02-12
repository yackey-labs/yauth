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

#[cfg(feature = "admin")]
pub mod admin;

use axum::{
    Extension, Json, Router,
    http::StatusCode,
    routing::{get, post},
};

use crate::middleware::AuthUser;
use crate::plugin::PluginContext;
use crate::state::YAuthState;

/// Core routes that are always available (session + logout)
pub fn core_routes(_ctx: &PluginContext) -> Router<YAuthState> {
    Router::new()
        .route("/session", get(get_session))
        .route("/logout", post(logout))
}

async fn get_session(Extension(user): Extension<AuthUser>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "displayName": user.display_name,
            "emailVerified": user.email_verified,
            "role": user.role,
            "banned": user.banned,
            "authMethod": format!("{:?}", user.auth_method).to_lowercase(),
        }
    }))
}

async fn logout(
    axum::extract::State(state): axum::extract::State<YAuthState>,
    Extension(user): Extension<AuthUser>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> impl axum::response::IntoResponse {
    let _ = &user; // acknowledge user is authenticated

    // Delete session if cookie-based auth
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let _ = crate::auth::session::delete_session(&state.db, cookie.value()).await;
    }

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
