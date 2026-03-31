use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::api_err;
use crate::state::YAuthState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub auth_method: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum AuthMethod {
    Session,
    Bearer,
    ApiKey,
}

/// Record authenticated user context on the current (SERVER) span.
fn record_auth_user_on_span(user: &AuthUser) {
    let span = tracing::Span::current();
    span.record("user.id", tracing::field::display(&user.id));
    span.record("user.email", user.email.as_str());
    span.record("user.roles", user.role.as_str());
    span.record(
        "yauth.auth_method",
        match &user.auth_method {
            AuthMethod::Session => "session",
            AuthMethod::Bearer => "bearer",
            AuthMethod::ApiKey => "api_key",
        },
    );
}

pub async fn auth_middleware(
    State(state): State<YAuthState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    // If a prior middleware (e.g. API key auth) already set AuthUser, skip re-checking.
    if req.extensions().get::<AuthUser>().is_some() {
        return next.run(req).await;
    }

    let request_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
        });
    let request_ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    // Try session cookie first
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let token = cookie.value();
        match crate::auth::session::validate_session(
            &state,
            token,
            request_ip.as_deref(),
            request_ua.as_deref(),
        )
        .await
        {
            Ok(Some(session_user)) => {
                match lookup_user(&state, session_user.user_id, AuthMethod::Session).await {
                    Ok(auth_user) => {
                        if auth_user.banned {
                            return api_err(StatusCode::FORBIDDEN, "Account suspended")
                                .into_response();
                        }
                        record_auth_user_on_span(&auth_user);
                        req.extensions_mut().insert(auth_user);
                        return next.run(req).await;
                    }
                    Err(e) => {
                        tracing::error!("User lookup failed: {}", e);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("Session validation error: {}", e);
            }
        }
    }

    // Try Bearer token
    #[cfg(feature = "bearer")]
    #[allow(clippy::collapsible_if)]
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                if let Ok(auth_user) = crate::plugins::bearer::validate_jwt(token, &state).await {
                    record_auth_user_on_span(&auth_user);
                    req.extensions_mut().insert(auth_user);
                    return next.run(req).await;
                }
            }
        }
    }

    // Try API key
    #[cfg(feature = "api-key")]
    #[allow(clippy::collapsible_if)]
    if let Some(api_key_header) = headers.get("x-api-key") {
        if let Ok(key_str) = api_key_header.to_str() {
            if let Ok(auth_user) = crate::plugins::api_key::validate_api_key(key_str, &state).await
            {
                record_auth_user_on_span(&auth_user);
                req.extensions_mut().insert(auth_user);
                return next.run(req).await;
            }
        }
    }

    let _ = &headers;

    api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

async fn lookup_user(
    state: &YAuthState,
    user_id: Uuid,
    method: AuthMethod,
) -> Result<AuthUser, String> {
    use crate::db::schema::yauth_users;
    use diesel::prelude::*;
    use diesel::result::OptionalExtension;
    use diesel_async_crate::RunQueryDsl;

    let mut conn = state.db.get().await.map_err(|e| e.to_string())?;
    let user = yauth_users::table
        .find(user_id)
        .select(crate::db::models::User::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User not found".to_string())?;

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        role: user.role,
        banned: user.banned,
        auth_method: method,
        scopes: None,
    })
}

pub fn require_scope(
    scope: &'static str,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone {
    move |req: Request, next: Next| {
        Box::pin(async move {
            if let Some(user) = req.extensions().get::<AuthUser>() {
                if let Some(ref scopes) = user.scopes
                    && !scopes.iter().any(|s| s == scope)
                {
                    return (
                        StatusCode::FORBIDDEN,
                        axum::Json(serde_json::json!({
                            "error": "insufficient_scope",
                            "error_description": format!("Required scope: {}", scope)
                        })),
                    )
                        .into_response();
                }
                return next.run(req).await;
            }
            api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
        })
    }
}

pub async fn require_admin(req: Request, next: Next) -> Response {
    if let Some(user) = req.extensions().get::<AuthUser>() {
        if user.role == "admin" {
            return next.run(req).await;
        }
        return api_err(StatusCode::FORBIDDEN, "Admin access required").into_response();
    }
    api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user() -> AuthUser {
        AuthUser {
            id: Uuid::nil(),
            email: "test@example.com".into(),
            display_name: Some("Test User".into()),
            email_verified: true,
            role: "user".into(),
            banned: false,
            auth_method: AuthMethod::Session,
            scopes: None,
        }
    }

    #[test]
    fn auth_user_serialization_roundtrip() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        let parsed: AuthUser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, user.id);
        assert_eq!(parsed.email, "test@example.com");
        assert_eq!(parsed.display_name, Some("Test User".into()));
        assert!(parsed.email_verified);
    }

    #[test]
    fn auth_method_variants_serialize() {
        for method in [AuthMethod::Session, AuthMethod::Bearer, AuthMethod::ApiKey] {
            let json = serde_json::to_string(&method).unwrap();
            let _: AuthMethod = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn auth_user_with_no_display_name() {
        let user = AuthUser {
            display_name: None,
            ..sample_user()
        };
        let json = serde_json::to_string(&user).unwrap();
        let parsed: AuthUser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.display_name, None);
    }
}
