use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::YAuthState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub auth_method: AuthMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    Session,
    Bearer,
    ApiKey,
}

pub async fn auth_middleware(
    State(state): State<YAuthState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    // Try session cookie first
    if let Some(cookie) = jar.get(&state.config.session_cookie_name) {
        let token = cookie.value();
        match crate::auth::session::validate_session(&state.db, token).await {
            Ok(Some(session_user)) => {
                match lookup_user(&state, session_user.user_id, AuthMethod::Session).await {
                    Ok(auth_user) => {
                        if auth_user.banned {
                            return (StatusCode::FORBIDDEN, "Account suspended").into_response();
                        }
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
    // Note: nested ifs are intentional — collapsing causes type inference failures (E0282)
    #[cfg(feature = "bearer")]
    #[allow(clippy::collapsible_if)]
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                if let Ok(auth_user) =
                    crate::plugins::bearer::validate_jwt(token, &state).await
                {
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
            if let Ok(auth_user) =
                crate::plugins::api_key::validate_api_key(key_str, &state).await
            {
                req.extensions_mut().insert(auth_user);
                return next.run(req).await;
            }
        }
    }

    // Suppress unused variable warnings when features are disabled
    let _ = &headers;

    (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

async fn lookup_user(
    state: &YAuthState,
    user_id: Uuid,
    method: AuthMethod,
) -> Result<AuthUser, sea_orm::DbErr> {
    let user = yauth_entity::users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or(sea_orm::DbErr::RecordNotFound("User not found".into()))?;

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        email_verified: user.email_verified,
        role: user.role,
        banned: user.banned,
        auth_method: method,
    })
}

pub async fn require_admin(req: Request, next: Next) -> Response {
    if let Some(user) = req.extensions().get::<AuthUser>() {
        if user.role == "admin" {
            return next.run(req).await;
        }
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }
    (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
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
