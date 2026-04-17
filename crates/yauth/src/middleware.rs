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

/// OAuth 2.0 Client Credentials grant type identifier (RFC 6749 §4.4).
#[cfg(feature = "oauth2-server")]
pub const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";

/// A non-human caller authenticated via OAuth 2.0 Client Credentials grant
/// (RFC 6749 §4.4) or another M2M flow. Sibling of [`AuthUser`].
///
/// Populated as a request extension by [`auth_middleware`] when the incoming
/// `Authorization: Bearer <jwt>` header carries a client_credentials token.
/// Handlers that only care "someone authenticated" keep matching
/// `Extension<AuthUser>` — they will not see machine callers. Handlers that
/// need to distinguish use [`Authenticated::from_extensions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MachineCaller {
    pub client_id: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub audience: Option<String>,
    pub jti: String,
    pub auth_method: MachineAuthMethod,
    /// Custom claims passed through from token issuance. Empty until the
    /// token endpoint's per-client allow-list admits non-reserved claims.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub custom_claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum MachineAuthMethod {
    /// RFC 6749 §4.4 Client Credentials grant, HS256 JWT.
    ClientCredentials,
    // Future: PrivateKeyJwt (see M3 plan).
}

/// The authenticated principal on the request. Either a human user or a
/// machine caller. Obtained via [`Authenticated::from_extensions`] inside
/// handlers that need to distinguish the two.
///
/// For handlers that only care about one principal type, prefer the concrete
/// `Extension<AuthUser>` / `Extension<MachineCaller>` extractors — they avoid
/// the enum-wrap allocation that this helper performs on every call.
#[derive(Debug, Clone)]
pub enum Authenticated {
    User(AuthUser),
    Machine(MachineCaller),
}

impl Authenticated {
    pub fn from_extensions(req: &Request) -> Option<Self> {
        if let Some(user) = req.extensions().get::<AuthUser>() {
            return Some(Self::User(user.clone()));
        }
        if let Some(machine) = req.extensions().get::<MachineCaller>() {
            return Some(Self::Machine(machine.clone()));
        }
        None
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        match self {
            Self::User(u) => u
                .scopes
                .as_ref()
                .is_some_and(|s| s.iter().any(|x| x == scope)),
            Self::Machine(m) => m.scopes.iter().any(|x| x == scope),
        }
    }
}

/// Record authenticated user context on the current (SERVER) span.
fn record_auth_user_on_span(user: &AuthUser) {
    crate::otel::set_attribute("user.id", user.id.to_string());
    // PII: user.email is intentionally omitted. Use user.id for correlation.
    crate::otel::set_attribute("user.roles", user.role.clone());
    crate::otel::set_attribute(
        "yauth.auth_method",
        match &user.auth_method {
            AuthMethod::Session => "session",
            AuthMethod::Bearer => "bearer",
            AuthMethod::ApiKey => "api_key",
        },
    );
}

/// Record machine-caller context on the current (SERVER) span. Never sets
/// `user.id` — that attribute is reserved for human callers so dashboards
/// filtering on it don't silently include M2M traffic.
#[cfg(feature = "oauth2-server")]
fn record_machine_caller_on_span(caller: &MachineCaller) {
    crate::otel::set_attribute("client.id", caller.client_id.clone());
    crate::otel::set_attribute("yauth.auth_method", GRANT_TYPE_CLIENT_CREDENTIALS);
    if !caller.scopes.is_empty() {
        crate::otel::set_attribute("yauth.scopes", caller.scopes.join(" "));
    }
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
                        crate::otel::record_error("user_lookup_failed", &e);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                crate::otel::record_error("session_validation_error", &e);
            }
        }
    }

    // Try Bearer token. Dispatch by claim shape (not by error string) — tokens
    // carrying `client_id` + no `email` go to the client path; everything else
    // goes to the user path. The dispatcher peek is unverified; the selected
    // validator still performs full signature + exp + aud + JTI checks.
    #[cfg(feature = "bearer")]
    #[allow(clippy::collapsible_if)]
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                let is_machine = crate::plugins::bearer::is_machine_token(token);
                #[cfg(feature = "oauth2-server")]
                if is_machine {
                    if let Ok(caller) =
                        crate::plugins::bearer::validate_jwt_as_client(token, &state).await
                    {
                        record_machine_caller_on_span(&caller);
                        req.extensions_mut().insert(caller);
                        return next.run(req).await;
                    }
                }
                if !is_machine
                    && let Ok(auth_user) = crate::plugins::bearer::validate_jwt(token, &state).await
                {
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
    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await
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
            // Machine callers are checked first — their scopes are always a
            // concrete list (never `None`). A caller with no scopes fails any
            // `require_scope` gate, which is the stricter default.
            if let Some(machine) = req.extensions().get::<MachineCaller>() {
                if !machine.scopes.iter().any(|s| s == scope) {
                    return insufficient_scope(scope);
                }
                return next.run(req).await;
            }
            if let Some(user) = req.extensions().get::<AuthUser>() {
                // Legacy semantics: `scopes: None` on a human user means
                // "unrestricted" — preserve that for backwards compatibility.
                if let Some(ref scopes) = user.scopes
                    && !scopes.iter().any(|s| s == scope)
                {
                    return insufficient_scope(scope);
                }
                return next.run(req).await;
            }
            api_err(StatusCode::UNAUTHORIZED, "Authentication required").into_response()
        })
    }
}

fn insufficient_scope(required: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "insufficient_scope",
            "error_description": format!("Required scope: {}", required)
        })),
    )
        .into_response()
}

pub async fn require_admin(State(state): State<YAuthState>, req: Request, next: Next) -> Response {
    if let Some(user) = req.extensions().get::<AuthUser>() {
        if user.role == "admin" {
            return next.run(req).await;
        }
        return api_err(StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    // Machine callers: only admitted when explicitly opted in via AdminConfig
    // AND carrying the `admin` scope. This expands the blast radius of a
    // compromised client_id, so we emit a span event for auditability.
    #[cfg(all(feature = "admin", feature = "oauth2-server"))]
    if let Some(machine) = req.extensions().get::<MachineCaller>()
        && state.admin_config.allow_machine_callers
        && machine.scopes.iter().any(|s| s == "admin")
    {
        crate::otel::add_event(
            "admin_machine_call_allowed",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new(
                "client.id",
                machine.client_id.clone(),
            )],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        return next.run(req).await;
    }
    let _ = state;

    if req.extensions().get::<MachineCaller>().is_some() {
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
