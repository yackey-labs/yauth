//! OpenID Connect (OIDC) plugin — makes yauth a full OIDC Provider.
//!
//! **When to use:** Enable this when you need yauth to act as an identity provider
//! that issues `id_token`s, publishes OIDC discovery metadata, and exposes a
//! `/userinfo` endpoint. Required for OIDC-compliant SSO flows.
//!
//! **Requires:** `bearer` + `oauth2-server` features (automatically enabled by `oidc` flag).

use axum::{Extension, Json, Router, extract::State, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::config::OidcConfig;
use crate::middleware::AuthUser;
use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub struct OidcPlugin {
    _config: OidcConfig,
}

impl OidcPlugin {
    pub fn new(config: OidcConfig) -> Self {
        Self { _config: config }
    }
}

impl YAuthPlugin for OidcPlugin {
    fn name(&self) -> &'static str {
        "oidc"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(
            Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(openid_configuration),
                )
                .route("/.well-known/jwks.json", get(jwks_endpoint)),
        )
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/userinfo", get(userinfo).post(userinfo)))
    }
}

// ---------------------------------------------------------------------------
// GET /.well-known/openid-configuration — OIDC Discovery
// ---------------------------------------------------------------------------

async fn openid_configuration(State(state): State<YAuthState>) -> Json<serde_json::Value> {
    let oidc = &state.oidc_config;
    let issuer = &oidc.issuer;

    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", issuer),
        "token_endpoint": format!("{}/oauth/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
        "registration_endpoint": format!("{}/oauth/register", issuer),
        "introspection_endpoint": format!("{}/oauth/introspect", issuer),
        "revocation_endpoint": format!("{}/oauth/revoke", issuer),
        "device_authorization_endpoint": format!("{}/oauth/device/code", issuer),
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": oidc.claims_supported,
        "code_challenge_methods_supported": ["S256"],
    }))
}

// ---------------------------------------------------------------------------
// GET /.well-known/jwks.json — JSON Web Key Set
// ---------------------------------------------------------------------------

async fn jwks_endpoint(State(state): State<YAuthState>) -> Json<serde_json::Value> {
    let jwks = crate::auth::jwks::generate_jwks(&state.bearer_config);
    Json(serde_json::to_value(jwks).unwrap_or_else(|_| serde_json::json!({"keys": []})))
}

// ---------------------------------------------------------------------------
// GET/POST /userinfo — OIDC UserInfo endpoint
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct UserInfoResponse {
    sub: String,
    email: String,
    email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

async fn userinfo(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Json(UserInfoResponse {
        sub: user.id.to_string(),
        email: user.email,
        email_verified: user.email_verified,
        name: user.display_name,
    })
}

/// Generate an OIDC id_token for the given user. Called from the oauth2_server
/// token endpoint when the `openid` scope is present.
pub fn generate_id_token(
    user: &yauth_entity::users::Model,
    state: &YAuthState,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<String, String> {
    let oidc = &state.oidc_config;
    let bearer = &state.bearer_config;

    let now = chrono::Utc::now();
    let exp = (now + oidc.id_token_ttl).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let mut claims = serde_json::json!({
        "iss": oidc.issuer,
        "sub": user.id.to_string(),
        "aud": client_id,
        "exp": exp,
        "iat": iat,
        "email": user.email,
        "email_verified": user.email_verified,
        "name": user.display_name,
    });
    // OIDC Core §3.1.3.7: nonce MUST NOT be included when absent from the request
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string());
    }

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(bearer.jwt_secret.as_bytes());

    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| format!("Failed to encode id_token: {}", e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn userinfo_response_serializes() {
        let resp = super::UserInfoResponse {
            sub: "test-id".into(),
            email: "test@example.com".into(),
            email_verified: true,
            name: Some("Test User".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("Test User"));
    }
}
