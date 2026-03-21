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

/// Encode an OIDC id_token JWT from individual claim values.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_id_token_jwt(
    issuer: &str,
    sub: &str,
    client_id: &str,
    email: &str,
    email_verified: bool,
    display_name: Option<&str>,
    nonce: Option<&str>,
    id_token_ttl: std::time::Duration,
    jwt_secret: &str,
) -> Result<String, String> {
    let now = chrono::Utc::now();
    let exp = (now + id_token_ttl).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "exp": exp,
        "iat": iat,
        "email": email,
        "email_verified": email_verified,
        "name": display_name,
    });
    // OIDC Core §3.1.3.7: nonce MUST NOT be included when absent from the request
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string());
    }

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes());

    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| format!("Failed to encode id_token: {}", e))
}

/// Generate an OIDC id_token from individual user fields.
pub fn generate_id_token_from_fields(
    user_id: &uuid::Uuid,
    email: &str,
    email_verified: bool,
    display_name: Option<&str>,
    state: &YAuthState,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<String, String> {
    encode_id_token_jwt(
        &state.oidc_config.issuer,
        &user_id.to_string(),
        client_id,
        email,
        email_verified,
        display_name,
        nonce,
        state.oidc_config.id_token_ttl,
        &state.bearer_config.jwt_secret,
    )
}

#[cfg(test)]
mod tests {
    use super::UserInfoResponse;

    // -----------------------------------------------------------------------
    // UserInfoResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn userinfo_response_serializes() {
        let resp = UserInfoResponse {
            sub: "test-id".into(),
            email: "test@example.com".into(),
            email_verified: true,
            name: Some("Test User".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("Test User"));
    }

    #[test]
    fn userinfo_response_omits_name_when_none() {
        let resp = UserInfoResponse {
            sub: "user-42".into(),
            email: "noname@example.com".into(),
            email_verified: false,
            name: None,
        };
        let val: serde_json::Value = serde_json::to_value(&resp).unwrap();
        let obj = val.as_object().expect("should be a JSON object");
        assert!(
            !obj.contains_key("name"),
            "name key should be omitted when None, got: {:?}",
            obj
        );
        assert_eq!(val["sub"], "user-42");
        assert_eq!(val["email"], "noname@example.com");
        assert_eq!(val["email_verified"], false);
    }

    #[test]
    fn userinfo_response_includes_all_fields_when_name_present() {
        let resp = UserInfoResponse {
            sub: "abc-123".into(),
            email: "full@example.com".into(),
            email_verified: true,
            name: Some("Full Name".into()),
        };
        let val: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(val["sub"], "abc-123");
        assert_eq!(val["email"], "full@example.com");
        assert_eq!(val["email_verified"], true);
        assert_eq!(val["name"], "Full Name");
    }

    // -----------------------------------------------------------------------
    // generate_id_token / encode_id_token_jwt tests
    //
    // These test the extracted `encode_id_token_jwt` function directly,
    // which is the same code path used by `generate_id_token`.
    // -----------------------------------------------------------------------

    fn encode_id_token(
        issuer: &str,
        sub: &str,
        client_id: &str,
        email: &str,
        email_verified: bool,
        display_name: Option<&str>,
        nonce: Option<&str>,
        ttl_secs: i64,
        jwt_secret: &str,
    ) -> String {
        super::encode_id_token_jwt(
            issuer,
            sub,
            client_id,
            email,
            email_verified,
            display_name,
            nonce,
            std::time::Duration::from_secs(ttl_secs as u64),
            jwt_secret,
        )
        .expect("JWT encoding should not fail")
    }

    /// Decode an id_token using the same secret, returning the claims as a JSON value.
    fn decode_claims(token: &str, jwt_secret: &str) -> serde_json::Value {
        let key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_aud = false; // we check aud manually
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
            .expect("JWT decoding should not fail");
        data.claims
    }

    #[test]
    fn id_token_with_nonce_has_correct_claims() {
        let secret = "test-secret-key-for-unit-tests";
        let issuer = "https://auth.example.com";
        let sub = "550e8400-e29b-41d4-a716-446655440000";
        let client_id = "my-client";
        let email = "user@example.com";
        let nonce_val = "random-nonce-abc123";

        let token = encode_id_token(
            issuer,
            sub,
            client_id,
            email,
            true,
            Some("Test User"),
            Some(nonce_val),
            3600,
            secret,
        );

        let claims = decode_claims(&token, secret);

        assert_eq!(claims["iss"], issuer);
        assert_eq!(claims["sub"], sub);
        assert_eq!(claims["aud"], client_id);
        assert_eq!(claims["email"], email);
        assert_eq!(claims["email_verified"], true);
        assert_eq!(claims["name"], "Test User");
        assert_eq!(claims["nonce"], nonce_val);
        assert!(claims["exp"].is_number(), "exp should be a number");
        assert!(claims["iat"].is_number(), "iat should be a number");
    }

    #[test]
    fn id_token_without_nonce_omits_nonce_claim() {
        let secret = "another-test-secret";
        let token = encode_id_token(
            "https://auth.example.com",
            "user-id-1",
            "client-1",
            "no-nonce@example.com",
            false,
            None,
            None, // no nonce
            3600,
            secret,
        );

        let claims = decode_claims(&token, secret);

        assert!(
            claims.get("nonce").is_none(),
            "nonce claim must NOT be present when nonce is None, got: {:?}",
            claims
        );
        // Other claims should still be present
        assert_eq!(claims["sub"], "user-id-1");
        assert_eq!(claims["email"], "no-nonce@example.com");
        assert_eq!(claims["email_verified"], false);
    }

    #[test]
    fn id_token_exp_is_in_the_future() {
        let secret = "exp-test-secret";
        let ttl_secs = 7200;

        let token = encode_id_token(
            "https://auth.example.com",
            "user-exp",
            "client-exp",
            "exp@example.com",
            true,
            None,
            None,
            ttl_secs,
            secret,
        );

        let claims = decode_claims(&token, secret);

        let exp = claims["exp"].as_i64().expect("exp should be an integer");
        let iat = claims["iat"].as_i64().expect("iat should be an integer");
        let now = chrono::Utc::now().timestamp();

        assert!(exp > now, "exp ({}) should be after now ({})", exp, now);
        assert!(
            exp >= iat + ttl_secs,
            "exp ({}) should be at least iat ({}) + ttl ({})",
            exp,
            iat,
            ttl_secs
        );
        // Verify exp is not absurdly far in the future (within ttl + 5s tolerance)
        assert!(
            exp <= iat + ttl_secs + 5,
            "exp ({}) should be within 5s of iat ({}) + ttl ({})",
            exp,
            iat,
            ttl_secs
        );
    }

    #[test]
    fn id_token_iss_matches_configured_issuer() {
        let secret = "iss-test-secret";
        let issuer = "https://my-custom-issuer.example.org";

        let token = encode_id_token(
            issuer,
            "user-iss",
            "client-iss",
            "iss@example.com",
            true,
            None,
            None,
            3600,
            secret,
        );

        let claims = decode_claims(&token, secret);
        assert_eq!(
            claims["iss"].as_str().unwrap(),
            issuer,
            "iss claim must match the configured issuer"
        );
    }
}
