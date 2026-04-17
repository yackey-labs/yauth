//! Helpers for M2M OAuth2 tests: JWT forging and form-encoding.
//!
//! These helpers exist so tests can construct tokens that the production
//! issuance path would never produce (wrong aud, mismatched sub, expired
//! iat, etc.) — the point is to prove the validator rejects them.

#![cfg(feature = "oauth2-server")]

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

pub fn form_urlencoded(pairs: &[(&str, String)]) -> String {
    serde_urlencoded::to_string(pairs).expect("form urlencode")
}

#[derive(Serialize)]
struct CcClaims<'a> {
    sub: &'a str,
    exp: i64,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    client_id: &'a str,
}

pub fn forge_cc_token(
    secret: &str,
    client_id: &str,
    audience: &str,
    scope: Option<&str>,
    exp: i64,
) -> String {
    forge_cc_token_with_sub(secret, client_id, client_id, audience, scope, exp)
}

pub fn forge_cc_token_with_sub(
    secret: &str,
    client_id: &str,
    sub: &str,
    audience: &str,
    scope: Option<&str>,
    exp: i64,
) -> String {
    let claims = CcClaims {
        sub,
        exp,
        iat: chrono::Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        aud: if audience.is_empty() {
            None
        } else {
            Some(audience)
        },
        scope,
        client_id,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("forge cc token")
}

#[derive(Serialize)]
struct UserLikeClaims {
    sub: String,
    email: String,
    role: String,
    exp: i64,
    iat: i64,
    jti: String,
}

pub fn forge_user_like_token() -> String {
    let claims = UserLikeClaims {
        sub: uuid::Uuid::now_v7().to_string(),
        email: "probe@example.com".into(),
        role: "user".into(),
        exp: chrono::Utc::now().timestamp() + 60,
        iat: chrono::Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"irrelevant"),
    )
    .expect("forge user-like token")
}
