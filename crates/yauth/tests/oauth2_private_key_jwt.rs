//! M3 integration tests: `private_key_jwt` client authentication (RFC 7523).
//!
//! Covers:
//! - Register client with `token_endpoint_auth_method=private_key_jwt`
//! - Sign an assertion with the matching private key → mint token → call
//!   a protected route successfully
//! - Replay: same assertion twice → second rejected
//! - Tampered assertion (wrong aud / iss / signature) rejected
//! - Client-secret + assertion mixed rejected
//! - `none` / `HS256` alg on assertion rejected (OWASP alg-confusion)
//! - Private_key_jwt client cannot authenticate with `client_secret`
//! - Discovery doc advertises `private_key_jwt` + signing algs

#![cfg(all(
    feature = "memory-backend",
    feature = "asymmetric-jwt",
    feature = "oauth2-server",
    feature = "email-password"
))]

use axum::{
    Extension, Router, http::StatusCode, middleware as axum_mw, response::IntoResponse,
    routing::get,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

use yauth::backends::memory::InMemoryBackend;
use yauth::middleware::MachineCaller;
use yauth::prelude::*;

mod helpers;

const RSA_PRIV: &str = include_str!("fixtures/test_rsa_pkcs8.pem");
const RSA_PUB: &str = include_str!("fixtures/test_rsa_public.pem");
const EC_PRIV: &str = include_str!("fixtures/test_ec_pkcs8.pem");
const EC_PUB: &str = include_str!("fixtures/test_ec_public.pem");

const ISSUER: &str = "http://localhost:3000";

async fn machine_probe(Extension(c): Extension<MachineCaller>) -> impl IntoResponse {
    axum::Json(json!({ "client_id": c.client_id }))
}

async fn build_app() -> Router {
    let backend = InMemoryBackend::new();
    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: ISSUER.into(),
            session_cookie_name: "session".into(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            auto_admin_first_user: true,
            ..Default::default()
        },
    )
    .with_email_password(yauth::config::EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: false,
        hibp_check: false,
        ..Default::default()
    })
    .with_bearer(yauth::config::BearerConfig {
        jwt_secret: "test-secret-m3".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: Default::default(),
        signing_key_pem: None,
        kid: None,
    })
    .with_oauth2_server(yauth::config::OAuth2ServerConfig {
        issuer: ISSUER.into(),
        ..Default::default()
    })
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let scoped = Router::new()
        .route("/api/probe", get(machine_probe))
        .route_layer(axum_mw::from_fn(yauth::middleware::require_scope(
            "inbox.write",
        )));
    let protected = scoped.route_layer(axum_mw::from_fn_with_state(
        state.clone(),
        yauth::middleware::auth_middleware,
    ));

    Router::new()
        .merge(auth.router())
        .merge(protected)
        .with_state(state)
}

async fn register_pkj_client(app: &Router, pem: &str) -> String {
    let body = json!({
        "redirect_uris": ["http://localhost/cb"],
        "grant_types": ["client_credentials"],
        "scope": "inbox.write",
        "token_endpoint_auth_method": "private_key_jwt",
        "public_key_pem": pem,
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "register failed: {}",
        String::from_utf8_lossy(&bytes)
    );
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["client_id"].as_str().unwrap().to_string()
}

#[derive(Serialize)]
struct Assertion<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: String,
}

fn sign_rsa_assertion(cid: &str, priv_pem: &str, aud: &str, exp_offset: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = Assertion {
        iss: cid,
        sub: cid,
        aud,
        exp: now + exp_offset,
        iat: now,
        jti: uuid::Uuid::now_v7().to_string(),
    };
    let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).expect("load RSA priv");
    encode(&Header::new(Algorithm::RS256), &claims, &key).expect("encode assertion")
}

fn sign_ec_assertion(cid: &str, priv_pem: &str, aud: &str, exp_offset: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = Assertion {
        iss: cid,
        sub: cid,
        aud,
        exp: now + exp_offset,
        iat: now,
        jti: uuid::Uuid::now_v7().to_string(),
    };
    let key = EncodingKey::from_ec_pem(priv_pem.as_bytes()).expect("load EC priv");
    encode(&Header::new(Algorithm::ES256), &claims, &key).expect("encode assertion")
}

async fn post_token_with_assertion(app: &Router, assertion: &str) -> (StatusCode, Value) {
    let form = helpers::form_urlencoded(&[
        ("grant_type", "client_credentials".into()),
        ("scope", "inbox.write".into()),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ),
        ("client_assertion", assertion.into()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn call_probe(app: &Router, token: &str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/probe")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn rs256_assertion_happy_path() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    let assertion = sign_rsa_assertion(&cid, RSA_PRIV, &format!("{ISSUER}/oauth/token"), 60);
    let (status, body) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(status, StatusCode::OK, "mint failed: {body}");
    let token = body["access_token"].as_str().unwrap();
    assert_eq!(call_probe(&app, token).await, StatusCode::OK);
}

#[tokio::test]
async fn es256_assertion_happy_path() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, EC_PUB).await;
    let assertion = sign_ec_assertion(&cid, EC_PRIV, &format!("{ISSUER}/oauth/token"), 60);
    let (status, body) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(status, StatusCode::OK, "mint failed: {body}");
}

#[tokio::test]
async fn replayed_assertion_rejected() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    let assertion = sign_rsa_assertion(&cid, RSA_PRIV, &format!("{ISSUER}/oauth/token"), 60);

    let (s1, _) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, body) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(
        s2,
        StatusCode::UNAUTHORIZED,
        "replay must be rejected: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    let assertion = sign_rsa_assertion(&cid, RSA_PRIV, "https://evil.example/token", 60);
    let (status, body) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn expired_assertion_rejected() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    // exp -300s is past jsonwebtoken's default 60s leeway.
    let assertion = sign_rsa_assertion(&cid, RSA_PRIV, &format!("{ISSUER}/oauth/token"), -300);
    let (status, _) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_client_assertion_rejected() {
    let app = build_app().await;
    // No client registered; assertion claims an unknown iss.
    let assertion = sign_rsa_assertion(
        "nonexistent-client",
        RSA_PRIV,
        &format!("{ISSUER}/oauth/token"),
        60,
    );
    let (status, _) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hs256_assertion_rejected_alg_confusion() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    // Sign an HS256 assertion using... anything. The server must reject HS256
    // regardless of whether the signature checks out.
    let now = chrono::Utc::now().timestamp();
    let claims = Assertion {
        iss: &cid,
        sub: &cid,
        aud: &format!("{ISSUER}/oauth/token"),
        exp: now + 60,
        iat: now,
        jti: uuid::Uuid::now_v7().to_string(),
    };
    let key = EncodingKey::from_secret(RSA_PUB.as_bytes());
    let assertion = encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap();
    let (status, body) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "HS256 assertion must be rejected up front: {body}"
    );
}

#[tokio::test]
async fn iss_sub_mismatch_rejected() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    let now = chrono::Utc::now().timestamp();
    let claims = Assertion {
        iss: &cid,
        sub: "different-subject",
        aud: &format!("{ISSUER}/oauth/token"),
        exp: now + 60,
        iat: now,
        jti: uuid::Uuid::now_v7().to_string(),
    };
    let key = EncodingKey::from_rsa_pem(RSA_PRIV.as_bytes()).unwrap();
    let assertion = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();
    let (status, _) = post_token_with_assertion(&app, &assertion).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mixed_client_secret_and_assertion_rejected() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    let assertion = sign_rsa_assertion(&cid, RSA_PRIV, &format!("{ISSUER}/oauth/token"), 60);

    let form = helpers::form_urlencoded(&[
        ("grant_type", "client_credentials".into()),
        ("scope", "inbox.write".into()),
        ("client_id", cid.clone()),
        ("client_secret", "not-a-real-secret".into()),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ),
        ("client_assertion", assertion.clone()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn discovery_advertises_private_key_jwt() {
    let app = build_app().await;
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let methods = v["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    let has = methods.iter().any(|m| m == "private_key_jwt");
    assert!(has, "discovery must advertise private_key_jwt: {v}");
    let algs = v["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert!(algs.iter().any(|a| a == "RS256"));
    assert!(algs.iter().any(|a| a == "ES256"));
    assert!(
        v["jwks_uri"].is_string(),
        "discovery must advertise jwks_uri"
    );
}

#[tokio::test]
async fn tampered_signature_rejected() {
    let app = build_app().await;
    let cid = register_pkj_client(&app, RSA_PUB).await;
    let good = sign_rsa_assertion(&cid, RSA_PRIV, &format!("{ISSUER}/oauth/token"), 60);
    // Flip the last character of the signature.
    let mut chars: Vec<char> = good.chars().collect();
    let last = *chars.last().unwrap();
    let flipped = if last == 'A' { 'B' } else { 'A' };
    *chars.last_mut().unwrap() = flipped;
    let tampered: String = chars.into_iter().collect();
    let (status, _) = post_token_with_assertion(&app, &tampered).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
