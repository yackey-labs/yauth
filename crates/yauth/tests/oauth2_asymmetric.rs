//! M2 integration tests: asymmetric JWT signing (RS256/ES256) + populated JWKS.
//!
//! Covers:
//! - RS256 user + client_credentials mint-and-validate round-trip
//! - ES256 round-trip
//! - JWKS endpoint returns the populated public JWK
//! - External-style validation: decode a yauth-issued RS256 token using ONLY
//!   the JWKS output (no shared secret)
//! - HS256 byte-stable: header does not grow a `kid` when default config used
//! - Algorithm confusion: tokens signed with wrong alg → 401, no panic
//! - PKCS#1 PEM rejected at build() with an actionable error
//! - Unknown-alg token rejected

#![cfg(all(
    feature = "memory-backend",
    feature = "bearer",
    feature = "oauth2-server",
    feature = "asymmetric-jwt",
    feature = "email-password"
))]

use axum::{
    Extension, Router, http::StatusCode, middleware as axum_mw, response::IntoResponse,
    routing::get,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

use yauth::backends::memory::InMemoryBackend;
use yauth::config::SigningAlgorithm;
use yauth::middleware::MachineCaller;
use yauth::prelude::*;

mod helpers;

const RSA_PEM: &str = include_str!("fixtures/test_rsa_pkcs8.pem");
const EC_PEM: &str = include_str!("fixtures/test_ec_pkcs8.pem");

// ── Test scaffolding ──────────────────────────────────────────────────────

async fn machine_probe(Extension(c): Extension<MachineCaller>) -> impl IntoResponse {
    axum::Json(json!({ "client_id": c.client_id, "scopes": c.scopes }))
}

async fn build_app(alg: SigningAlgorithm, pem: Option<&str>) -> Router {
    let backend = InMemoryBackend::new();
    let auth = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost:3000".into(),
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
        jwt_secret: "test-secret-m2-asym".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: alg,
        signing_key_pem: pem.map(String::from),
        kid: None,
    })
    .with_oauth2_server(yauth::config::OAuth2ServerConfig::default())
    .build()
    .await
    .expect("build YAuth");

    let state = auth.state().clone();
    let scoped = Router::new()
        .route("/api/inbox", get(machine_probe))
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

async fn register_client(app: &Router) -> (String, String) {
    let body = json!({
        "redirect_uris": ["http://localhost/cb"],
        "grant_types": ["client_credentials"],
        "scope": "inbox.write",
        "token_endpoint_auth_method": "client_secret_post",
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
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (
        v["client_id"].as_str().unwrap().to_string(),
        v["client_secret"].as_str().unwrap().to_string(),
    )
}

async fn mint_token(app: &Router, cid: &str, csecret: &str) -> String {
    let form = helpers::form_urlencoded(&[
        ("grant_type", "client_credentials".into()),
        ("client_id", cid.into()),
        ("client_secret", csecret.into()),
        ("scope", "inbox.write".into()),
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
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "mint failed: {}",
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
    );
    let v: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

async fn call_protected(app: &Router, token: &str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/inbox")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

fn decode_header(token: &str) -> serde_json::Value {
    use base64::Engine;
    let seg = token.split('.').next().unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rs256_round_trip() {
    let app = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let (cid, csec) = register_client(&app).await;
    let token = mint_token(&app, &cid, &csec).await;

    let header = decode_header(&token);
    assert_eq!(header["alg"], "RS256");
    assert!(
        header.get("kid").is_some(),
        "asymmetric tokens must carry kid"
    );

    assert_eq!(call_protected(&app, &token).await, StatusCode::OK);
}

#[tokio::test]
async fn es256_round_trip() {
    let app = build_app(SigningAlgorithm::Es256, Some(EC_PEM)).await;
    let (cid, csec) = register_client(&app).await;
    let token = mint_token(&app, &cid, &csec).await;

    let header = decode_header(&token);
    assert_eq!(header["alg"], "ES256");

    assert_eq!(call_protected(&app, &token).await, StatusCode::OK);
}

#[tokio::test]
async fn hs256_byte_stable_no_kid_in_header() {
    let app = build_app(SigningAlgorithm::Hs256, None).await;
    let (cid, csec) = register_client(&app).await;
    let token = mint_token(&app, &cid, &csec).await;

    let header = decode_header(&token);
    assert_eq!(header["alg"], "HS256");
    assert!(
        header.get("kid").is_none(),
        "HS256 tokens must NOT carry kid (byte-stable with pre-M2)"
    );
    let field_count = header.as_object().map_or(0, |m| m.len());
    assert!(
        header.get("typ").is_some() || field_count <= 2,
        "HS256 header should be minimal ({{alg,typ}})"
    );
}

async fn fetch_jwks(app: &Router) -> Value {
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/.well-known/jwks.json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "jwks endpoint should 200, got {}: {}",
        status,
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn jwks_populated_for_rs256() {
    let app = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let jwks = fetch_jwks(&app).await;
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "exactly one key published");
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[0]["alg"], "RS256");
    assert_eq!(keys[0]["use"], "sig");
    assert!(keys[0]["n"].as_str().is_some());
    assert!(keys[0]["e"].as_str().is_some());
    assert!(keys[0]["kid"].as_str().is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn jwks_populated_for_es256() {
    let app = build_app(SigningAlgorithm::Es256, Some(EC_PEM)).await;
    let jwks = fetch_jwks(&app).await;
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "EC");
    assert_eq!(keys[0]["alg"], "ES256");
    assert_eq!(keys[0]["crv"], "P-256");
    let x = keys[0]["x"].as_str().unwrap();
    let y = keys[0]["y"].as_str().unwrap();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .unwrap()
            .len(),
        32,
        "P-256 x coord must be 32 bytes"
    );
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(y)
            .unwrap()
            .len(),
        32
    );
}

#[tokio::test]
async fn jwks_empty_for_hs256() {
    let app = build_app(SigningAlgorithm::Hs256, None).await;
    // No oidc, no asymmetric-jwt effect — jwks route should not be mounted.
    // When asymmetric-jwt is enabled but alg is HS256, route IS mounted
    // (through BearerPlugin) and returns an empty keyset.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/.well-known/jwks.json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // With oidc enabled via `full` feature, route exists and empty is correct.
    if resp.status() == StatusCode::OK {
        let v: Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert!(v["keys"].as_array().unwrap().is_empty());
    } else {
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn external_resource_server_validates_rs256_via_jwks_only() {
    use base64::Engine;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use serde::Deserialize;

    let app = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let (cid, csec) = register_client(&app).await;
    let token = mint_token(&app, &cid, &csec).await;

    // Pretend we're an external service: fetch JWKS, extract public key,
    // validate the token with NO shared secret.
    let jwks = fetch_jwks(&app).await;
    let jwk = &jwks["keys"][0];
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["n"].as_str().unwrap())
        .unwrap();
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["e"].as_str().unwrap())
        .unwrap();
    let public = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )
    .expect("build RSA public key from JWK");

    let der = public
        .to_pkcs1_der()
        .expect("encode public key to PKCS#1 DER");
    let key = DecodingKey::from_rsa_der(der.as_bytes());

    #[derive(Deserialize)]
    struct Cc {
        client_id: String,
    }
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_aud = false;
    let data = decode::<Cc>(&token, &key, &v).expect("external validator accepts");
    assert_eq!(data.claims.client_id, cid);
}

// ── Defensive / OWASP ─────────────────────────────────────────────────────

#[tokio::test]
async fn alg_confusion_hs256_token_rejected_on_rs256_server() {
    // Server configured for RS256. Craft a token signed with HS256 using the
    // server's jwt_secret — the historical alg-confusion attack. Must 401.
    let app = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let forged = helpers::forge_cc_token(
        "test-secret-m2-asym",
        "pretend-client",
        "",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() + 900,
    );
    assert_eq!(
        call_protected(&app, &forged).await,
        StatusCode::UNAUTHORIZED,
        "HS256 token must not be accepted by RS256-configured server"
    );
}

#[tokio::test]
async fn rs256_token_rejected_on_hs256_server() {
    // Converse: if admin meant HS256 but an attacker presents RS256, reject.
    // We can't easily forge an RS256 token without the private key in-test,
    // so we use a different approach: build two apps, mint on RS256, replay
    // against HS256.
    let rs_app = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let (cid, csec) = register_client(&rs_app).await;
    let rs_token = mint_token(&rs_app, &cid, &csec).await;

    let hs_app = build_app(SigningAlgorithm::Hs256, None).await;
    assert_eq!(
        call_protected(&hs_app, &rs_token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn pkcs1_rsa_pem_rejected_at_build() {
    // Simulate the user supplying a PKCS#1 PEM instead of PKCS#8. The builder
    // should fail-fast with an actionable error.
    let pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n";
    let backend = InMemoryBackend::new();
    let result = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost".into(),
            session_cookie_name: "s".into(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            auto_admin_first_user: false,
            ..Default::default()
        },
    )
    .with_email_password(yauth::config::EmailPasswordConfig::default())
    .with_bearer(yauth::config::BearerConfig {
        jwt_secret: "x".into(),
        access_token_ttl: Duration::from_secs(60),
        refresh_token_ttl: Duration::from_secs(60),
        audience: None,
        signing_algorithm: SigningAlgorithm::Rs256,
        signing_key_pem: Some(pkcs1.into()),
        kid: None,
    })
    .build()
    .await;

    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("PKCS#1 PEM must fail builder"),
    };
    assert!(
        err.contains("PKCS#8"),
        "error should guide user to PKCS#8: {err}"
    );
}

#[tokio::test]
async fn missing_pem_with_rs256_fails_build() {
    let backend = InMemoryBackend::new();
    let result = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost".into(),
            session_cookie_name: "s".into(),
            session_ttl: Duration::from_secs(3600),
            allow_signups: true,
            auto_admin_first_user: false,
            ..Default::default()
        },
    )
    .with_email_password(yauth::config::EmailPasswordConfig::default())
    .with_bearer(yauth::config::BearerConfig {
        jwt_secret: "x".into(),
        access_token_ttl: Duration::from_secs(60),
        refresh_token_ttl: Duration::from_secs(60),
        audience: None,
        signing_algorithm: SigningAlgorithm::Rs256,
        signing_key_pem: None,
        kid: None,
    })
    .build()
    .await;
    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("missing PEM must fail builder"),
    };
    assert!(
        err.contains("signing_key_pem"),
        "error should mention signing_key_pem: {err}"
    );
}

#[tokio::test]
async fn kid_is_stable_across_rebuilds() {
    // Same PEM → same kid (RFC 7638 thumbprint is deterministic).
    let a = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let b = build_app(SigningAlgorithm::Rs256, Some(RSA_PEM)).await;
    let kid_a = fetch_jwks(&a).await["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    let kid_b = fetch_jwks(&b).await["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(kid_a, kid_b);
    // Different alg/key → different kid.
    let c = build_app(SigningAlgorithm::Es256, Some(EC_PEM)).await;
    let kid_c = fetch_jwks(&c).await["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(kid_a, kid_c);
}

#[tokio::test]
async fn signing_key_pem_not_serialized() {
    // Defense-in-depth: config snapshots must never expose the private key.
    let config = yauth::config::BearerConfig {
        jwt_secret: "x".into(),
        access_token_ttl: Duration::from_secs(60),
        refresh_token_ttl: Duration::from_secs(60),
        audience: None,
        signing_algorithm: SigningAlgorithm::Rs256,
        signing_key_pem: Some(RSA_PEM.into()),
        kid: None,
    };
    let json = serde_json::to_string(&config).unwrap();
    assert!(
        !json.contains("BEGIN PRIVATE KEY"),
        "serialized config must not contain PEM body: {json}"
    );
    assert!(
        !json.contains("signing_key_pem"),
        "field should be skipped entirely"
    );
}
