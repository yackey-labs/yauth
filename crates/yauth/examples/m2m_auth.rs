//! End-to-end M2M example — mirrors the ghostline dispatcher pattern.
//!
//! Runs a complete yauth server in-process and walks through:
//!
//! 1. Register a `client_credentials` client (client_secret_post).
//! 2. Mint a client_credentials JWT (HS256 + RS256 paths).
//! 3. Call a scope-protected route as a `MachineCaller`.
//! 4. Register a `private_key_jwt` client with an RSA public key.
//! 5. Sign a client_assertion with the matching private key, mint a token,
//!    and exercise the same protected route.
//! 6. Fetch `/.well-known/jwks.json` and validate a yauth-issued RS256
//!    token from an *external* process using only the published JWK —
//!    the cross-trust-domain scenario M2 unlocks.
//! 7. Admin bans a client → token endpoint + auth middleware both reject it.
//!
//! Run:
//!   cargo run --example m2m_auth --features full,memory-backend,asymmetric-jwt

use std::sync::Arc;
use std::time::Duration;

use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::{
    Extension, Json, Router, http::StatusCode, middleware::from_fn, response::IntoResponse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation, decode, encode};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use yauth::backends::memory::InMemoryBackend;
use yauth::config::{AdminConfig, BearerConfig, OAuth2ServerConfig, SigningAlgorithm};
use yauth::middleware::{MachineCaller, auth_middleware, require_scope};
use yauth::prelude::*;

async fn inbox_handler(Extension(caller): Extension<MachineCaller>) -> impl IntoResponse {
    Json(json!({
        "message": "hello machine caller",
        "client_id": caller.client_id,
        "scopes": caller.scopes,
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("=== yauth M2M example (ghostline-style) ===\n");

    // Generate a fresh RSA keypair for the server's JWT signing.
    let server_priv = gen_rsa_private_pem();
    // Public key of the server is published via JWKS — not used directly here.

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
    .with_bearer(BearerConfig {
        jwt_secret: "m2m-example-hs256-secret".into(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        signing_algorithm: SigningAlgorithm::Rs256,
        signing_key_pem: Some(server_priv),
        kid: None,
    })
    .with_oauth2_server(OAuth2ServerConfig {
        issuer: "http://localhost:3000".into(),
        ..Default::default()
    })
    .with_admin()
    .with_admin_config(AdminConfig::default())
    .build()
    .await?;

    let state = auth.state().clone();

    let scoped = Router::new()
        .route("/api/inbox", get(inbox_handler))
        .route_layer(from_fn(require_scope("inbox.write")));
    let protected = scoped.route_layer(from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .merge(auth.router())
        .merge(protected)
        .with_state(state.clone());

    // Bind to 127.0.0.1:0 — the OS picks a free port.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app_clone = app.clone();
    tokio::spawn(async move {
        axum::serve(listener, app_clone).await.unwrap();
    });

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();

    // ── Scenario 1: client_secret_post + client_credentials ─────────────

    println!("→ Register a client_credentials client");
    let reg: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "redirect_uris": ["http://localhost/cb"],
            "grant_types": ["client_credentials"],
            "scope": "inbox.write",
            "token_endpoint_auth_method": "client_secret_post",
        }))
        .send()
        .await?
        .json()
        .await?;
    let cid = reg["client_id"].as_str().unwrap().to_string();
    let csecret = reg["client_secret"].as_str().unwrap().to_string();
    println!("   client_id = {cid}");

    let tok: Value = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &cid),
            ("client_secret", &csecret),
            ("scope", "inbox.write"),
        ])
        .send()
        .await?
        .json()
        .await?;
    let access_token = tok["access_token"].as_str().unwrap().to_string();
    println!("   minted RS256 access_token ({}…)", &access_token[..32]);

    let resp: Value = client
        .get(format!("{base}/api/inbox"))
        .bearer_auth(&access_token)
        .send()
        .await?
        .json()
        .await?;
    println!("   GET /api/inbox → {}", resp);
    assert_eq!(resp["client_id"], cid);

    // ── Scenario 2: private_key_jwt registration + assertion ────────────

    println!("\n→ Register a private_key_jwt client");
    let (client_priv, client_pub) = gen_rsa_keypair();
    let reg: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "redirect_uris": ["http://localhost/cb"],
            "grant_types": ["client_credentials"],
            "scope": "inbox.write",
            "token_endpoint_auth_method": "private_key_jwt",
            "public_key_pem": client_pub,
        }))
        .send()
        .await?
        .json()
        .await?;
    let pkj_cid = reg["client_id"].as_str().unwrap().to_string();
    println!("   client_id = {pkj_cid}");

    // The server-issued aud target is derived from `OAuth2ServerConfig::issuer`,
    // not the bound listener address. Match it exactly.
    let token_audience = "http://localhost:3000/oauth/token".to_string();
    let assertion = sign_assertion(&pkj_cid, &client_priv, &token_audience, 600);
    let tok: Value = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "inbox.write"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", &assertion),
        ])
        .send()
        .await?
        .json()
        .await?;
    let pkj_token = tok["access_token"].as_str().unwrap().to_string();
    println!("   minted token via private_key_jwt");
    let resp: Value = client
        .get(format!("{base}/api/inbox"))
        .bearer_auth(&pkj_token)
        .send()
        .await?
        .json()
        .await?;
    println!("   GET /api/inbox → {}", resp);

    // ── Scenario 3: external resource server validates via JWKS only ────

    println!("\n→ External validator: verify token via JWKS (no shared secret)");
    let jwks: Value = client
        .get(format!("{base}/.well-known/jwks.json"))
        .send()
        .await?
        .json()
        .await?;
    let jwk = &jwks["keys"][0];
    use base64::Engine;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap())?;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap())?;
    let public = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )?;
    use rsa::pkcs1::EncodeRsaPublicKey;
    let der = public.to_pkcs1_der()?;
    let key = jsonwebtoken::DecodingKey::from_rsa_der(der.as_bytes());

    #[derive(Deserialize)]
    struct Claims {
        client_id: String,
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let data = decode::<Claims>(&access_token, &key, &validation)?;
    println!(
        "   external validator accepted yauth token; claims.client_id = {}",
        data.claims.client_id
    );

    // ── Scenario 4: admin ban kill-switch ───────────────────────────────

    println!("\n→ Register admin, ban the client, verify both endpoints reject");
    let admin_client = reqwest::Client::builder().cookie_store(true).build()?;
    admin_client
        .post(format!("{base}/register"))
        .json(&json!({ "email": "admin@example.com", "password": "admin-password-123" }))
        .send()
        .await?;
    admin_client
        .post(format!("{base}/login"))
        .json(&json!({ "email": "admin@example.com", "password": "admin-password-123" }))
        .send()
        .await?;

    let ban = admin_client
        .post(format!("{base}/admin/oauth2/clients/{pkj_cid}/ban"))
        .json(&json!({ "reason": "compromised" }))
        .send()
        .await?;
    println!("   ban status: {}", ban.status());

    let resp = client
        .get(format!("{base}/api/inbox"))
        .bearer_auth(&pkj_token)
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    println!("   outstanding token now rejected (401) — kill switch effective");

    let resp = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "inbox.write"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            (
                "client_assertion",
                &sign_assertion(&pkj_cid, &client_priv, &token_audience, 60),
            ),
        ])
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    println!("   new mint attempt rejected (401)");

    println!("\n✔ all scenarios passed");
    let _ = Arc::clone(&Arc::new(app));
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Assertion<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: String,
}

fn sign_assertion(cid: &str, priv_pem: &str, aud: &str, ttl_secs: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = Assertion {
        iss: cid,
        sub: cid,
        aud,
        exp: now + ttl_secs,
        iat: now,
        jti: uuid::Uuid::now_v7().to_string(),
    };
    let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).expect("load priv");
    encode(&Header::new(Algorithm::RS256), &claims, &key).expect("sign")
}

fn gen_rsa_private_pem() -> String {
    let mut rng = rand::rngs::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("gen RSA");
    private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
}

fn gen_rsa_keypair() -> (String, String) {
    let mut rng = rand::rngs::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("gen RSA");
    let public = rsa::RsaPublicKey::from(&private);
    let priv_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let pub_pem = public.to_public_key_pem(LineEnding::LF).unwrap();
    (priv_pem, pub_pem)
}
