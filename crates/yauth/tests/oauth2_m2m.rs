//! M2M integration tests: validate OAuth 2.0 Client Credentials JWTs end-to-end.
//!
//! Covers:
//! - Happy path: register client → mint token → call protected route → 200
//! - Scope enforcement (`require_scope`) for machine callers
//! - JTI revocation parity with user JWTs
//! - Audience, expiry, deleted-client rejection
//! - Regression: user JWTs continue to validate unchanged
//! - OWASP: malformed payload, sub/client_id mismatch, overlong tokens
//!
//! Runs against the memory backend always; diesel_pg backend is covered in a
//! sibling module so we exercise the same code against a real database.

#![cfg(all(
    feature = "memory-backend",
    feature = "bearer",
    feature = "oauth2-server",
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
use yauth::middleware::{AuthUser, MachineAuthMethod, MachineCaller};
use yauth::prelude::*;

mod helpers;

// ── Handlers used as test probes ───────────────────────────────────────────

async fn machine_only_probe(Extension(caller): Extension<MachineCaller>) -> impl IntoResponse {
    axum::Json(json!({
        "client_id": caller.client_id,
        "scopes": caller.scopes,
        "jti": caller.jti,
        "audience": caller.audience,
        "auth_method": caller.auth_method,
    }))
}

async fn user_only_probe(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    axum::Json(json!({
        "email": user.email,
        "role": user.role,
    }))
}

async fn either_probe(
    user: Option<Extension<AuthUser>>,
    machine: Option<Extension<MachineCaller>>,
) -> impl IntoResponse {
    if let Some(Extension(u)) = user {
        return axum::Json(json!({ "principal": "user", "id": u.id.to_string() }));
    }
    if let Some(Extension(m)) = machine {
        return axum::Json(json!({ "principal": "machine", "client_id": m.client_id }));
    }
    axum::Json(json!({ "principal": "none" }))
}

// ── Test app builder ───────────────────────────────────────────────────────

struct TestApp {
    router: Router,
}

impl TestApp {
    async fn new() -> Self {
        Self::new_with_audience(None, Duration::from_secs(900)).await
    }

    async fn new_with_audience(audience: Option<String>, ttl: Duration) -> Self {
        let backend = InMemoryBackend::new();
        let builder = YAuthBuilder::new(
            backend,
            YAuthConfig {
                base_url: "http://localhost:3000".to_string(),
                session_cookie_name: "session".to_string(),
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
            jwt_secret: "test-secret-m2m-integration".to_string(),
            access_token_ttl: ttl,
            refresh_token_ttl: Duration::from_secs(86400),
            audience,
            #[cfg(feature = "asymmetric-jwt")]
            signing_algorithm: Default::default(),
            #[cfg(feature = "asymmetric-jwt")]
            signing_key_pem: None,
            #[cfg(feature = "asymmetric-jwt")]
            kid: None,
        })
        .with_oauth2_server(yauth::config::OAuth2ServerConfig::default());

        let auth = builder.build().await.expect("build YAuth");
        let auth_state = auth.state().clone();

        let protected_scoped = Router::new()
            .route("/api/inbox", get(machine_only_probe))
            .layer(axum_mw::from_fn(yauth::middleware::require_scope(
                "inbox.write",
            )));

        let protected_open = Router::new()
            .route("/api/either", get(either_probe))
            .route("/api/me", get(user_only_probe));

        let protected = protected_scoped
            .merge(protected_open)
            .layer(axum_mw::from_fn_with_state(
                auth_state.clone(),
                yauth::middleware::auth_middleware,
            ));

        let router = Router::new()
            .merge(auth.router())
            .merge(protected)
            .with_state(auth_state);

        Self { router }
    }

    async fn register_client(&self, scopes: &[&str], grants: &[&str]) -> (String, String) {
        let body = json!({
            "redirect_uris": ["http://localhost/cb"],
            "client_name": "m2m-test",
            "grant_types": grants,
            "scope": scopes.join(" "),
            "token_endpoint_auth_method": "client_secret_post",
        });
        let resp = self
            .router
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
        assert_eq!(resp.status(), StatusCode::CREATED, "register failed");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        (
            v["client_id"].as_str().unwrap().to_string(),
            v["client_secret"].as_str().unwrap().to_string(),
        )
    }

    async fn mint_cc_token(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: Option<&str>,
    ) -> String {
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id.to_string()),
            ("client_secret", client_secret.to_string()),
        ];
        if let Some(s) = scope {
            form.push(("scope", s.to_string()));
        }
        let body = helpers::form_urlencoded(&form);
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "token mint failed: {:?}",
            String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["access_token"].as_str().unwrap().to_string()
    }

    async fn get_with_bearer(&self, path: &str, token: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        (status, v)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn happy_path_machine_caller_reaches_protected_route() {
    let app = TestApp::new().await;
    let (cid, csecret) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    let token = app.mint_cc_token(&cid, &csecret, Some("inbox.write")).await;

    let (status, body) = app.get_with_bearer("/api/inbox", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], Value::String(cid.clone()));
    assert_eq!(body["scopes"], json!(["inbox.write"]));
    assert_eq!(
        body["auth_method"],
        json!(MachineAuthMethod::ClientCredentials)
    );
}

#[tokio::test]
async fn missing_required_scope_returns_403() {
    let app = TestApp::new().await;
    let (cid, csecret) = app
        .register_client(&["other"], &["client_credentials"])
        .await;
    // Token has no scope — require_scope("inbox.write") must reject.
    let token = app.mint_cc_token(&cid, &csecret, None).await;

    let (status, body) = app.get_with_bearer("/api/inbox", &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "insufficient_scope");
}

#[tokio::test]
async fn revoke_jti_via_state_rejects_token() {
    // Build with direct state access so we can reach into revocations repo.
    let backend = InMemoryBackend::new();
    let builder = YAuthBuilder::new(
        backend,
        YAuthConfig {
            base_url: "http://localhost:3000".to_string(),
            session_cookie_name: "session".to_string(),
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
        jwt_secret: "test-secret-m2m-integration".to_string(),
        access_token_ttl: Duration::from_secs(900),
        refresh_token_ttl: Duration::from_secs(86400),
        audience: None,
        #[cfg(feature = "asymmetric-jwt")]
        signing_algorithm: Default::default(),
        #[cfg(feature = "asymmetric-jwt")]
        signing_key_pem: None,
        #[cfg(feature = "asymmetric-jwt")]
        kid: None,
    })
    .with_oauth2_server(yauth::config::OAuth2ServerConfig::default());

    let auth = builder.build().await.expect("build YAuth");
    let state = auth.state().clone();

    let protected_scoped = Router::new()
        .route("/api/inbox", get(machine_only_probe))
        .layer(axum_mw::from_fn(yauth::middleware::require_scope(
            "inbox.write",
        )));

    let protected = protected_scoped.layer(axum_mw::from_fn_with_state(
        state.clone(),
        yauth::middleware::auth_middleware,
    ));

    let router = Router::new()
        .merge(auth.router())
        .merge(protected)
        .with_state(state.clone());

    let app = TestApp { router };
    let (cid, csecret) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    let token = app.mint_cc_token(&cid, &csecret, Some("inbox.write")).await;

    // Works once.
    let (s, body) = app.get_with_bearer("/api/inbox", &token).await;
    assert_eq!(s, StatusCode::OK);
    let jti = body["jti"].as_str().unwrap();

    // Revoke via repos.
    state
        .repos
        .revocations
        .revoke_token(jti, Duration::from_secs(3600))
        .await
        .expect("revoke token");

    // Now rejected.
    let (s, _body) = app.get_with_bearer("/api/inbox", &token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn matching_audience_accepted() {
    let app =
        TestApp::new_with_audience(Some("resource.example".into()), Duration::from_secs(900)).await;
    let (cid, csecret) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    let token = app.mint_cc_token(&cid, &csecret, Some("inbox.write")).await;

    let (status, _) = app.get_with_bearer("/api/inbox", &token).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let app =
        TestApp::new_with_audience(Some("resource.example".into()), Duration::from_secs(900)).await;
    let (cid, _) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    let forged = helpers::forge_cc_token(
        "test-secret-m2m-integration",
        &cid,
        "wrong.audience",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() + 900,
    );
    let (status, _) = app.get_with_bearer("/api/inbox", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_returns_401() {
    let app = TestApp::new().await;
    let (cid, _csecret) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    // jsonwebtoken default leeway is 60s — use -300 to be safely past.
    let forged = helpers::forge_cc_token(
        "test-secret-m2m-integration",
        &cid,
        "irrelevant",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() - 300,
    );
    let (status, _body) = app.get_with_bearer("/api/inbox", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_jwt_regression_still_works() {
    // The M1 dispatcher change must not break the human-user path.
    let app = TestApp::new().await;
    // Register a user, log them in via email/password, get a bearer token.
    let register = json!({ "email": "alice@example.com", "password": "test-password-123" });
    let resp = app
        .router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(register.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "register failed: {}",
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
    );

    let login = json!({ "email": "alice@example.com", "password": "test-password-123" });
    let resp = app
        .router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(login.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token login failed");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let access = v["access_token"].as_str().unwrap().to_string();

    // Hit the user-only probe.
    let (status, body) = app.get_with_bearer("/api/me", &access).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "alice@example.com");
}

#[tokio::test]
async fn either_probe_distinguishes_principals() {
    let app = TestApp::new().await;
    let (cid, csecret) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    let token = app.mint_cc_token(&cid, &csecret, Some("inbox.write")).await;
    let (status, body) = app.get_with_bearer("/api/either", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["principal"], "machine");
    assert_eq!(body["client_id"], cid);
}

// ── OWASP / defensive ────────────────────────────────────────────────────

#[tokio::test]
async fn malformed_token_returns_401() {
    let app = TestApp::new().await;
    let cases = [
        "not.a.jwt",
        "garbage",
        "aaa.bbb.ccc",
        &"A".repeat(8192), // overlong
        "",
    ];
    for bad in cases {
        let (status, _) = app.get_with_bearer("/api/inbox", bad).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "malformed token {bad:?} should 401"
        );
    }
}

#[tokio::test]
async fn sub_client_id_mismatch_rejected() {
    let app = TestApp::new().await;
    // Forge a token whose sub != client_id — both present so dispatcher routes
    // to client path, then the extra check must reject.
    let forged = helpers::forge_cc_token_with_sub(
        "test-secret-m2m-integration",
        "some-client-id",
        "different-sub",
        "irrelevant",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() + 900,
    );
    let (status, _) = app.get_with_bearer("/api/inbox", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deleted_client_cannot_replay_old_token() {
    // Mint a token, then simulate the client being removed before the token
    // expires. Since the in-memory backend has no delete method exposed on the
    // repo trait, we exercise the "client_id not found" path by forging a
    // token for a never-registered client_id.
    let app = TestApp::new().await;
    let forged = helpers::forge_cc_token(
        "test-secret-m2m-integration",
        "never-registered",
        "irrelevant",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() + 900,
    );
    let (status, _) = app.get_with_bearer("/api/inbox", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_client_id_claim_rejected() {
    // Dispatcher requires `client_id` present + no `email` to route to
    // machine path. A token with empty client_id string still has the key
    // present — must be rejected by the mismatch check.
    let app = TestApp::new().await;
    let forged = helpers::forge_cc_token_with_sub(
        "test-secret-m2m-integration",
        "",
        "",
        "irrelevant",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() + 900,
    );
    let (status, _) = app.get_with_bearer("/api/inbox", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_signature_rejected() {
    let app = TestApp::new().await;
    let (cid, _csecret) = app
        .register_client(&["inbox.write"], &["client_credentials"])
        .await;
    let forged = helpers::forge_cc_token(
        "wrong-signing-secret",
        &cid,
        "irrelevant",
        Some("inbox.write"),
        chrono::Utc::now().timestamp() + 900,
    );
    let (status, _) = app.get_with_bearer("/api/inbox", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn is_machine_token_peek_is_signature_independent() {
    use yauth::plugins::bearer::is_machine_token;

    let machine = helpers::forge_cc_token(
        "any-key",
        "cid",
        "aud",
        Some("s"),
        chrono::Utc::now().timestamp() + 60,
    );
    assert!(is_machine_token(&machine));

    // User-shaped claims (email present) should NOT peek as machine.
    let user_shape = helpers::forge_user_like_token();
    assert!(!is_machine_token(&user_shape));

    // Malformed tokens do not peek as machine (they fall through to the user
    // path and 401 there, matching pre-M1 behavior).
    for bad in ["", "abc", "a.b", "a.b.c.d"] {
        assert!(!is_machine_token(bad), "{bad:?} should not peek as machine");
    }
}
