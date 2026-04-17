//! Integration tests for the diesel-libsql backend.
//!
//! Validates core auth flows work end-to-end using an in-memory libSQL database.

#![cfg(all(feature = "diesel-libsql-backend", feature = "email-password"))]

use axum::{Extension, Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

mod helpers;

use yauth::backends::diesel_libsql::DieselLibsqlBackend;
use yauth::middleware::AuthUser;
use yauth::prelude::*;

/// Build a YAuth instance with DieselLibsqlBackend (in-memory) and email-password plugin.
async fn build_test_app() -> Router {
    let manager = diesel_libsql::deadpool::Manager::new("file::memory:");
    let pool = diesel_libsql::deadpool::Pool::builder(manager)
        .max_size(1)
        .build()
        .expect("Failed to create libsql pool");
    helpers::schema::setup_libsql_schema_diesel(&pool).await;
    let backend = DieselLibsqlBackend::from_pool(pool);

    #[allow(unused_mut)]
    let mut builder = YAuthBuilder::new(
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
    });

    #[cfg(feature = "bearer")]
    {
        builder = builder.with_bearer(yauth::config::BearerConfig {
            jwt_secret: "test-secret-for-libsql-backend".to_string(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(86400),
            audience: None,
            #[cfg(feature = "asymmetric-jwt")]
            signing_algorithm: Default::default(),
            #[cfg(feature = "asymmetric-jwt")]
            signing_key_pem: None,
            #[cfg(feature = "asymmetric-jwt")]
            kid: None,
        });
    }
    #[cfg(feature = "mfa")]
    {
        builder = builder.with_mfa(yauth::config::MfaConfig::default());
    }
    #[cfg(feature = "api-key")]
    {
        builder = builder.with_api_key();
    }
    #[cfg(feature = "admin")]
    {
        builder = builder.with_admin();
    }
    #[cfg(feature = "account-lockout")]
    {
        builder = builder.with_account_lockout(yauth::config::AccountLockoutConfig::default());
    }

    let auth = builder
        .build()
        .await
        .expect("Failed to build YAuth with DieselLibsqlBackend");

    let auth_state = auth.state().clone();

    let app_protected = Router::new().route("/api/me", get(me_handler)).layer(
        axum::middleware::from_fn_with_state(
            auth_state.clone(),
            yauth::middleware::auth_middleware,
        ),
    );

    Router::new()
        .merge(app_protected)
        .nest("/api/auth", auth.router())
        .with_state(auth_state)
}

async fn me_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "id": user.id,
            "email": user.email,
        })),
    )
}

/// Helper to make a request and get response parts.
async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> (StatusCode, String, Option<String>) {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }

    let body_str = body.map(|b| serde_json::to_string(&b).unwrap());
    let req = req
        .body(axum::body::Body::from(body_str.unwrap_or_default()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();

    // Extract set-cookie header
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string());

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body).to_string();

    (status, body_str, set_cookie)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_login_session_logout_flow() {
    let app = build_test_app().await;

    // 1. Register a new user
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": "test@example.com",
            "password": "securepassword123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "Register failed: {}", body);

    // 2. Login with the registered user
    let (status, body, set_cookie) = request(
        &app,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": "test@example.com",
            "password": "securepassword123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Login failed: {}", body);
    let cookie = set_cookie.expect("Login should return a session cookie");

    // Extract just the cookie name=value part
    let cookie_value = cookie.split(';').next().unwrap();

    // 3. Call GET /session and confirm authenticated
    let (status, body, _) =
        request(&app, "GET", "/api/auth/session", None, Some(cookie_value)).await;
    assert_eq!(status, StatusCode::OK, "Session check failed: {}", body);
    let session_data: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session_data["email"].as_str().unwrap(), "test@example.com");

    // 4. Logout and confirm session is invalidated
    let (status, _, _) = request(&app, "POST", "/api/auth/logout", None, Some(cookie_value)).await;
    assert_eq!(status, StatusCode::OK, "Logout failed");

    // 5. Confirm session is invalidated after logout
    let (status, _, _) = request(&app, "GET", "/api/auth/session", None, Some(cookie_value)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Session should be invalidated after logout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_registration_returns_409() {
    let app = build_test_app().await;

    // Register first user
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": "dupe@example.com",
            "password": "securepassword123"
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "First register failed: {}",
        body
    );

    // Attempt duplicate registration with same email
    let (status, _, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": "dupe@example.com",
            "password": "anotherpassword456"
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "Duplicate registration should return 409 Conflict"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_insensitive_email_duplicate() {
    let app = build_test_app().await;

    // Register with lowercase
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": "case@example.com",
            "password": "securepassword123"
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "First register failed: {}",
        body
    );

    // Attempt with different case
    let (status, _, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": "CASE@EXAMPLE.COM",
            "password": "anotherpassword456"
        })),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "Case-insensitive duplicate should return 409 Conflict"
    );
}
