//! Integration tests for the diesel-mysql backend.
//!
//! Requires a MySQL 8.0+ server accessible via the `MYSQL_DATABASE_URL` env var.
//! Default: `mysql://yauth:yauth@127.0.0.1:3307/yauth_test`
//!
//! All tests are parallel-safe: unique emails per test and rate limits disabled.
//!
//! Start MySQL with: `docker compose up -d mysql`

#![cfg(all(
    feature = "diesel-mysql-backend",
    feature = "email-password",
    feature = "memory-backend"
))]

use axum::{Extension, Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

use yauth::backends::diesel_mysql::DieselMysqlBackend;
use yauth::middleware::AuthUser;
use yauth::prelude::*;

fn mysql_url() -> String {
    std::env::var("MYSQL_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://yauth:yauth@127.0.0.1:3307/yauth_test".to_string())
}

/// Build a YAuth instance with DieselMysqlBackend and email-password plugin.
/// Rate limits are disabled so tests can run in parallel without 429 collisions.
async fn build_test_app() -> Router {
    use yauth::repo::{DatabaseBackend, EnabledFeatures};

    let url = mysql_url();
    let backend = DieselMysqlBackend::new(&url).expect("Failed to create MySQL backend");
    backend
        .migrate(&EnabledFeatures::from_compile_flags())
        .await
        .expect("Failed to run MySQL migrations");

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
        rate_limit: None,
        ..Default::default()
    });

    #[cfg(feature = "bearer")]
    {
        builder = builder.with_bearer(yauth::config::BearerConfig {
            jwt_secret: "test-secret-for-mysql-integration".into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(86400),
            audience: None,
        });
    }

    #[cfg(feature = "mfa")]
    {
        builder = builder.with_mfa(yauth::config::MfaConfig::default());
    }

    let auth = builder
        .build()
        .await
        .expect("Failed to build YAuth with DieselMysqlBackend");

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

    let set_cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string());

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body).to_string();

    (status, body_str, set_cookie)
}

/// Use a unique email per test to avoid cross-test contamination in a shared database.
fn unique_email(prefix: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}_{ts}@example.com")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mysql_register_login_session_logout_flow() {
    let app = build_test_app().await;
    let email = unique_email("mysql_flow");

    // 1. Register a new user
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": email,
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
            "email": email,
            "password": "securepassword123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Login failed: {}", body);
    let cookie = set_cookie.expect("Login should return a session cookie");

    let cookie_value = cookie.split(';').next().unwrap();

    // 3. Call GET /session and confirm authenticated
    let (status, body, _) =
        request(&app, "GET", "/api/auth/session", None, Some(cookie_value)).await;
    assert_eq!(status, StatusCode::OK, "Session check failed: {}", body);
    let session_data: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session_data["email"].as_str().unwrap(), &email);

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
async fn mysql_duplicate_registration_returns_409() {
    let app = build_test_app().await;
    let email = unique_email("mysql_dupe");

    // Register first user
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": email,
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
            "email": email,
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
async fn mysql_case_insensitive_email_duplicate() {
    let app = build_test_app().await;
    let email = unique_email("mysql_case");

    // Register with lowercase
    let (status, body, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": email,
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

    // Attempt with uppercase version of the same email
    let (status, _, _) = request(
        &app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": email.to_uppercase(),
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

/// Direct repository-level tests (bypass HTTP) for fine-grained validation.
mod repo_tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use yauth::repo::{DatabaseBackend, EnabledFeatures};

    async fn get_repos() -> yauth::repo::Repositories {
        let url = mysql_url();
        let backend = DieselMysqlBackend::new(&url).expect("Failed to create MySQL backend");
        backend
            .migrate(&EnabledFeatures::from_compile_flags())
            .await
            .expect("Failed to run MySQL migrations");
        backend.repositories()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_and_find_user() {
        let repos = get_repos().await;
        let id = Uuid::now_v7();
        let now = Utc::now().naive_utc();
        let email = unique_email("mysql_repo_create");

        let user = repos
            .users
            .create(yauth::domain::NewUser {
                id,
                email: email.clone(),
                display_name: Some("Test User".to_string()),
                email_verified: false,
                role: "user".to_string(),
                banned: false,
                banned_reason: None,
                banned_until: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("create user");

        assert_eq!(user.id, id);
        assert_eq!(user.email, email);
        assert_eq!(user.display_name.as_deref(), Some("Test User"));

        // find_by_id
        let found = repos.users.find_by_id(id).await.expect("find_by_id");
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.id, id);
        assert_eq!(found.email, email);

        // find_by_email
        let found = repos
            .users
            .find_by_email(&email)
            .await
            .expect("find_by_email");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id);

        // Clean up
        repos.users.delete(id).await.expect("delete user");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_user_returns_conflict() {
        use yauth::repo::RepoError;

        let repos = get_repos().await;
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let now = Utc::now().naive_utc();
        let email = unique_email("mysql_repo_dupe");

        repos
            .users
            .create(yauth::domain::NewUser {
                id: id1,
                email: email.clone(),
                display_name: None,
                email_verified: false,
                role: "user".to_string(),
                banned: false,
                banned_reason: None,
                banned_until: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("create first user");

        let result = repos
            .users
            .create(yauth::domain::NewUser {
                id: id2,
                email: email.clone(),
                display_name: None,
                email_verified: false,
                role: "user".to_string(),
                banned: false,
                banned_reason: None,
                banned_until: None,
                created_at: now,
                updated_at: now,
            })
            .await;

        assert!(
            matches!(result, Err(RepoError::Conflict(_))),
            "Expected Conflict error, got: {:?}",
            result
        );

        // Clean up
        repos.users.delete(id1).await.expect("delete user");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_create_validate_delete() {
        let repos = get_repos().await;
        let user_id = Uuid::now_v7();
        let now = Utc::now().naive_utc();
        let email = unique_email("mysql_repo_session");

        repos
            .users
            .create(yauth::domain::NewUser {
                id: user_id,
                email,
                display_name: None,
                email_verified: false,
                role: "user".to_string(),
                banned: false,
                banned_reason: None,
                banned_until: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("create user for session test");

        let token_hash = "test_session_hash_mysql_12345".to_string();

        let session_id = repos
            .session_ops
            .create_session(
                user_id,
                token_hash.clone(),
                Some("127.0.0.1".to_string()),
                Some("test-agent".to_string()),
                Duration::from_secs(3600),
            )
            .await
            .expect("create session");

        assert!(!session_id.is_nil());

        // Validate the session
        let session = repos
            .session_ops
            .validate_session(&token_hash)
            .await
            .expect("validate session");
        assert!(session.is_some());
        let session = session.unwrap();
        assert_eq!(session.user_id, user_id);

        // Delete the session
        let deleted = repos
            .session_ops
            .delete_session(&token_hash)
            .await
            .expect("delete session");
        assert!(deleted);

        // Validate again — should be None
        let session = repos
            .session_ops
            .validate_session(&token_hash)
            .await
            .expect("validate deleted session");
        assert!(session.is_none());

        // Clean up
        repos.users.delete(user_id).await.expect("delete user");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rate_limit_enforcement() {
        let repos = get_repos().await;
        let key = format!("mysql_test_rate_limit_{}", Uuid::now_v7());

        // The rate limiter increments-then-checks in one call.
        // With limit=3: first 2 calls allowed (count=1,2), 3rd hits limit (count=3 >= 3).
        for i in 0..2 {
            let result = repos
                .rate_limits
                .check_rate_limit(&key, 3, 60)
                .await
                .expect("check rate limit");
            assert!(
                result.allowed,
                "Request {} should be allowed, remaining: {}",
                i + 1,
                result.remaining
            );
        }

        // 3rd request hits the limit (count=3 >= limit=3)
        let result = repos
            .rate_limits
            .check_rate_limit(&key, 3, 60)
            .await
            .expect("check rate limit");
        assert!(
            !result.allowed,
            "3rd request should be rate-limited, remaining: {}",
            result.remaining
        );
        assert_eq!(result.remaining, 0);
        assert!(result.retry_after > 0);
    }
}
