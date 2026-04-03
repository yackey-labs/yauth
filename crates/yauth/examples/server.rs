//! # YAuth Example Server
//!
//! A complete Axum application demonstrating how to integrate the yauth
//! authentication library with all plugins enabled.
//!
//! ## Quick Start
//!
//! ```bash
//! # Start PostgreSQL (e.g. via Docker)
//! docker run -d --name yauth-pg -e POSTGRES_USER=yauth -e POSTGRES_PASSWORD=yauth \
//!     -e POSTGRES_DB=yauth -p 5432:5432 postgres:16
//!
//! # Run the server
//! DATABASE_URL=postgres://yauth:yauth@127.0.0.1:5432/yauth \
//!     cargo run --example server --features full
//! ```
//!
//! ## Environment Variables
//!
//! | Variable              | Default                     | Description                         |
//! |-----------------------|-----------------------------|-------------------------------------|
//! | `YAUTH_BACKEND`       | `diesel`                    | Backend: `diesel` or `memory`        |
//! | `DATABASE_URL`        | *(required for diesel)*     | PostgreSQL connection string         |
//! | `PORT`                | `3000`                      | Server listen port                   |
//! | `BASE_URL`            | `http://localhost:3000`     | Public-facing base URL               |
//! | `SESSION_COOKIE_NAME` | `session`                   | Name of the session cookie           |
//! | `JWT_SECRET`          | `dev-secret-change-me`      | HMAC secret for bearer JWTs          |
//! | `SMTP_HOST`           | *(none)*                    | SMTP host (enables email sending)    |
//! | `SMTP_PORT`           | `587`                       | SMTP port                            |
//! | `SMTP_FROM`           | `noreply@localhost`         | Sender address for outbound emails   |
//! | `PASSKEY_RP_ID`       | `localhost`                 | WebAuthn Relying Party ID            |
//! | `PASSKEY_RP_ORIGIN`   | `http://localhost:3000`     | WebAuthn Relying Party origin        |
//! | `PASSKEY_RP_NAME`     | `YAuth Dev`                 | WebAuthn Relying Party display name  |
//! | `MFA_ISSUER`          | `YAuth Dev`                 | TOTP issuer shown in authenticator   |
//! | `ALLOW_SIGNUPS`       | `true`                      | Set to `false` to disable all signups|
//!
//! ## Endpoints
//!
//! - `GET  /api/health`       — unauthenticated health check
//! - `GET  /api/me`           — returns the authenticated user (requires auth)
//! - `/api/auth/...`          — all yauth auth routes (register, login, session, etc.)

use axum::{Extension, Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

use yauth::middleware::AuthUser;
use yauth::prelude::*;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // -----------------------------------------------------------------------
    // 1. Initialize logging
    // -----------------------------------------------------------------------
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // -----------------------------------------------------------------------
    // 2. Read configuration from environment variables
    // -----------------------------------------------------------------------
    let yauth_backend = env::var("YAUTH_BACKEND").unwrap_or_else(|_| "diesel".into());
    let database_url = if yauth_backend == "memory" {
        None
    } else {
        Some(
            env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set (e.g. postgres://user:pass@host/db)"),
        )
    };
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{}", port));
    let session_cookie_name = env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "session".into());
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());

    // SMTP — if SMTP_HOST is set, email sending is enabled
    let smtp_config = env::var("SMTP_HOST").ok().map(|host| {
        let port: u16 = env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);
        let from = env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@localhost".into());
        yauth::config::SmtpConfig { host, port, from }
    });

    // Passkey / WebAuthn
    let passkey_rp_id = env::var("PASSKEY_RP_ID").unwrap_or_else(|_| "localhost".into());
    let passkey_rp_origin = env::var("PASSKEY_RP_ORIGIN").unwrap_or_else(|_| base_url.clone());
    let passkey_rp_name = env::var("PASSKEY_RP_NAME").unwrap_or_else(|_| "YAuth Dev".into());

    // MFA / TOTP
    let mfa_issuer = env::var("MFA_ISSUER").unwrap_or_else(|_| "YAuth Dev".into());

    // Global signup toggle
    let allow_signups = env::var("ALLOW_SIGNUPS")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    if smtp_config.is_none() {
        log::warn!(
            "SMTP_HOST not set — email sending is disabled. \
             Set SMTP_HOST, SMTP_PORT, and SMTP_FROM to enable."
        );
    }

    // -----------------------------------------------------------------------
    // 3. Create the database backend
    // -----------------------------------------------------------------------
    let backend: Box<dyn yauth::repo::DatabaseBackend> = if yauth_backend == "memory" {
        log::info!("Using in-memory backend (no database required)");
        Box::new(yauth::backends::memory::InMemoryBackend::new())
    } else {
        log::info!("Connecting to database...");
        let url = database_url.as_ref().unwrap();
        Box::new(
            yauth::backends::diesel::DieselBackend::new(url)
                .expect("Failed to create database backend"),
        )
    };

    // -----------------------------------------------------------------------
    // 4. Build the YAuth instance with all plugins enabled
    // -----------------------------------------------------------------------
    #[allow(unused_mut)]
    let mut builder = YAuthBuilder::new(
        backend,
        yauth::config::YAuthConfig {
            base_url: base_url.clone(),
            session_cookie_name,
            session_ttl: Duration::from_secs(7 * 24 * 3600), // 1 week
            cookie_domain: env::var("COOKIE_DOMAIN").ok().into(),
            secure_cookies: !base_url.starts_with("http://localhost"),
            trusted_origins: vec![base_url.clone()],
            smtp: smtp_config,
            auto_admin_first_user: true,
            allow_signups,
            ..Default::default()
        },
    )
    // Email + password registration and login
    .with_email_password(yauth::config::EmailPasswordConfig {
        min_password_length: 8,
        require_email_verification: true,
        hibp_check: true, // Check passwords against Have I Been Pwned
        ..Default::default()
    })
    // WebAuthn passkey authentication
    .with_passkey(yauth::config::PasskeyConfig {
        rp_id: passkey_rp_id,
        rp_origin: passkey_rp_origin,
        rp_name: passkey_rp_name,
    })
    // TOTP-based multi-factor authentication
    .with_mfa(yauth::config::MfaConfig {
        issuer: mfa_issuer,
        backup_code_count: 10,
    })
    // JWT bearer tokens (for API / mobile clients)
    .with_bearer(yauth::config::BearerConfig {
        jwt_secret,
        access_token_ttl: Duration::from_secs(15 * 60), // 15 minutes
        refresh_token_ttl: Duration::from_secs(30 * 24 * 3600), // 30 days
        audience: None,
    })
    // API key authentication (X-Api-Key header)
    .with_api_key()
    // Admin user management endpoints
    .with_admin()
    // Magic link (passwordless email login)
    .with_magic_link(yauth::config::MagicLinkConfig::default())
    // Account lockout (brute-force protection)
    .with_account_lockout(yauth::config::AccountLockoutConfig::default())
    // Webhooks (HTTP callbacks on auth events)
    .with_webhooks(yauth::config::WebhookConfig::default())
    // OAuth2 Authorization Server
    .with_oauth2_server(yauth::config::OAuth2ServerConfig {
        issuer: base_url.clone(),
        authorization_code_ttl: Duration::from_secs(60),
        scopes_supported: vec![
            "read:runs".into(),
            "write:runs".into(),
            "read:milestones".into(),
            "write:milestones".into(),
        ],
        allow_dynamic_registration: true,
        ..Default::default()
    })
    // OIDC (OpenID Connect Provider)
    .with_oidc(yauth::config::OidcConfig {
        issuer: base_url.clone(),
        ..Default::default()
    })
    // Status endpoint
    .with_status();

    // Optional Redis store backend
    #[cfg(feature = "redis")]
    let builder = if let Ok(redis_url) = env::var("REDIS_URL") {
        log::info!("Using Redis store backend: {}", redis_url);
        let client = redis::Client::open(redis_url).expect("Invalid REDIS_URL");
        let conn = client
            .get_connection_manager()
            .await
            .expect("Failed to connect to Redis");
        builder.with_redis(conn)
    } else {
        builder
    };

    let auth = builder.build().await.expect("Failed to build YAuth");

    // -----------------------------------------------------------------------
    // 5. Build the Axum application
    // -----------------------------------------------------------------------
    // Grab a clone of the auth state — we need it both for nesting the auth
    // router and for our own app routes that require authentication.
    let auth_state = auth.state().clone();

    // Protected application routes — these use the yauth auth middleware so
    // that `AuthUser` is available via `Extension<AuthUser>`.
    let app_protected = Router::new().route("/api/me", get(me_handler)).layer(
        axum::middleware::from_fn_with_state(
            auth_state.clone(),
            yauth::middleware::auth_middleware,
        ),
    );

    let app = Router::new()
        // Public routes
        .route("/api/health", get(health_handler))
        // Protected app routes (auth middleware applied above)
        .merge(app_protected)
        // Mount all yauth auth routes under /api/auth
        .nest("/api/auth", auth.router())
        // Provide the shared YAuthState to all routes
        .with_state(auth_state);

    // -----------------------------------------------------------------------
    // 6. Start the server
    // -----------------------------------------------------------------------
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind port");
    log::info!("YAuth example server listening on http://0.0.0.0:{}", port);
    log::info!("  Health:  GET  http://localhost:{}/api/health", port);
    log::info!(
        "  Me:      GET  http://localhost:{}/api/me  (requires auth)",
        port
    );
    log::info!(
        "  Auth:    POST http://localhost:{}/api/auth/register",
        port
    );
    log::info!("           POST http://localhost:{}/api/auth/login", port);
    log::info!("           GET  http://localhost:{}/api/auth/session", port);

    axum::serve(listener, app).await.expect("Server error");
}

// ---------------------------------------------------------------------------
// Application Handlers
// ---------------------------------------------------------------------------

/// Unauthenticated health check endpoint.
///
/// Returns `200 OK` with a simple JSON body. Use this for liveness probes.
async fn health_handler() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Protected endpoint that returns the authenticated user's information.
///
/// The `AuthUser` is injected by yauth's auth middleware. It is available as
/// an Axum `Extension` on any route that has the middleware applied. This
/// demonstrates the pattern consuming applications should follow to build
/// their own protected routes.
///
/// Supported authentication methods (tried in order by the middleware):
///   1. Session cookie
///   2. `Authorization: Bearer <jwt>` header
///   3. `X-Api-Key: <key>` header
async fn me_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "email_verified": user.email_verified,
            "role": user.role,
            "auth_method": format!("{:?}", user.auth_method),
        })),
    )
}
