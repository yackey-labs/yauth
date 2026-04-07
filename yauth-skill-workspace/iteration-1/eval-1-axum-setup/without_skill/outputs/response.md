# Setting Up yauth with Email/Password, Passkeys, and MFA

Here is the complete setup for an Axum app with yauth authentication. You need two files: `Cargo.toml` and `src/main.rs`.

## Cargo.toml

```toml
[package]
name = "myapp"
version = "0.1.0"
edition = "2024"

[dependencies]
# Web framework
axum = { version = "0.8", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.6", features = ["cors", "trace"] }

# yauth — enable the three plugins you need
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

## src/main.rs

```rust
use axum::{Extension, Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

use yauth::middleware::AuthUser;
use yauth::prelude::*;

#[tokio::main]
async fn main() {
    // 1. Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,yauth=debug".into()),
        )
        .init();

    // 2. Database connection pool
    let database_url = "postgres://myapp:secret@db.internal:5432/myapp";

    let manager =
        yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(database_url);
    let pool = yauth::DieselPool::builder(manager)
        .build()
        .expect("Failed to create database pool");

    // 3. Run yauth migrations (creates all required tables)
    yauth::migration::diesel_migrations::run_migrations(&pool)
        .await
        .expect("Failed to run yauth migrations");
    tracing::info!("Migrations complete");

    // 4. Configure yauth
    let yauth_config = YAuthConfig {
        base_url: "http://localhost:3000".into(),
        session_cookie_name: "session".into(),
        session_ttl: Duration::from_secs(7 * 24 * 3600), // 1 week
        secure_cookies: false, // set true in production with HTTPS
        trusted_origins: vec!["http://localhost:3000".into()],
        auto_admin_first_user: true,
        ..Default::default()
    };

    // 5. Build yauth with email-password, passkey, and MFA plugins
    let auth = YAuthBuilder::new(pool, yauth_config)
        .with_email_password(yauth::config::EmailPasswordConfig {
            min_password_length: 8,
            require_email_verification: false, // set true when you have SMTP configured
            hibp_check: true,
            ..Default::default()
        })
        .with_passkey(yauth::config::PasskeyConfig {
            rp_id: "localhost".into(),                   // your domain in production
            rp_origin: "http://localhost:3000".into(),    // must match browser origin
            rp_name: "My App".into(),                    // shown in passkey prompts
        })
        .with_mfa(yauth::config::MfaConfig {
            issuer: "My App".into(),  // shown in authenticator apps (e.g. Google Authenticator)
            backup_code_count: 10,
        })
        .build();

    // 6. Grab the shared auth state
    let auth_state = auth.state().clone();

    // 7. Build protected app routes (auth middleware injects Extension<AuthUser>)
    let app_protected = Router::new()
        .route("/api/me", get(me_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            yauth::middleware::auth_middleware,
        ));

    // 8. CORS layer (adjust allowed origins for production)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(false);

    // 9. Assemble the app
    let app = Router::new()
        // Public routes
        .route("/api/health", get(health_handler))
        // Protected app routes
        .merge(app_protected)
        // Mount yauth auth routes at /api/auth
        .nest("/api/auth", auth.router())
        // Share the YAuthState with all routes
        .with_state(auth_state)
        // CORS
        .layer(cors);

    // 10. Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind");
    tracing::info!("Server listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.expect("Server error");
}

/// Unauthenticated health check.
async fn health_handler() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Protected endpoint - returns the current authenticated user.
///
/// The `AuthUser` extension is injected by yauth's auth middleware.
/// Authentication is tried in order: session cookie, then bearer token, then API key.
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
```

## What This Gives You

### Auth Routes (all under `/api/auth/`)

**Email/Password (enabled by `email-password` feature):**
- `POST /api/auth/register` -- create account with email + password
- `POST /api/auth/login` -- log in with email + password (sets session cookie)
- `POST /api/auth/forgot-password` -- request password reset email
- `POST /api/auth/reset-password` -- reset password with token
- `POST /api/auth/change-password` -- change password (authenticated)
- `GET  /api/auth/verify-email` -- verify email address via link

**Passkey / WebAuthn (enabled by `passkey` feature):**
- `POST /api/auth/passkey/register/start` -- begin passkey registration (authenticated)
- `POST /api/auth/passkey/register/finish` -- complete passkey registration
- `POST /api/auth/passkey/login/start` -- begin passkey login
- `POST /api/auth/passkey/login/finish` -- complete passkey login
- `GET  /api/auth/passkey/list` -- list registered passkeys (authenticated)
- `DELETE /api/auth/passkey/:id` -- delete a passkey (authenticated)

**MFA / TOTP (enabled by `mfa` feature):**
- `POST /api/auth/mfa/setup` -- generate TOTP secret + QR URI (authenticated)
- `POST /api/auth/mfa/verify` -- verify TOTP code to enable MFA (authenticated)
- `POST /api/auth/mfa/challenge` -- submit TOTP during login (when MFA is enabled)
- `GET  /api/auth/mfa/backup-codes` -- get backup codes (authenticated)
- `POST /api/auth/mfa/disable` -- disable MFA (authenticated)

**Core (always available):**
- `GET  /api/auth/session` -- get current authenticated user info
- `POST /api/auth/logout` -- invalidate session
- `GET  /api/auth/config` -- returns enabled auth features (useful for frontend UI decisions)

### Your App Routes

- `GET /api/health` -- public health check
- `GET /api/me` -- returns the authenticated user (protected by yauth middleware)

## Production Checklist

1. **HTTPS**: Set `secure_cookies: true` and update `base_url`, `trusted_origins`, `rp_origin` to use `https://`.

2. **Passkey RP ID**: Change `rp_id` from `"localhost"` to your actual domain (e.g., `"myapp.com"`). The `rp_origin` must match the browser origin exactly.

3. **Email verification**: Set `require_email_verification: true` and configure SMTP:
   ```rust
   smtp: Some(yauth::config::SmtpConfig {
       host: "smtp.example.com".into(),
       port: 587,
       from: "noreply@myapp.com".into(),
   }),
   ```

4. **Environment variables**: Move the database URL and any secrets out of source code:
   ```rust
   let database_url = std::env::var("DATABASE_URL")
       .expect("DATABASE_URL must be set");
   ```

5. **CORS**: Replace `Any` origins with your actual frontend origin(s). Include `traceparent` and `tracestate` headers if using OpenTelemetry.

6. **Custom DB schema** (optional): If you want yauth tables isolated from your app tables, set `db_schema: "auth".into()` in `YAuthConfig` and use `yauth::create_pool()` instead of building the pool manually -- it sets the `search_path` automatically.
