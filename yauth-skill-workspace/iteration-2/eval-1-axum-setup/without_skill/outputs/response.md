# Setting Up yauth with Email/Password, Passkeys, and MFA

Here is a complete setup for a new Axum web app using yauth for authentication with email/password, passkeys, and MFA. Auth routes will be nested under `/api/auth` and a protected `/api/me` endpoint will return the current user.

## Project Structure

```
my-app/
  Cargo.toml
  src/
    main.rs
```

## Cargo.toml

```toml
[package]
name = "my-app"
version = "0.1.0"
edition = "2021"

[dependencies]
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa"] }
yauth-entity = { version = "0.3", features = ["email-password", "passkey", "mfa"] }
yauth-migration = { version = "0.3", features = ["email-password", "passkey", "mfa"] }

axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tower-http = { version = "0.6", features = ["cors"] }
```

## src/main.rs

```rust
use axum::{
    extract::Extension,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};

// yauth re-exports the AuthUser type that the middleware injects
use yauth::{AuthUser, YAuthBuilder, YAuthConfig};
use yauth::plugins::{
    EmailPasswordConfig,
    PasskeyConfig,
    MfaConfig,
};

#[derive(Serialize)]
struct MeResponse {
    id: String,
    email: String,
}

/// Protected endpoint — only reachable by authenticated users.
/// The yauth middleware injects `AuthUser` as an Extension when
/// a valid session cookie, bearer token, or API key is present.
async fn me_handler(Extension(user): Extension<AuthUser>) -> Json<MeResponse> {
    Json(MeResponse {
        id: user.id.to_string(),
        email: user.email.clone(),
    })
}

#[tokio::main]
async fn main() {
    // 1. Configure yauth
    let config = YAuthConfig {
        database_url: "postgres://myapp:secret@db.internal:5432/myapp".to_string(),
        // Isolate yauth tables in a separate PG schema (optional, default is "public")
        db_schema: "public".to_string(),
        ..Default::default()
    };

    // 2. Create the database pool with yauth's helper (sets search_path correctly)
    let pool = yauth::create_pool(&config).await.expect("Failed to create DB pool");

    // 3. Run yauth migrations (creates all yauth_* tables)
    yauth_migration::run_migrations(&pool)
        .await
        .expect("Failed to run yauth migrations");

    // 4. Configure plugins
    let ep_config = EmailPasswordConfig {
        // Require email verification before login
        require_email_verification: true,
        // Check passwords against HaveIBeenPwned (k-anonymity, no full password sent)
        hibp_check: true,
        ..Default::default()
    };

    let pk_config = PasskeyConfig {
        rp_id: "myapp.example.com".to_string(),
        rp_name: "My App".to_string(),
        rp_origin: "https://myapp.example.com".to_string(),
        ..Default::default()
    };

    let mfa_config = MfaConfig {
        issuer: "My App".to_string(),
        // Number of backup codes to generate
        backup_code_count: 10,
        ..Default::default()
    };

    // 5. Build yauth with all three plugins
    let yauth = YAuthBuilder::new(pool, config)
        .with_email_password(ep_config)
        .with_passkey(pk_config)
        .with_mfa(mfa_config)
        .build();

    // 6. Get the yauth router (includes public + protected auth routes)
    //    and the shared state
    let auth_router = yauth.router();
    let state = yauth.into_state();

    // 7. Build a protected /api/me route using yauth's auth middleware
    //    The auth middleware checks session cookie -> bearer token -> API key
    let protected_routes = Router::new()
        .route("/me", get(me_handler));

    // 8. Compose the full application
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            "content-type".parse().unwrap(),
            "authorization".parse().unwrap(),
            "traceparent".parse().unwrap(),
            "tracestate".parse().unwrap(),
            "x-api-key".parse().unwrap(),
        ]);

    let app = Router::new()
        // Auth routes at /api/auth (login, register, passkey, mfa, etc.)
        .nest("/api/auth", auth_router)
        // Protected routes at /api (requires authentication)
        .nest("/api", protected_routes)
        .layer(cors)
        .with_state(state);

    // 9. Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind");

    println!("Server running on http://0.0.0.0:3000");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
```

## What This Gives You

### Auth Routes (under `/api/auth`)

**Email/Password (public):**
- `POST /api/auth/register` — create account (email + password)
- `POST /api/auth/login` — log in (returns session cookie)
- `POST /api/auth/forgot-password` — request password reset email
- `POST /api/auth/reset-password` — reset password with token
- `POST /api/auth/verify-email` — verify email with token

**Email/Password (protected, requires session):**
- `POST /api/auth/change-password` — change password while logged in

**Passkey (public):**
- `POST /api/auth/passkey/login/begin` — start passkey authentication
- `POST /api/auth/passkey/login/finish` — complete passkey authentication

**Passkey (protected):**
- `POST /api/auth/passkey/register/begin` — start passkey registration
- `POST /api/auth/passkey/register/finish` — complete passkey registration
- `GET /api/auth/passkey/list` — list registered passkeys
- `DELETE /api/auth/passkey/:id` — remove a passkey

**MFA (protected):**
- `POST /api/auth/mfa/setup` — generate TOTP secret + QR code
- `POST /api/auth/mfa/verify` — verify TOTP code and enable MFA
- `POST /api/auth/mfa/disable` — disable MFA
- `GET /api/auth/mfa/backup-codes` — retrieve backup codes

**Core (always available):**
- `GET /api/auth/session` — get current authenticated user info
- `POST /api/auth/logout` — invalidate session

### Protected Route

- `GET /api/me` — returns the authenticated user's ID and email

## Important Notes

1. **Table prefix**: All yauth database tables are prefixed with `yauth_` to avoid conflicts with your app's tables.

2. **Tri-mode auth**: The middleware automatically checks for authentication in this order: session cookie, then Bearer token (if `bearer` feature is enabled), then API key (if `api-key` feature is enabled). For this setup with only email-password + passkey + mfa, authentication is via session cookies.

3. **Timing-safe**: yauth uses dummy password hashes on failed lookups to prevent user enumeration via timing attacks.

4. **Rate limiting**: Built-in per-operation rate limits protect against brute force on login, registration, and forgot-password endpoints.

5. **MFA intercept**: When MFA is enabled for a user, the login endpoint will return an MFA challenge instead of completing login. The client must then call a verify endpoint with the TOTP code to complete authentication.

6. **Passkey configuration**: You must set `rp_id`, `rp_name`, and `rp_origin` to match your actual domain for WebAuthn to work correctly in browsers.

7. **CORS headers**: The `traceparent`, `tracestate`, and `x-api-key` headers are included in the CORS config as required by the yauth ecosystem for OpenTelemetry and API key support.

8. **Email sending**: For email verification and forgot-password flows, you will need to configure an email transport in `YAuthConfig` or handle the `AuthEvent::EmailVerificationRequested` / `AuthEvent::PasswordResetRequested` events to send emails yourself. During development, you can use Mailpit (`docker compose up -d` includes it in the yauth repo).
