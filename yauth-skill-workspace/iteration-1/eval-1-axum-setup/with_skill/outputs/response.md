# yauth Setup: Email/Password + Passkeys + MFA

Here is the complete setup for integrating yauth into your Axum application with email/password, passkey, and MFA support, auth routes at `/api/auth`, and a protected `/api/me` endpoint.

## Cargo.toml

```toml
[package]
name = "myapp"
version = "0.1.0"
edition = "2021"

[dependencies]
yauth = { version = "0.3", features = ["email-password", "passkey", "mfa"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tower-http = { version = "0.6", features = ["cors"] }
```

The three feature flags enable exactly the plugins you need:
- `email-password` -- registration, login, email verification, forgot/reset/change password
- `passkey` -- WebAuthn registration and login
- `mfa` -- TOTP setup/verify and backup codes

## src/main.rs

```rust
use axum::{Extension, Json, Router, routing::get};
use serde_json::json;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use yauth::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = "postgres://myapp:secret@db.internal:5432/myapp";

    // 1. Create the database connection pool
    let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(database_url);
    let pool = yauth::DieselPool::builder(config).build()?;

    // 2. Run migrations (idempotent -- creates tables for email-password, passkey, and mfa)
    yauth::migration::diesel_migrations::run_migrations(&pool).await?;

    // 3. Configure and build the YAuth instance
    let auth = YAuthBuilder::new(pool, yauth::config::YAuthConfig {
        base_url: "https://myapp.example.com".into(),
        session_cookie_name: "session".into(),
        session_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
        secure_cookies: true,
        trusted_origins: vec!["https://myapp.example.com".into()],
        smtp: Some(yauth::config::SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            from: "noreply@example.com".into(),
        }),
        auto_admin_first_user: true,
        allow_signups: true,
        ..Default::default()
    })
    .with_email_password(yauth::config::EmailPasswordConfig::default())
    .with_passkey(yauth::config::PasskeyConfig {
        rp_id: "myapp.example.com".into(),
        rp_origin: "https://myapp.example.com".into(),
        rp_name: "My App".into(),
    })
    .with_mfa(yauth::config::MfaConfig {
        issuer: "My App".into(),
        backup_code_count: 10,
    })
    .build();

    // 4. Get the auth state for middleware and routing
    let auth_state = auth.state().clone();

    // 5. Define protected application routes
    let app_protected = Router::new()
        .route("/api/me", get(me_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            yauth::middleware::auth_middleware,
        ));

    // 6. CORS configuration (needed if frontend is on a different origin)
    let cors = CorsLayer::new()
        .allow_origin(["https://myapp.example.com".parse().unwrap()])
        .allow_methods(Any)
        .allow_headers([
            "content-type".parse().unwrap(),
            "authorization".parse().unwrap(),
            "x-api-key".parse().unwrap(),
            "traceparent".parse().unwrap(),
            "tracestate".parse().unwrap(),
        ])
        .allow_credentials(true);

    // 7. Assemble the full router
    let app = Router::new()
        .route("/api/health", get(health_handler))
        .merge(app_protected)
        .nest("/api/auth", auth.router()) // All yauth routes under /api/auth
        .layer(cors)
        .with_state(auth_state);

    // 8. Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Protected endpoint -- returns the current authenticated user.
/// The auth middleware injects `AuthUser` as an Extension.
async fn me_handler(Extension(user): Extension<yauth::middleware::AuthUser>) -> impl axum::response::IntoResponse {
    Json(json!({
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "auth_method": format!("{:?}", user.auth_method),
    }))
}

/// Simple health check (unauthenticated).
async fn health_handler() -> impl axum::response::IntoResponse {
    Json(json!({ "status": "ok" }))
}
```

## What This Gives You

### Auth Routes (all under `/api/auth`)

**Email-Password:**
- `POST /api/auth/register` -- create a new account
- `POST /api/auth/login` -- log in with email and password
- `POST /api/auth/verify-email` -- verify email address
- `POST /api/auth/resend-verification` -- resend verification email
- `POST /api/auth/forgot-password` -- request a password reset
- `POST /api/auth/reset-password` -- reset password with token
- `POST /api/auth/change-password` -- change password (authenticated)

**Passkey (WebAuthn):**
- `POST /api/auth/passkey/login/begin` -- start passkey login
- `POST /api/auth/passkey/login/finish` -- complete passkey login
- `POST /api/auth/passkeys/register/begin` -- start passkey registration (authenticated)
- `POST /api/auth/passkeys/register/finish` -- complete passkey registration (authenticated)
- `GET /api/auth/passkeys` -- list registered passkeys (authenticated)
- `DELETE /api/auth/passkeys/{id}` -- remove a passkey (authenticated)

**MFA (TOTP):**
- `POST /api/auth/mfa/setup` -- begin MFA enrollment (authenticated)
- `POST /api/auth/mfa/verify` -- verify TOTP code during login
- `POST /api/auth/mfa/confirm` -- confirm MFA setup (authenticated)
- `POST /api/auth/mfa/disable` -- disable MFA (authenticated)

**Core:**
- `GET /api/auth/config` -- public auth configuration
- `GET /api/auth/session` -- current user info (authenticated)
- `POST /api/auth/logout` -- destroy session (authenticated)
- `PATCH /api/auth/me` -- update profile (authenticated)

### Application Routes

- `GET /api/me` -- returns the current authenticated user (your custom endpoint)
- `GET /api/health` -- health check

### Database Tables Created

The migration runner automatically creates these tables (all prefixed with `yauth_`):

| Feature | Tables |
|---|---|
| Core | `yauth_users`, `yauth_sessions`, `yauth_audit_log` |
| email-password | `yauth_passwords`, `yauth_email_verifications`, `yauth_password_resets` |
| passkey | `yauth_webauthn_credentials` |
| mfa | `yauth_totp_secrets`, `yauth_backup_codes` |

## Things to Customize Before Production

1. **SMTP settings** -- Replace `smtp.example.com` with your actual SMTP server. Without working SMTP, email verification and password reset emails will not be sent.

2. **`base_url` and `trusted_origins`** -- Set these to your actual production domain. The `rp_id` and `rp_origin` in `PasskeyConfig` must also match.

3. **`secure_cookies: true`** -- This is already set, which requires HTTPS. For local development, set it to `false`.

4. **Store backend** -- The default is in-memory storage, which loses sessions on restart. For production, add `.with_store_backend(StoreBackend::Postgres)` to the builder to persist sessions in your existing database, or use Redis if available.

5. **Database URL** -- Currently hardcoded. In production, read from an environment variable:
   ```rust
   let database_url = std::env::var("DATABASE_URL")
       .expect("DATABASE_URL must be set");
   ```

## Local Development Variant

For local development, adjust the config:

```rust
let auth = YAuthBuilder::new(pool, yauth::config::YAuthConfig {
    base_url: "http://localhost:3000".into(),
    secure_cookies: false, // No HTTPS locally
    trusted_origins: vec!["http://localhost:3000".into()],
    smtp: None, // Or use Mailpit on port 1025
    ..Default::default()
})
.with_email_password(yauth::config::EmailPasswordConfig::default())
.with_passkey(yauth::config::PasskeyConfig {
    rp_id: "localhost".into(),
    rp_origin: "http://localhost:3000".into(),
    rp_name: "My App (Dev)".into(),
})
.with_mfa(yauth::config::MfaConfig {
    issuer: "My App (Dev)".into(),
    backup_code_count: 10,
})
.build();
```

## Frontend Integration (Optional)

If you are building a SolidJS frontend, install the UI packages:

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-solidjs
```

Then wrap your app in `YAuthProvider` and use the pre-built components:

```tsx
import { YAuthProvider, LoginForm, MfaChallenge, PasskeyButton } from "@yackey-labs/yauth-ui-solidjs";
import { createSignal, Show } from "solid-js";

function App() {
  return (
    <YAuthProvider baseUrl="/api/auth">
      <LoginPage />
    </YAuthProvider>
  );
}

function LoginPage() {
  const [mfaPending, setMfaPending] = createSignal<string | null>(null);

  return (
    <Show when={mfaPending()} fallback={
      <div>
        <LoginForm
          onSuccess={() => window.location.href = "/dashboard"}
          onMfaRequired={(sessionId) => setMfaPending(sessionId)}
          showPasskey={true}
        />
        <PasskeyButton mode="login" onSuccess={() => window.location.href = "/dashboard"} />
      </div>
    }>
      {(sessionId) => (
        <MfaChallenge
          pendingSessionId={sessionId()}
          onSuccess={() => window.location.href = "/dashboard"}
        />
      )}
    </Show>
  );
}
```

The auth middleware checks credentials in this order: session cookie, then `Authorization: Bearer <jwt>`, then `X-Api-Key` header. Since you have not enabled the `bearer` or `api-key` features, only session cookies are active, which is the right default for a web app with a browser-based frontend.
