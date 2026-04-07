# Setting Up yauth with Email/Password, Passkeys, and MFA

Here is a complete setup for an Axum web app with yauth authentication. You will need two files: `Cargo.toml` and `src/main.rs`.

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

## src/main.rs

```rust
use axum::{
    extract::Extension,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::time::Duration;
use yauth::prelude::*;
use yauth::middleware::AuthUser;

async fn me_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Json(json!({
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "auth_method": format!("{:?}", user.auth_method),
    }))
}

async fn health_handler() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = "postgres://myapp:secret@db.internal:5432/myapp";

    // 1. Create the database connection pool
    let config = yauth::AsyncDieselConnectionManager::<yauth::AsyncPgConnection>::new(database_url);
    let pool = yauth::DieselPool::builder(config).build()?;

    // 2. Run migrations (idempotent -- creates tables for email-password, passkey, mfa)
    yauth::migration::diesel_migrations::run_migrations(&pool).await?;

    // 3. Configure and build YAuth
    let yauth_config = yauth::config::YAuthConfig {
        base_url: "http://localhost:3000".into(),
        session_cookie_name: "session".into(),
        session_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
        secure_cookies: false, // set to true in production with HTTPS
        trusted_origins: vec!["http://localhost:3000".into()],
        allow_signups: true,
        auto_admin_first_user: true,
        ..Default::default()
    };

    let auth = YAuthBuilder::new(pool, yauth_config)
        .with_email_password(yauth::config::EmailPasswordConfig::default())
        .with_passkey(yauth::config::PasskeyConfig {
            rp_id: "localhost".into(),           // use your domain in production
            rp_origin: "http://localhost:3000".into(),
            rp_name: "My App".into(),
        })
        .with_mfa(yauth::config::MfaConfig {
            issuer: "My App".into(),
            backup_code_count: 10,
        })
        .build();

    // 4. Build the Axum router
    let auth_state = auth.state().clone();

    // Protected routes -- AuthUser is injected via Extension by the auth middleware
    let app_protected = Router::new()
        .route("/api/me", get(me_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            yauth::middleware::auth_middleware,
        ));

    let app = Router::new()
        .route("/api/health", get(health_handler))
        .merge(app_protected)
        .nest("/api/auth", auth.router()) // All yauth routes under /api/auth
        .with_state(auth_state);

    // 5. Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
```

## What This Gets You

### Auth routes available at `/api/auth`:

**Core (always available):**
- `GET /api/auth/config` -- public auth configuration
- `GET /api/auth/session` -- get current user (requires auth)
- `POST /api/auth/logout` -- destroy session (requires auth)

**Email/Password:**
- `POST /api/auth/register` -- create a new account
- `POST /api/auth/login` -- log in with email + password
- `POST /api/auth/verify-email` -- verify email address
- `POST /api/auth/resend-verification` -- resend verification email
- `POST /api/auth/forgot-password` -- request password reset
- `POST /api/auth/reset-password` -- reset password with token
- `POST /api/auth/change-password` -- change password (requires auth)

**Passkey (WebAuthn):**
- `POST /api/auth/passkey/login/begin` -- start passkey login
- `POST /api/auth/passkey/login/finish` -- complete passkey login
- `POST /api/auth/passkeys/register/begin` -- start passkey registration (requires auth)
- `POST /api/auth/passkeys/register/finish` -- complete passkey registration (requires auth)
- `GET /api/auth/passkeys` -- list registered passkeys (requires auth)
- `DELETE /api/auth/passkeys/{id}` -- delete a passkey (requires auth)

**MFA (TOTP + Backup Codes):**
- `POST /api/auth/mfa/setup` -- begin MFA setup (requires auth)
- `POST /api/auth/mfa/verify` -- verify TOTP code during login
- `POST /api/auth/mfa/confirm` -- confirm MFA setup (requires auth)
- `POST /api/auth/mfa/disable` -- disable MFA (requires auth)

### Your protected endpoint:
- `GET /api/me` -- returns the currently authenticated user's `id`, `email`, `role`, and `auth_method`

### Database tables created automatically:

| Feature | Tables |
|---|---|
| Core (always) | `yauth_users`, `yauth_sessions`, `yauth_audit_log` |
| Email/Password | `yauth_passwords`, `yauth_email_verifications`, `yauth_password_resets` |
| Passkey | `yauth_webauthn_credentials` |
| MFA | `yauth_totp_secrets`, `yauth_backup_codes` |

## How auth works

The auth middleware on `/api/me` checks credentials in this order:
1. **Session cookie** -- looks for a `session` cookie and validates it
2. **Bearer token** -- checks `Authorization: Bearer <jwt>` header (only if `bearer` feature is enabled, which it is not here)
3. **API key** -- checks `X-Api-Key` header (only if `api-key` feature is enabled, which it is not here)

The first valid credential wins, and the authenticated user is injected as `Extension<AuthUser>` into your handler.

## Production checklist

Before deploying, update these settings:

1. **`secure_cookies: true`** -- requires HTTPS
2. **`base_url`** -- set to your production URL (e.g., `"https://myapp.example.com"`)
3. **`trusted_origins`** -- set to your production frontend origin
4. **`rp_id`** and **`rp_origin`** in `PasskeyConfig` -- set to your production domain
5. **SMTP** -- add `smtp: Some(SmtpConfig { ... })` to `yauth_config` if you want email verification and password reset emails to actually send
6. **Store backend** -- the default is in-memory (data lost on restart). For production, use Postgres or Redis:

```rust
// Postgres store (no extra infra needed):
let auth = YAuthBuilder::new(pool, yauth_config)
    // ... plugins ...
    .with_store_backend(StoreBackend::Postgres)
    .build();
```

## Frontend integration (optional)

If you have a SolidJS frontend:

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-solidjs
```

```tsx
import { YAuthProvider, LoginForm, MfaChallenge, PasskeyButton } from "@yackey-labs/yauth-ui-solidjs";

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
      <>
        <LoginForm
          onSuccess={() => navigate("/dashboard")}
          onMfaRequired={(sessionId) => setMfaPending(sessionId)}
          showPasskey
        />
        <PasskeyButton mode="login" onSuccess={() => navigate("/dashboard")} />
      </>
    }>
      {(sessionId) => (
        <MfaChallenge
          pendingSessionId={sessionId()}
          onSuccess={() => navigate("/dashboard")}
        />
      )}
    </Show>
  );
}
```
