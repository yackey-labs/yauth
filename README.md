# yauth

Modular, plugin-based authentication library for Rust (Axum) with a generated TypeScript client and SolidJS UI components.

Every feature is behind a **feature flag** — enable only what you need.

## Features

| Feature | Description |
|---------|-------------|
| `email-password` | Registration, login, email verification, forgot/reset/change password, HIBP breach checking |
| `passkey` | WebAuthn registration and passwordless login |
| `mfa` | TOTP setup/verify with backup codes; intercepts login flow via event system |
| `oauth` | OAuth2 client — multi-provider linking, account management |
| `bearer` | JWT access/refresh tokens with token family tracking (reuse detection) |
| `api-key` | Scoped API key generation with optional expiration |
| `magic-link` | Passwordless email login with optional signup |
| `admin` | User management, ban/unban, session management, impersonation |
| `oauth2-server` | Full OAuth2 authorization server (authorization code + PKCE, device flow, dynamic client registration, refresh tokens) |
| `telemetry` | OpenTelemetry tracing bridge |
| `full` | All of the above |

Only `email-password` is enabled by default.

## Quick Start

Add yauth to your `Cargo.toml`:

```toml
[dependencies]
yauth = { version = "0.1", features = ["email-password", "passkey", "mfa"] }
```

Configure and build:

```rust
use yauth::{YAuthBuilder, config::*};

let yauth = YAuthBuilder::new(db, YAuthConfig {
    base_url: "https://myapp.example.com".into(),
    session_ttl: Duration::from_secs(7 * 24 * 3600),
    secure_cookies: true,
    ..Default::default()
})
.with_email_password(EmailPasswordConfig {
    min_password_length: 10,
    require_email_verification: true,
    hibp_check: true,
})
.with_passkey(PasskeyConfig {
    rp_id: "myapp.example.com".into(),
    rp_origin: "https://myapp.example.com".into(),
    rp_name: "My App".into(),
})
.with_mfa(MfaConfig::default())
.build();

let app = Router::new()
    .merge(yauth.router())
    .with_state(yauth.into_state());
```

## Architecture

### Plugin System

Plugins implement the `YAuthPlugin` trait:

- `public_routes()` — unauthenticated endpoints (login, register, etc.)
- `protected_routes()` — endpoints behind auth middleware
- `on_event()` — react to auth events (e.g., MFA intercepts login)

Custom plugins can be added via `builder.with_plugin(Box::new(MyPlugin))`.

### Tri-Mode Auth Middleware

Every protected route checks credentials in order:

1. **Session cookie** — `CookieJar` → `validate_session()`
2. **Bearer token** — `Authorization: Bearer <jwt>` → JWT validation (requires `bearer` feature)
3. **API key** — `X-Api-Key: <key>` → key hash lookup (requires `api-key` feature)

The authenticated user is injected as `Extension<AuthUser>` with fields: `id`, `email`, `display_name`, `email_verified`, `role`, `banned`, `auth_method`, and `scopes`.

### Event System

All auth operations emit an `AuthEvent`:

- `UserRegistered`, `LoginSucceeded`, `LoginFailed`, `SessionCreated`, `Logout`
- `PasswordChanged`, `EmailVerified`
- `MfaEnabled`, `MfaDisabled`
- `UserBanned`, `UserUnbanned`
- `MagicLinkSent`, `MagicLinkVerified`

Plugins respond with `Continue`, `RequireMfa { pending_session_id }`, or `Block { status, message }`.

## API Routes

### Core (always available)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/session` | Yes | Get authenticated user info |
| POST | `/logout` | Yes | Invalidate session |
| PATCH | `/me` | Yes | Update display name |

### Email/Password

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | No | Register with email + password |
| POST | `/login` | No | Authenticate |
| POST | `/verify-email` | No | Verify email token |
| POST | `/resend-verification` | No | Resend verification email |
| POST | `/forgot-password` | No | Request password reset |
| POST | `/reset-password` | No | Reset password with token |
| POST | `/change-password` | Yes | Change password |

### Passkey (WebAuthn)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/passkey/login/begin` | No | Start WebAuthn login challenge |
| POST | `/passkey/login/finish` | No | Complete WebAuthn login |
| POST | `/passkeys/register/begin` | Yes | Start passkey registration |
| POST | `/passkeys/register/finish` | Yes | Complete passkey registration |
| GET | `/passkeys` | Yes | List passkeys |
| DELETE | `/passkeys/{id}` | Yes | Delete passkey |

### MFA (TOTP + Backup Codes)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/mfa/verify` | No | Verify MFA code during login |
| POST | `/mfa/totp/setup` | Yes | Generate TOTP secret + backup codes |
| POST | `/mfa/totp/confirm` | Yes | Confirm TOTP setup |
| DELETE | `/mfa/totp` | Yes | Disable TOTP |
| GET | `/mfa/backup-codes` | Yes | Get backup code count |
| POST | `/mfa/backup-codes/regenerate` | Yes | Regenerate backup codes |

### OAuth (Client)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/oauth/{provider}/authorize` | No | Start OAuth flow |
| GET/POST | `/oauth/{provider}/callback` | No | OAuth callback |
| GET | `/oauth/accounts` | Yes | List connected accounts |
| DELETE | `/oauth/{provider}` | Yes | Unlink provider |
| POST | `/oauth/{provider}/link` | Yes | Link account to provider |

### Bearer Tokens (JWT)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/token` | No | Get access + refresh tokens |
| POST | `/token/refresh` | No | Refresh access token |
| POST | `/token/revoke` | Yes | Revoke refresh token |

### API Keys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api-keys` | Yes | List API keys |
| POST | `/api-keys` | Yes | Create API key (optional scopes, expiry) |
| DELETE | `/api-keys/{id}` | Yes | Delete API key |

### Magic Link

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/magic-link/send` | No | Send magic link email |
| POST | `/magic-link/verify` | No | Verify magic link token |

### Admin

All admin routes require `role = "admin"`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List users (paginated, searchable) |
| GET | `/admin/users/{id}` | Get user details |
| PUT | `/admin/users/{id}` | Update user |
| DELETE | `/admin/users/{id}` | Delete user |
| POST | `/admin/users/{id}/ban` | Ban user |
| POST | `/admin/users/{id}/unban` | Unban user |
| POST | `/admin/users/{id}/impersonate` | Create session as user |
| GET | `/admin/sessions` | List sessions |
| DELETE | `/admin/sessions/{id}` | Terminate session |

### OAuth2 Server

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| GET | `/oauth/authorize` | Authorization endpoint (JSON or redirect to consent UI) |
| POST | `/oauth/authorize` | Consent submission (JSON or form-urlencoded) |
| POST | `/oauth/token` | Token endpoint (JSON or form-urlencoded, per RFC 6749) |
| POST | `/oauth/register` | Dynamic client registration (RFC 7591) |
| POST | `/oauth/device/code` | Device authorization request (RFC 8628) |
| GET/POST | `/oauth/device` | Device verification |

Supported grant types: `authorization_code` (with PKCE S256), `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code`.

## TypeScript Packages

### @yauth/client

Zero-dependency HTTP client auto-generated from Rust types and route metadata via `axum-ts-client`.

```typescript
import { createClient } from "@yauth/client";

const auth = createClient({ baseUrl: "https://myapp.example.com/auth" });

// Email/password
await auth.emailPassword.register({ email, password });
const { user } = await auth.emailPassword.login({ email, password });

// Session
const { user } = await auth.getSession();
await auth.logout();

// Passkey, MFA, OAuth, bearer, API keys, magic link, admin, OAuth2 server
// — all available as namespaced methods on the client
```

### @yauth/shared

Shared TypeScript types (`AuthUser`, `AuthSession`, etc.) and an AAGUID authenticator map.

### @yauth/ui-solidjs

Pre-built SolidJS components:

- `YAuthProvider` / `useYAuth()` — context provider
- `LoginForm`, `RegisterForm`, `ForgotPasswordForm`, `ResetPasswordForm`
- `ChangePasswordForm`, `VerifyEmail`, `ProfileSettings`
- `PasskeyButton`, `OAuthButtons`
- `MfaSetup`, `MfaChallenge`
- `MagicLinkForm`
- `ConsentScreen` — OAuth2 authorization consent UI

## Security

- **Argon2id** password hashing with timing-safe dummy hash on failed lookups
- **HaveIBeenPwned** k-anonymity password breach checking (fail-open)
- **Rate limiting** per operation (login, register, forgot-password, magic-link)
- **Session tokens** stored as SHA-256 hashes
- **JWT refresh token family tracking** — automatic revocation on reuse detection
- **CSRF protection** — HttpOnly + SameSite=Lax cookies; bearer/API key via headers
- **Email enumeration prevention** — consistent responses for non-existent accounts
- **Audit logging** — all auth events written to `yauth_audit_log` table
- **WebAuthn challenge TTL** — 5-minute expiry with credential exclusion

## Database

yauth uses SeaORM with PostgreSQL. All tables are prefixed with `yauth_`. Migrations are feature-gated — only tables for enabled features are created.

Run migrations:

```bash
# Via the migration crate
cargo run -p yauth-migration -- up
```

## Development

```bash
# Rust
cargo test --features full
cargo clippy --features full -- -D warnings
cargo fmt --check

# TypeScript
bun install
bun validate          # lint:fix + typecheck + build
bun generate          # regenerate TS client from Rust types
bun generate:check    # CI: fail if client is out of date

# Integration testing
docker compose up -d                 # PostgreSQL + Mailpit
bash pentest/pentest-yauth.sh        # 172+ OWASP security test cases
```

## Versioning

Automated via [knope](https://knope.tech) from conventional commits. Never manually edit version numbers. All Rust crates and npm packages share a single unified version.

## License

MIT
