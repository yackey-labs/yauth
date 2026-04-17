# API Routes

All routes are mounted under your chosen prefix (e.g., `/api/auth`).

## Core (always available)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/session` | Yes | Get authenticated user info |
| POST | `/logout` | Yes | Invalidate session |
| PATCH | `/me` | Yes | Update display name |

## Email/Password

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | No | Register with email + password |
| POST | `/login` | No | Authenticate (supports `remember_me` flag) |
| POST | `/verify-email` | No | Verify email token |
| POST | `/resend-verification` | No | Resend verification email |
| POST | `/forgot-password` | No | Request password reset |
| POST | `/reset-password` | No | Reset password with token |
| POST | `/change-password` | Yes | Change password |

## Passkey (WebAuthn)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/passkey/login/begin` | No | Start WebAuthn login challenge |
| POST | `/passkey/login/finish` | No | Complete WebAuthn login |
| POST | `/passkeys/register/begin` | Yes | Start passkey registration |
| POST | `/passkeys/register/finish` | Yes | Complete passkey registration |
| GET | `/passkeys` | Yes | List passkeys |
| DELETE | `/passkeys/{id}` | Yes | Delete passkey |

## MFA (TOTP + Backup Codes)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/mfa/verify` | No | Verify MFA code during login |
| POST | `/mfa/totp/setup` | Yes | Generate TOTP secret + backup codes |
| POST | `/mfa/totp/confirm` | Yes | Confirm TOTP setup |
| DELETE | `/mfa/totp` | Yes | Disable TOTP |
| GET | `/mfa/backup-codes` | Yes | Get backup code count |
| POST | `/mfa/backup-codes/regenerate` | Yes | Regenerate backup codes |

## OAuth (Client)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/oauth/{provider}/authorize` | No | Start OAuth flow |
| GET/POST | `/oauth/{provider}/callback` | No | OAuth callback |
| GET | `/oauth/accounts` | Yes | List connected accounts |
| DELETE | `/oauth/{provider}` | Yes | Unlink provider |
| POST | `/oauth/{provider}/link` | Yes | Link account to provider |

## Bearer Tokens (JWT)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/token` | No | Get access + refresh tokens |
| POST | `/token/refresh` | No | Refresh access token |
| POST | `/token/revoke` | Yes | Revoke refresh token |

## API Keys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api-keys` | Yes | List API keys |
| POST | `/api-keys` | Yes | Create API key (optional scopes, expiry) |
| DELETE | `/api-keys/{id}` | Yes | Delete API key |

## Magic Link

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/magic-link/send` | No | Send magic link email |
| POST | `/magic-link/verify` | No | Verify magic link token |

## Status

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/status` | Yes | List enabled plugin names |

## Admin

All admin routes require `role = "admin"` (or a `MachineCaller` with
scope `admin` when `AdminConfig::allow_machine_callers = true`).

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

### OAuth2 client administration (requires `admin` + `oauth2-server`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/oauth2/clients` | List banned OAuth2 clients (newest ban first) |
| POST | `/admin/oauth2/clients/{client_id}/ban` | Mark a client banned; rejects new mints AND outstanding tokens |
| POST | `/admin/oauth2/clients/{client_id}/unban` | Clear ban |
| POST | `/admin/oauth2/clients/{client_id}/rotate-public-key` | Replace registered `public_key_pem` (requires `asymmetric-jwt`) |

Ban / unban / rotate each write an audit_log row with `actor_type`,
`actor_id` (for users) or `actor_client_id` (for machine callers), and
`target_client_id` in the metadata JSON.

## OAuth2 Server

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| GET | `/oauth/authorize` | Authorization endpoint (JSON or redirect to consent UI) |
| POST | `/oauth/authorize` | Consent submission (JSON or form-urlencoded) |
| POST | `/oauth/token` | Token endpoint — authorization_code, refresh_token, client_credentials (RFC 6749) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| POST | `/oauth/register` | Dynamic client registration (RFC 7591) — accepts `token_endpoint_auth_method` + `public_key_pem` for `private_key_jwt` clients |
| POST | `/oauth/device/code` | Device authorization request (RFC 8628) |
| GET/POST | `/oauth/device` | Device verification |

Supported grant types: `authorization_code` (with PKCE S256), `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`.

Supported client authentication methods at `/oauth/token`:
- `client_secret_post` (form-urlencoded `client_id` + `client_secret`)
- `client_secret_basic` (HTTP Basic)
- `private_key_jwt` (RFC 7523 — `client_assertion_type` + `client_assertion`; requires `asymmetric-jwt`)

Machine callers: tokens minted via `client_credentials` are validated at
`auth_middleware` and populate `Extension<MachineCaller>` on the request.
Use `require_scope("...")` to gate routes — it works for both human and
machine callers. See [configuration.md](configuration.md#oauth-20-m2m--client_credentials--private_key_jwt).

## Account Lockout

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/account/request-unlock` | No | Request unlock email |
| POST | `/account/unlock` | No | Unlock account with token |
| POST | `/admin/users/{id}/unlock` | Yes (admin) | Admin force-unlock |

## Webhooks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/webhooks` | Yes | Create webhook |
| GET | `/webhooks` | Yes | List webhooks |
| GET | `/webhooks/{id}` | Yes | Get webhook with delivery history |
| PUT | `/webhooks/{id}` | Yes | Update webhook |
| DELETE | `/webhooks/{id}` | Yes | Delete webhook |
| POST | `/webhooks/{id}/test` | Yes | Send test delivery |

## OIDC

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/openid-configuration` | No | OIDC discovery document |
| GET | `/.well-known/jwks.json` | No | JSON Web Key Set |
| GET/POST | `/userinfo` | Yes | OIDC UserInfo endpoint |
