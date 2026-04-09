# Configuration Reference

## Session Binding

Detects session hijacking by binding sessions to client IP and/or User-Agent. Configure in `YAuthConfig`:

- `bind_ip: true` — track client IP at session creation
- `bind_user_agent: true` — track User-Agent at session creation
- `BindingAction::Warn` — log mismatch but allow access
- `BindingAction::Invalidate` — destroy session on mismatch (forces re-auth)

**When to use:** Enable `Warn` by default; use `Invalidate` for high-security applications. Note that `bind_ip` may cause issues with mobile users or VPN changes.

## Remember Me

Set `remember_me_ttl` on `YAuthConfig` to enable longer sessions when users opt in. The login request accepts a `remember_me: true` field.

**When to use:** When you want short default sessions (e.g., 24h) with opt-in long sessions (e.g., 30d) via a "keep me logged in" checkbox.

## Password Policy

Configure `PasswordPolicyConfig` on `EmailPasswordConfig`:

- `require_uppercase`, `require_lowercase`, `require_digit`, `require_special` — character class requirements
- `max_length` — maximum password length (default: 128)
- `disallow_common_passwords` — reject top common passwords
- `password_history_count` — prevent reuse of last N passwords (0 = disabled)

**When to use:** When regulatory compliance or security policy requires specific password complexity rules beyond minimum length + HIBP checking.

## Account Lockout

Configure `AccountLockoutConfig`:

- `max_failed_attempts` — threshold before lockout (default: 5)
- `lockout_duration` — base lockout time (default: 5 minutes)
- `exponential_backoff` — double duration on each lockout
- `max_lockout_duration` — cap for backoff (default: 24 hours)
- `auto_unlock` — auto-unlock after duration expires

**When to use:** When you need per-account brute-force protection that works across IPs. Rate limiting is per-IP; account lockout is per-account. Use both together for defense in depth.

## Webhooks

Configure `WebhookConfig`:

- `max_retries` — retry failed deliveries (default: 3)
- `retry_delay` — delay between retries (default: 30s)
- `timeout` — HTTP timeout per delivery (default: 10s)
- `max_webhooks` — limit per user (default: 10)

Payloads are signed with HMAC-SHA256 via the `X-Webhook-Signature` header. Admin routes at `/webhooks` manage webhook CRUD.

**When to use:** When external systems (Slack bots, CRMs, analytics) need real-time notifications of auth events without polling.

## OIDC

Configure `OidcConfig`:

- `issuer` — OIDC issuer URL (must match `iss` claim)
- `id_token_ttl` — id_token expiry (default: 1 hour)
- `claims_supported` — advertised claims (default: sub, email, email_verified, name)

**When to use:** When yauth is the identity provider and downstream apps need OIDC-compliant SSO. Automatically enables `bearer` + `oauth2-server`.
