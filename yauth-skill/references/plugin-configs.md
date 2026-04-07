# Plugin Configuration Reference

Complete configuration structs for every yauth plugin. All config types live under `yauth::config::`.

## Table of Contents

- [EmailPasswordConfig](#emailpasswordconfig)
- [PasskeyConfig](#passkeyconfig)
- [MfaConfig](#mfaconfig)
- [OAuthConfig](#oauthconfig)
- [BearerConfig](#bearerconfig)
- [MagicLinkConfig](#magiclinkconfig)
- [OAuth2ServerConfig](#oauth2serverconfig)
- [AccountLockoutConfig](#accountlockoutconfig)
- [WebhookConfig](#webhookconfig)
- [OidcConfig](#oidcconfig)
- [SessionBindingConfig](#sessionbindingconfig)
- [SmtpConfig](#smtpconfig)

---

## EmailPasswordConfig

Feature: `email-password` (default)

```rust
EmailPasswordConfig {
    min_password_length: usize,         // Default: 8
    require_email_verification: bool,   // Default: true
    hibp_check: bool,                   // Default: true — check passwords against HaveIBeenPwned
    password_policy: PasswordPolicyConfig {
        min_length: usize,              // Default: 8
        max_length: usize,              // Default: 128
        require_uppercase: bool,        // Default: false
        require_lowercase: bool,        // Default: false
        require_digit: bool,            // Default: false
        require_special: bool,          // Default: false
        disallow_common_passwords: bool,// Default: true
        password_history_count: u32,    // Default: 0 (disabled)
    },
}
```

**Notes:**
- `hibp_check` uses k-anonymity (only first 5 chars of SHA-1 hash sent to API) — safe for production
- `password_history_count > 0` prevents reuse of the N most recent passwords
- `disallow_common_passwords` checks against a built-in list of common passwords

---

## PasskeyConfig

Feature: `passkey`

```rust
PasskeyConfig {
    rp_id: String,      // Relying Party ID — typically your domain (e.g., "example.com")
    rp_origin: String,  // Full origin URL (e.g., "https://example.com")
    rp_name: String,    // Display name shown in authenticator prompts
}
```

**Notes:**
- `rp_id` must match the domain the browser sees — use `"localhost"` for local dev
- For subdomains, use the parent domain (e.g., `"example.com"` works for `app.example.com`)

---

## MfaConfig

Feature: `mfa`

```rust
MfaConfig {
    issuer: String,          // Default: "YAuth" — shown in authenticator apps
    backup_code_count: usize,// Default: 10
}
```

---

## OAuthConfig

Feature: `oauth`

```rust
OAuthConfig {
    providers: Vec<OAuthProviderConfig>,
}

OAuthProviderConfig {
    name: String,            // Provider name (e.g., "google", "github")
    client_id: String,
    client_secret: String,
    auth_url: String,        // Authorization endpoint
    token_url: String,       // Token endpoint
    userinfo_url: String,    // User info endpoint
    scopes: Vec<String>,     // OAuth scopes to request
    emails_url: Option<String>, // Fallback URL for email fetch (e.g., GitHub emails API)
}
```

**Notes:**
- `emails_url` is useful for providers like GitHub where the primary email may not be in the userinfo response

---

## BearerConfig

Feature: `bearer`

```rust
BearerConfig {
    jwt_secret: String,         // HMAC secret (required, non-empty)
    access_token_ttl: Duration, // Default: 15 minutes
    refresh_token_ttl: Duration,// Default: 30 days
    audience: Option<String>,   // RFC 8707 audience claim (optional)
}
```

**Notes:**
- Use a strong, random secret in production (at least 32 bytes)
- `audience` is validated on token verification if set

---

## MagicLinkConfig

Feature: `magic-link`

```rust
MagicLinkConfig {
    link_ttl: Duration,          // Default: 5 minutes
    allow_signup: bool,          // Default: true — create new users on first magic link login
    default_role: Option<String>,// Default: None — role for auto-created users
}
```

---

## OAuth2ServerConfig

Feature: `oauth2-server`

```rust
OAuth2ServerConfig {
    issuer: String,                      // Issuer URL (must match your public URL)
    authorization_code_ttl: Duration,    // Default: 60 seconds
    scopes_supported: Vec<String>,       // Default: [] — list of scopes your server supports
    allow_dynamic_registration: bool,    // Default: true
    device_code_ttl: Duration,           // Default: 600 seconds
    device_poll_interval: u32,           // Default: 5 seconds
    device_verification_uri: Option<String>,  // URI for device flow verification page
    consent_ui_url: Option<String>,      // URL for consent screen UI
}
```

---

## AccountLockoutConfig

Feature: `account-lockout`

```rust
AccountLockoutConfig {
    max_failed_attempts: u32,       // Default: 5
    lockout_duration: Duration,     // Default: 5 minutes
    exponential_backoff: bool,      // Default: true — doubles lockout each time
    max_lockout_duration: Duration, // Default: 24 hours (cap for exponential backoff)
    attempt_window: Duration,       // Default: 15 minutes — failed attempts reset after this
    auto_unlock: bool,              // Default: true — auto-unlock after lockout_duration expires
}
```

---

## WebhookConfig

Feature: `webhooks`

```rust
WebhookConfig {
    max_retries: u32,         // Default: 3
    retry_delay: Duration,    // Default: 30 seconds
    timeout: Duration,        // Default: 10 seconds — per-request timeout
    max_webhooks: usize,      // Default: 10 — max webhooks per account
}
```

**Notes:**
- Webhook payloads are signed with HMAC-SHA256 for verification
- Delivery history is tracked in `yauth_webhook_deliveries`

---

## OidcConfig

Feature: `oidc` (requires `bearer` + `oauth2-server`)

```rust
OidcConfig {
    issuer: String,                  // Must match OAuth2ServerConfig.issuer
    id_token_ttl: Duration,          // Default: 1 hour
    claims_supported: Vec<String>,   // Default: ["sub", "email", "email_verified", "name"]
}
```

---

## SessionBindingConfig

Part of `YAuthConfig` (always available):

```rust
SessionBindingConfig {
    bind_ip: bool,                      // Default: false
    bind_user_agent: bool,              // Default: false
    ip_mismatch_action: BindingAction,  // Default: Warn
    ua_mismatch_action: BindingAction,  // Default: Warn
}

enum BindingAction {
    Warn,       // Log mismatch but allow the request
    Invalidate, // Force re-authentication
}
```

**Notes:**
- `bind_ip: true` with `Invalidate` provides strong session fixation protection but breaks mobile users who switch networks frequently
- `Warn` mode is useful for audit logging without disrupting users

---

## SmtpConfig

Part of `YAuthConfig` (always available):

```rust
SmtpConfig {
    host: String,  // SMTP server hostname
    port: u16,     // SMTP port (typically 587 for TLS, 1025 for Mailpit)
    from: String,  // Sender email address
}
```
