use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Controls the `Domain` attribute on session cookies.
///
/// - `Auto` (default): No `Domain` attribute — the cookie is scoped to the exact
///   origin only. This is the most secure default and prevents subdomain leakage
///   (e.g. PR preview deployments won't receive production cookies).
/// - `Explicit("example.com")`: Sets `Domain=example.com`. Use only when cookies
///   must be shared across subdomains (e.g. API on `api.example.com`, frontend
///   on `app.example.com`). **Warning**: all subdomains will receive this cookie.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CookieDomainPolicy {
    /// Set `Domain` to the given value. Use for cross-subdomain cookie sharing.
    Explicit(String),
    /// No `Domain` attribute — exact origin scoping (most secure).
    #[default]
    Auto,
}

impl CookieDomainPolicy {
    /// Returns the domain string to set on the cookie, or `None` for exact-origin scoping.
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Explicit(d) if !d.is_empty() => Some(d.as_str()),
            _ => None,
        }
    }
}

/// Backwards-compatible: accepts `Option<String>` (null/string) or `CookieDomainPolicy`
/// from JSON. `null` or missing → `Auto`, `"example.com"` → `Explicit("example.com")`,
/// `""` → `Auto`.
impl From<Option<String>> for CookieDomainPolicy {
    fn from(opt: Option<String>) -> Self {
        match opt {
            Some(s) if !s.is_empty() => Self::Explicit(s),
            _ => Self::Auto,
        }
    }
}

/// Core configuration for the yauth authentication system.
///
/// Controls session behavior, cookie settings, CORS origins, and global
/// feature switches. Pass this as the second argument to `YAuthBuilder::new()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YAuthConfig {
    /// Base URL of your application (e.g., `"https://myapp.example.com"`).
    /// Used in email templates and OAuth redirect URLs.
    pub base_url: String,
    /// Name of the session cookie (default: `"session"`).
    pub session_cookie_name: String,
    /// How long sessions last before expiring (default: 7 days).
    #[serde(with = "duration_secs")]
    pub session_ttl: Duration,
    /// Cookie domain policy. Defaults to `Auto` (no `Domain` attribute — cookie
    /// scopes to the exact origin, which is the most secure default).
    /// Set to `Explicit("example.com")` only when you need cookies shared across
    /// subdomains (e.g. `app.example.com` + `api.example.com`).
    ///
    /// **Warning**: Setting a `Domain` attribute causes the cookie to be sent to ALL
    /// subdomains, which can cause session collisions in PR preview deployments
    /// (e.g. `pr-5.app.example.com` receives the production cookie).
    #[serde(default)]
    pub cookie_domain: CookieDomainPolicy,
    /// Set to `true` in production to add the `Secure` flag to cookies (HTTPS only).
    pub secure_cookies: bool,
    /// CORS allowed origins. Must include your frontend URL for cookie-based auth to work.
    pub trusted_origins: Vec<String>,
    /// SMTP configuration for sending emails (verification, password reset, magic links).
    /// `None` disables email sending — verification and reset endpoints will return errors.
    pub smtp: Option<SmtpConfig>,
    /// When true, the first registered user automatically gets the "admin" role.
    #[serde(default)]
    pub auto_admin_first_user: bool,
    /// Optional "remember me" session TTL. When set, login endpoints accept a
    /// `remember_me` flag and use this longer TTL instead of `session_ttl`.
    /// Use when you want short default sessions (e.g., 24h) with opt-in long sessions (e.g., 30d).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remember_me_ttl: Option<DurationSecs>,
    /// Session binding configuration. Use when you need to detect session hijacking
    /// by binding sessions to client IP and/or User-Agent.
    #[serde(default)]
    pub session_binding: SessionBindingConfig,
    /// When false, all signup/registration endpoints return 403 Forbidden.
    /// This is a global kill-switch that applies across all plugins (email-password,
    /// magic-link, OAuth, etc.). Defaults to true (signups allowed).
    #[serde(default = "default_true")]
    pub allow_signups: bool,
    /// PostgreSQL schema for yauth tables. Defaults to `"public"`.
    /// Set to a different schema (e.g. `"auth"`) to isolate yauth tables
    /// from your application tables. The schema will be created if it doesn't exist.
    #[serde(default = "default_schema")]
    pub db_schema: String,
}

fn default_true() -> bool {
    true
}

fn default_schema() -> String {
    "public".into()
}

impl Default for YAuthConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:3000".into(),
            session_cookie_name: "session".into(),
            session_ttl: Duration::from_secs(7 * 24 * 3600),
            cookie_domain: CookieDomainPolicy::Auto,
            secure_cookies: false,
            trusted_origins: vec!["http://localhost:3000".into()],
            smtp: None,
            auto_admin_first_user: false,
            remember_me_ttl: None,
            session_binding: SessionBindingConfig::default(),
            allow_signups: true,
            db_schema: "public".into(),
        }
    }
}

/// A Duration wrapper that serializes as seconds. Use for optional duration config fields.
#[derive(Debug, Clone, Copy)]
pub struct DurationSecs(pub Duration);

impl DurationSecs {
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

impl Serialize for DurationSecs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0.as_secs())
    }
}

impl<'de> Deserialize<'de> for DurationSecs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let secs = u64::deserialize(deserializer)?;
        Ok(DurationSecs(Duration::from_secs(secs)))
    }
}

/// Session binding — detect session hijacking by checking IP and/or User-Agent.
/// Use `Warn` to log mismatches without disrupting users, or `Invalidate` to
/// force re-authentication when the client fingerprint changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBindingConfig {
    pub bind_ip: bool,
    pub bind_user_agent: bool,
    #[serde(default = "default_binding_action")]
    pub ip_mismatch_action: BindingAction,
    #[serde(default = "default_binding_action")]
    pub ua_mismatch_action: BindingAction,
}

fn default_binding_action() -> BindingAction {
    BindingAction::Warn
}

impl Default for SessionBindingConfig {
    fn default() -> Self {
        Self {
            bind_ip: false,
            bind_user_agent: false,
            ip_mismatch_action: BindingAction::Warn,
            ua_mismatch_action: BindingAction::Warn,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BindingAction {
    Warn,
    Invalidate,
}

mod duration_secs {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

/// SMTP server configuration for sending transactional emails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname (e.g., `"smtp.example.com"`).
    pub host: String,
    /// SMTP server port (typically 587 for STARTTLS or 465 for implicit TLS).
    pub port: u16,
    /// Sender email address for all outgoing emails (e.g., `"auth@example.com"`).
    pub from: String,
}

/// Per-operation rate limit configuration.
///
/// Controls how many requests are allowed within a sliding time window.
/// Set to `None` on `EmailPasswordConfig` to disable rate limiting entirely
/// (useful for testing). The default preserves existing behavior: 10 requests
/// per 60-second window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 10,
            window_secs: 60,
        }
    }
}

/// Configuration for the email/password authentication plugin.
///
/// Controls password requirements, email verification, breach checking, and rate limiting.
#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailPasswordConfig {
    /// Minimum password length (default: 8). Applied before policy checks.
    pub min_password_length: usize,
    /// Require users to verify their email before login (default: true).
    pub require_email_verification: bool,
    /// Check passwords against HaveIBeenPwned via k-anonymity API (default: true).
    /// Fails open — if the HIBP API is unreachable, registration proceeds.
    pub hibp_check: bool,
    /// Additional password complexity requirements (uppercase, digits, etc.).
    #[serde(default)]
    pub password_policy: PasswordPolicyConfig,
    /// Per-operation rate limit. `Some(config)` enables rate limiting with the
    /// given parameters; `None` disables rate limiting entirely. Defaults to
    /// 10 requests per 60-second window.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: Option<RateLimitConfig>,
}

#[cfg(feature = "email-password")]
fn default_rate_limit() -> Option<RateLimitConfig> {
    Some(RateLimitConfig::default())
}

#[cfg(feature = "email-password")]
impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            require_email_verification: true,
            hibp_check: true,
            password_policy: PasswordPolicyConfig::default(),
            rate_limit: Some(RateLimitConfig::default()),
        }
    }
}

/// Password policy configuration for enforcing password complexity requirements.
/// Use when you need stricter password rules beyond minimum length and HIBP checking.
#[cfg(feature = "email-password")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicyConfig {
    /// Minimum password length enforced by the policy validator (default: 8).
    #[serde(default = "default_min_password_length")]
    pub min_length: usize,
    /// Maximum password length (default: 128). Prevents denial-of-service via very long passwords.
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    /// Reject common passwords (top 10,000 from SecLists).
    pub disallow_common_passwords: bool,
    /// Number of previous passwords to remember and prevent reuse. 0 = disabled.
    pub password_history_count: u32,
}

#[cfg(feature = "email-password")]
fn default_min_password_length() -> usize {
    8
}

#[cfg(feature = "email-password")]
impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            disallow_common_passwords: true,
            password_history_count: 0,
        }
    }
}

/// Configuration for the WebAuthn passkey plugin.
///
/// The relying party (RP) values must match your domain — WebAuthn credentials
/// are bound to the RP ID and will not work if these don't match the browser's origin.
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyConfig {
    /// Relying party ID — typically your domain without port (e.g., `"myapp.example.com"`).
    pub rp_id: String,
    /// Relying party origin — full origin including scheme (e.g., `"https://myapp.example.com"`).
    pub rp_origin: String,
    /// Human-readable relying party name shown in authenticator prompts (e.g., `"My App"`).
    pub rp_name: String,
}

/// Configuration for the MFA (TOTP + backup codes) plugin.
#[cfg(feature = "mfa")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    /// Issuer name shown in authenticator apps (e.g., `"My App"` → appears as `My App: user@example.com`).
    pub issuer: String,
    /// Number of one-time backup codes generated when MFA is enabled (default: 10).
    pub backup_code_count: usize,
}

#[cfg(feature = "mfa")]
impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            issuer: "YAuth".into(),
            backup_code_count: 10,
        }
    }
}

/// Configuration for the OAuth2 client plugin (sign in with Google, GitHub, etc.).
#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// List of configured OAuth2 providers.
    pub providers: Vec<OAuthProviderConfig>,
}

/// Configuration for a single OAuth2 provider.
#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// Provider name used in URLs (e.g., `"google"` → `/oauth/google/authorize`).
    pub name: String,
    /// OAuth2 client ID from the provider's developer console.
    pub client_id: String,
    /// OAuth2 client secret from the provider's developer console.
    pub client_secret: String,
    /// Authorization endpoint URL (e.g., `"https://accounts.google.com/o/oauth2/v2/auth"`).
    pub auth_url: String,
    /// Token endpoint URL (e.g., `"https://oauth2.googleapis.com/token"`).
    pub token_url: String,
    /// Userinfo endpoint URL for fetching the authenticated user's profile.
    pub userinfo_url: String,
    /// OAuth2 scopes to request (e.g., `["openid", "email", "profile"]`).
    pub scopes: Vec<String>,
    /// Optional URL to fetch user emails (e.g. GitHub's /user/emails).
    /// Used as fallback when the userinfo endpoint doesn't return an email.
    #[serde(default)]
    pub emails_url: Option<String>,
}

/// Configuration for the magic link (passwordless email login) plugin.
#[cfg(feature = "magic-link")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkConfig {
    /// How long magic links remain valid (default: 5 minutes).
    #[serde(with = "duration_secs")]
    pub link_ttl: Duration,
    /// Allow new accounts to be created via magic link (default: true).
    /// When false, only existing users can log in with magic links.
    pub allow_signup: bool,
    /// Role assigned to users created via magic link signup. `None` uses the system default.
    pub default_role: Option<String>,
}

#[cfg(feature = "magic-link")]
impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            link_ttl: Duration::from_secs(5 * 60),
            allow_signup: true,
            default_role: None,
        }
    }
}

#[cfg(feature = "oauth2-server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ServerConfig {
    /// Issuer URL for the authorization server (used in AS metadata).
    pub issuer: String,
    /// Authorization code TTL (default: 60 seconds per spec recommendation).
    #[serde(with = "duration_secs")]
    pub authorization_code_ttl: Duration,
    /// Available scopes that clients can request.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Whether to allow dynamic client registration (POST /register).
    #[serde(default)]
    pub allow_dynamic_registration: bool,
    /// Device code TTL (default: 600 seconds / 10 minutes per RFC 8628).
    #[serde(default = "default_device_code_ttl", with = "duration_secs")]
    pub device_code_ttl: Duration,
    /// Minimum polling interval in seconds for device code grant (default: 5).
    #[serde(default = "default_device_poll_interval")]
    pub device_poll_interval: u32,
    /// Verification URI for device authorization. Defaults to `{issuer}/oauth/device`.
    #[serde(default)]
    pub device_verification_uri: Option<String>,
    /// URL of the consent UI page. When set, GET /oauth/authorize redirects here
    /// with all query params forwarded. When None, returns JSON (API-only mode).
    #[serde(default)]
    pub consent_ui_url: Option<String>,
}

#[cfg(feature = "oauth2-server")]
fn default_device_code_ttl() -> Duration {
    Duration::from_secs(600)
}

#[cfg(feature = "oauth2-server")]
fn default_device_poll_interval() -> u32 {
    5
}

#[cfg(feature = "oauth2-server")]
impl Default for OAuth2ServerConfig {
    fn default() -> Self {
        Self {
            issuer: "http://localhost:3000".into(),
            authorization_code_ttl: Duration::from_secs(60),
            scopes_supported: vec![],
            allow_dynamic_registration: true,
            device_code_ttl: Duration::from_secs(600),
            device_poll_interval: 5,
            device_verification_uri: None,
            consent_ui_url: None,
        }
    }
}

/// Configuration for the bearer token (JWT) plugin.
///
/// Access tokens are short-lived JWTs; refresh tokens are long-lived and stored
/// in the database with token family tracking for reuse detection.
#[cfg(feature = "bearer")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BearerConfig {
    /// Secret key for signing and verifying JWTs (HMAC-SHA256).
    /// Use a cryptographically random string (e.g., 32+ bytes, base64-encoded).
    pub jwt_secret: String,
    /// Access token lifetime (typically short, e.g., 15 minutes).
    #[serde(with = "duration_secs")]
    pub access_token_ttl: Duration,
    /// Refresh token lifetime (typically long, e.g., 30 days).
    #[serde(with = "duration_secs")]
    pub refresh_token_ttl: Duration,
    /// Optional audience claim for JWT tokens (resource server URL per RFC 8707).
    #[serde(default)]
    pub audience: Option<String>,
}

/// Account lockout configuration for brute-force protection.
/// Use when you need persistent per-account lockout beyond rate limiting.
/// Rate limiting is per-IP/operation; lockout is per-account across all IPs.
#[cfg(feature = "account-lockout")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLockoutConfig {
    /// Number of failed attempts before locking the account.
    pub max_failed_attempts: u32,
    /// Base lockout duration in seconds.
    #[serde(with = "duration_secs")]
    pub lockout_duration: Duration,
    /// Double the lockout duration on each subsequent lockout.
    pub exponential_backoff: bool,
    /// Maximum lockout duration in seconds (cap for exponential backoff).
    #[serde(with = "duration_secs")]
    pub max_lockout_duration: Duration,
    /// Window in seconds to count failed attempts.
    #[serde(with = "duration_secs")]
    pub attempt_window: Duration,
    /// Automatically unlock accounts after the lockout duration expires.
    pub auto_unlock: bool,
}

#[cfg(feature = "account-lockout")]
impl Default for AccountLockoutConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(300),
            exponential_backoff: true,
            max_lockout_duration: Duration::from_secs(86400),
            attempt_window: Duration::from_secs(900),
            auto_unlock: true,
        }
    }
}

/// Webhook configuration for receiving HTTP callbacks on auth events.
/// Use when external systems need real-time notifications of auth events
/// (user registered, login, ban, etc.) without polling.
#[cfg(feature = "webhooks")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub max_retries: u32,
    #[serde(with = "duration_secs")]
    pub retry_delay: Duration,
    #[serde(with = "duration_secs")]
    pub timeout: Duration,
    pub max_webhooks: usize,
}

#[cfg(feature = "webhooks")]
impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            max_webhooks: 10,
        }
    }
}

/// OIDC configuration for running yauth as a full OpenID Connect Provider.
/// Use when you need id_token issuance, `/.well-known/openid-configuration`,
/// and `/userinfo` endpoint — making yauth a standards-compliant identity provider.
/// Requires both `bearer` (for JWT signing) and `oauth2-server` (for authorization flows).
#[cfg(feature = "oidc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    #[serde(with = "duration_secs")]
    pub id_token_ttl: Duration,
    #[serde(default = "default_oidc_claims")]
    pub claims_supported: Vec<String>,
}

#[cfg(feature = "oidc")]
fn default_oidc_claims() -> Vec<String> {
    vec![
        "sub".into(),
        "email".into(),
        "email_verified".into(),
        "name".into(),
    ]
}

#[cfg(feature = "oidc")]
impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: "http://localhost:3000".into(),
            id_token_ttl: Duration::from_secs(3600),
            claims_supported: default_oidc_claims(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let config = YAuthConfig::default();
        assert_eq!(config.session_cookie_name, "session");
        assert_eq!(config.session_ttl, Duration::from_secs(604800));
        assert!(!config.secure_cookies);
        assert!(config.smtp.is_none());
        assert!(!config.auto_admin_first_user);
        assert!(config.allow_signups);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = YAuthConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: YAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_url, config.base_url);
        assert_eq!(parsed.session_ttl, config.session_ttl);
    }

    #[test]
    fn allow_signups_defaults_to_true_when_missing() {
        let json = r#"{"base_url":"http://localhost:3000","session_cookie_name":"session","session_ttl":604800,"cookie_domain":null,"secure_cookies":false,"trusted_origins":["http://localhost:3000"],"smtp":null,"auto_admin_first_user":false,"session_binding":{"bind_ip":false,"bind_user_agent":false,"ip_mismatch_action":"Warn","ua_mismatch_action":"Warn"}}"#;
        let config: YAuthConfig = serde_json::from_str(json).unwrap();
        assert!(config.allow_signups);
    }

    #[test]
    fn allow_signups_can_be_set_to_false() {
        let config = YAuthConfig {
            allow_signups: false,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: YAuthConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.allow_signups);
    }

    #[test]
    fn duration_serde_as_seconds() {
        let config = YAuthConfig {
            session_ttl: Duration::from_secs(3600),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("3600"));
        let parsed: YAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_ttl, Duration::from_secs(3600));
    }

    #[cfg(feature = "email-password")]
    #[test]
    fn email_password_config_defaults() {
        let config = EmailPasswordConfig::default();
        assert_eq!(config.min_password_length, 8);
        assert!(config.require_email_verification);
        assert!(config.hibp_check);
    }

    #[cfg(feature = "mfa")]
    #[test]
    fn mfa_config_defaults() {
        let config = MfaConfig::default();
        assert_eq!(config.issuer, "YAuth");
        assert_eq!(config.backup_code_count, 10);
    }

    // --- Session Binding Config ---

    #[test]
    fn session_binding_config_defaults() {
        let config = SessionBindingConfig::default();
        assert!(!config.bind_ip);
        assert!(!config.bind_user_agent);
        assert_eq!(config.ip_mismatch_action, BindingAction::Warn);
        assert_eq!(config.ua_mismatch_action, BindingAction::Warn);
    }

    #[test]
    fn session_binding_config_serialization_roundtrip() {
        let config = SessionBindingConfig {
            bind_ip: true,
            bind_user_agent: true,
            ip_mismatch_action: BindingAction::Invalidate,
            ua_mismatch_action: BindingAction::Warn,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SessionBindingConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.bind_ip);
        assert!(parsed.bind_user_agent);
        assert_eq!(parsed.ip_mismatch_action, BindingAction::Invalidate);
        assert_eq!(parsed.ua_mismatch_action, BindingAction::Warn);
    }

    #[test]
    fn binding_action_equality() {
        assert_ne!(BindingAction::Warn, BindingAction::Invalidate);
        assert_eq!(BindingAction::Warn, BindingAction::Warn);
        assert_eq!(BindingAction::Invalidate, BindingAction::Invalidate);
    }

    // --- DurationSecs / Remember Me ---

    #[test]
    fn duration_secs_serialization() {
        let ds = DurationSecs(Duration::from_secs(2592000));
        let json = serde_json::to_string(&ds).unwrap();
        assert_eq!(json, "2592000");
    }

    #[test]
    fn duration_secs_deserialization() {
        let ds: DurationSecs = serde_json::from_str("2592000").unwrap();
        assert_eq!(ds.0, Duration::from_secs(2592000));
    }

    #[test]
    fn duration_secs_as_duration() {
        let ds = DurationSecs(Duration::from_secs(42));
        assert_eq!(ds.as_duration(), Duration::from_secs(42));
    }

    #[test]
    fn yauth_config_with_remember_me_ttl_roundtrip() {
        let config = YAuthConfig {
            remember_me_ttl: Some(DurationSecs(Duration::from_secs(2592000))),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("2592000"));
        let parsed: YAuthConfig = serde_json::from_str(&json).unwrap();
        let ttl = parsed
            .remember_me_ttl
            .expect("remember_me_ttl should be Some");
        assert_eq!(ttl.0, Duration::from_secs(2592000));
    }

    #[test]
    fn yauth_config_remember_me_ttl_none_omitted() {
        let config = YAuthConfig {
            remember_me_ttl: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("remember_me_ttl"));
    }

    // --- Password Policy Config ---

    #[cfg(feature = "email-password")]
    #[test]
    fn password_policy_config_defaults() {
        let config = PasswordPolicyConfig::default();
        assert_eq!(config.min_length, 8);
        assert_eq!(config.max_length, 128);
        assert!(!config.require_uppercase);
        assert!(!config.require_lowercase);
        assert!(!config.require_digit);
        assert!(!config.require_special);
        assert!(config.disallow_common_passwords);
        assert_eq!(config.password_history_count, 0);
    }

    // --- Account Lockout Config ---

    #[cfg(feature = "account-lockout")]
    #[test]
    fn account_lockout_config_defaults() {
        let config = AccountLockoutConfig::default();
        assert_eq!(config.max_failed_attempts, 5);
        assert_eq!(config.lockout_duration, Duration::from_secs(300));
        assert!(config.exponential_backoff);
        assert_eq!(config.max_lockout_duration, Duration::from_secs(86400));
        assert_eq!(config.attempt_window, Duration::from_secs(900));
        assert!(config.auto_unlock);
    }

    #[cfg(feature = "account-lockout")]
    #[test]
    fn account_lockout_config_serialization_roundtrip() {
        let config = AccountLockoutConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AccountLockoutConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_failed_attempts, config.max_failed_attempts);
        assert_eq!(parsed.lockout_duration, config.lockout_duration);
        assert_eq!(parsed.exponential_backoff, config.exponential_backoff);
        assert_eq!(parsed.max_lockout_duration, config.max_lockout_duration);
        assert_eq!(parsed.attempt_window, config.attempt_window);
        assert_eq!(parsed.auto_unlock, config.auto_unlock);
    }

    // --- Webhook Config ---

    #[cfg(feature = "webhooks")]
    #[test]
    fn webhook_config_defaults() {
        let config = WebhookConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(30));
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.max_webhooks, 10);
    }

    // --- OIDC Config ---

    #[cfg(feature = "oidc")]
    #[test]
    fn oidc_config_defaults() {
        let config = OidcConfig::default();
        assert_eq!(config.issuer, "http://localhost:3000");
        assert_eq!(config.id_token_ttl, Duration::from_secs(3600));
        assert!(config.claims_supported.contains(&"sub".to_string()));
        assert!(config.claims_supported.contains(&"email".to_string()));
        assert!(
            config
                .claims_supported
                .contains(&"email_verified".to_string())
        );
        assert!(config.claims_supported.contains(&"name".to_string()));
        assert_eq!(config.claims_supported.len(), 4);
    }
}
