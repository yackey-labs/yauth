// Package yauthcfg defines the declarative configuration schema for
// yauth-go and provides loaders/validators for it.
//
// Configuration may be supplied via YAML (yauth.yaml / yauth.yml) or
// TOML (yauth.toml). The loader picks a decoder based on file
// extension. Secrets are NEVER stored inline — every secret-bearing
// field is referenced by environment variable (*_env) or file path
// (*_path) so configs are safe to commit.
//
// Migration policy: Config does not run migrations. Production users
// run `yauth migrate` as a one-shot job (Kubernetes Job, ECS task,
// etc.) so multi-replica app rollouts cannot race AutoMigrate. The
// optional `database.auto_migrate` flag exists for development only
// and emits a stderr warning when active.
package yauthcfg

import "time"

// Config is the root configuration document.
type Config struct {
	Database  DatabaseConfig  `yaml:"database" toml:"database"`
	Server    ServerConfig    `yaml:"server" toml:"server"`
	Session   SessionConfig   `yaml:"session" toml:"session"`
	RateLimit RateLimitConfig `yaml:"rate_limit" toml:"rate_limit"`
	Telemetry TelemetryConfig `yaml:"telemetry" toml:"telemetry"`
	Plugins   PluginsConfig   `yaml:"plugins" toml:"plugins"`
}

// DatabaseConfig selects a driver and DSN. DSN may be a literal value
// or `env:VAR_NAME` to resolve from the environment at load time.
type DatabaseConfig struct {
	Driver string `yaml:"driver" toml:"driver"`
	DSN    string `yaml:"dsn" toml:"dsn"`

	// AutoMigrate, when true, runs Migrate inside NewFromConfig.
	// DEV/TEST ONLY — production must use `yauth migrate`. When set
	// the factory writes a warning to stderr.
	AutoMigrate bool `yaml:"auto_migrate" toml:"auto_migrate"`
}

// ServerConfig holds HTTP listener settings used by example binaries.
// The library itself returns an http.Handler; these fields are for
// consumers that want a turnkey listener.
type ServerConfig struct {
	Addr   string `yaml:"addr" toml:"addr"`
	Prefix string `yaml:"prefix" toml:"prefix"`
}

// SessionConfig mirrors the cookie/session knobs on yauth.YAuthConfig.
type SessionConfig struct {
	TTL            time.Duration `yaml:"ttl" toml:"ttl"`
	CookieName     string        `yaml:"cookie_name" toml:"cookie_name"`
	CookieSecure   bool          `yaml:"cookie_secure" toml:"cookie_secure"`
	CookieDomain   string        `yaml:"cookie_domain" toml:"cookie_domain"`
	CookiePath     string        `yaml:"cookie_path" toml:"cookie_path"`
	CookieSameSite string        `yaml:"cookie_same_site" toml:"cookie_same_site"`

	// BindIP enables IP-binding on cookie sessions: a request whose IP
	// does not match the session's stored IPAddress will be handled per
	// IPMismatchAction.
	BindIP bool `yaml:"bind_ip" toml:"bind_ip"`
	// BindUserAgent enables User-Agent binding on cookie sessions.
	BindUserAgent bool `yaml:"bind_user_agent" toml:"bind_user_agent"`
	// IPMismatchAction is "warn" (log + audit, allow) or "invalidate"
	// (delete session, return unauthorized). Empty defaults to "warn".
	IPMismatchAction string `yaml:"ip_mismatch_action" toml:"ip_mismatch_action"`
	// UAMismatchAction is "warn" or "invalidate". Empty defaults to "warn".
	UAMismatchAction string `yaml:"ua_mismatch_action" toml:"ua_mismatch_action"`
}

// RateLimitConfig is the per-operation rate-limit surface exposed in
// yauth.yaml. A zero Max disables the limiter for that op. Defaults are
// applied in NewFromConfig when the section is omitted.
type RateLimitConfig struct {
	Login          RateLimitRule `yaml:"login" toml:"login"`
	Register       RateLimitRule `yaml:"register" toml:"register"`
	ForgotPassword RateLimitRule `yaml:"forgot_password" toml:"forgot_password"`
	MagicLinkSend  RateLimitRule `yaml:"magic_link_send" toml:"magic_link_send"`
	UnlockRequest  RateLimitRule `yaml:"unlock_request" toml:"unlock_request"`
	MFAVerify      RateLimitRule `yaml:"mfa_verify" toml:"mfa_verify"`
}

// RateLimitRule is one (max, window) pair.
type RateLimitRule struct {
	Max    int           `yaml:"max" toml:"max"`
	Window time.Duration `yaml:"window" toml:"window"`
}

// TelemetryConfig wraps the OTel exporter settings.
type TelemetryConfig struct {
	Enabled      bool   `yaml:"enabled" toml:"enabled"`
	ServiceName  string `yaml:"service_name" toml:"service_name"`
	OTLPEndpoint string `yaml:"otlp_endpoint" toml:"otlp_endpoint"`
}

// PluginsConfig is the discriminated set of plugin sections. Each
// sub-section has an `enabled` flag; only enabled sections are wired
// by NewFromConfig.
type PluginsConfig struct {
	EmailPassword EmailPasswordPluginConfig `yaml:"email_password" toml:"email_password"`
	Bearer        BearerPluginConfig        `yaml:"bearer" toml:"bearer"`
	APIKey        APIKeyPluginConfig        `yaml:"api_key" toml:"api_key"`
	MagicLink     MagicLinkPluginConfig     `yaml:"magic_link" toml:"magic_link"`
	AccountLock   AccountLockPluginConfig   `yaml:"account_lock" toml:"account_lock"`
	Status        StatusPluginConfig        `yaml:"status" toml:"status"`
	Admin         AdminPluginConfig         `yaml:"admin" toml:"admin"`
	MFA           MFAPluginConfig           `yaml:"mfa" toml:"mfa"`
	Passkey       PasskeyPluginConfig       `yaml:"passkey" toml:"passkey"`
	OAuth         OAuthPluginConfig         `yaml:"oauth" toml:"oauth"`
	Webhooks      WebhooksPluginConfig      `yaml:"webhooks" toml:"webhooks"`
	AsymJWT       AsymJWTPluginConfig       `yaml:"asym_jwt" toml:"asym_jwt"`
	OIDC          OIDCPluginConfig          `yaml:"oidc" toml:"oidc"`
	OAuth2Server  OAuth2ServerPluginConfig  `yaml:"oauth2_server" toml:"oauth2_server"`
}

// EmailPasswordPluginConfig configures plugins/emailpassword.
type EmailPasswordPluginConfig struct {
	Enabled                  bool          `yaml:"enabled" toml:"enabled"`
	MinPasswordLength        int           `yaml:"min_password_length" toml:"min_password_length"`
	RequireEmailVerification bool          `yaml:"require_email_verification" toml:"require_email_verification"`
	RememberMeTTL            time.Duration `yaml:"remember_me_ttl" toml:"remember_me_ttl"`

	// HIBPCheck is a tri-state pointer: nil = default (true), &true =
	// enabled, &false = explicitly disabled. The pointer shape lets
	// operators turn the check off in air-gapped or test environments
	// without leaving the field dropped in YAML.
	HIBPCheck *bool `yaml:"hibp_check,omitempty" toml:"hibp_check,omitempty"`

	// PasswordPolicy mirrors auth/passwordpolicy.Policy.
	PasswordPolicy PasswordPolicyConfig `yaml:"password_policy" toml:"password_policy"`

	// VerificationLinkBaseURL is the base URL for email-verification
	// links delivered by the configured Mailer. Empty = raw token.
	VerificationLinkBaseURL string `yaml:"verification_link_base_url" toml:"verification_link_base_url"`
	// PasswordResetLinkBaseURL is the same for password-reset emails.
	PasswordResetLinkBaseURL string `yaml:"password_reset_link_base_url" toml:"password_reset_link_base_url"`

	// VerificationTokenTTL is the lifetime of email-verification
	// tokens. Defaults to 24h when zero.
	VerificationTokenTTL time.Duration `yaml:"verification_token_ttl" toml:"verification_token_ttl"`
	// PasswordResetTokenTTL is the lifetime of password-reset tokens.
	// Defaults to 1h when zero.
	PasswordResetTokenTTL time.Duration `yaml:"password_reset_token_ttl" toml:"password_reset_token_ttl"`
}

// PasswordPolicyConfig mirrors auth/passwordpolicy.Policy.
type PasswordPolicyConfig struct {
	MinLength      int  `yaml:"min_length" toml:"min_length"`
	MaxLength      int  `yaml:"max_length" toml:"max_length"`
	RequireUpper   bool `yaml:"require_upper" toml:"require_upper"`
	RequireLower   bool `yaml:"require_lower" toml:"require_lower"`
	RequireDigit   bool `yaml:"require_digit" toml:"require_digit"`
	RequireSpecial bool `yaml:"require_special" toml:"require_special"`
	DisallowCommon bool `yaml:"disallow_common" toml:"disallow_common"`
	HistoryCount   int  `yaml:"history_count" toml:"history_count"`
}

// BearerPluginConfig configures the JWT bearer token plugin.
type BearerPluginConfig struct {
	Enabled      bool          `yaml:"enabled" toml:"enabled"`
	JWTSecretEnv string        `yaml:"jwt_secret_env" toml:"jwt_secret_env"`
	AccessTTL    time.Duration `yaml:"access_ttl" toml:"access_ttl"`
	RefreshTTL   time.Duration `yaml:"refresh_ttl" toml:"refresh_ttl"`
	Issuer       string        `yaml:"issuer" toml:"issuer"`
}

// APIKeyPluginConfig configures the api-key plugin.
type APIKeyPluginConfig struct {
	Enabled    bool   `yaml:"enabled" toml:"enabled"`
	HeaderName string `yaml:"header_name" toml:"header_name"`
	Prefix     string `yaml:"prefix" toml:"prefix"`
}

// MagicLinkPluginConfig configures the magic-link plugin.
type MagicLinkPluginConfig struct {
	Enabled bool          `yaml:"enabled" toml:"enabled"`
	TTL     time.Duration `yaml:"ttl" toml:"ttl"`
}

// AccountLockPluginConfig configures the account-lockout plugin.
type AccountLockPluginConfig struct {
	Enabled         bool          `yaml:"enabled" toml:"enabled"`
	MaxAttempts     int           `yaml:"max_attempts" toml:"max_attempts"`
	LockoutDuration time.Duration `yaml:"lockout_duration" toml:"lockout_duration"`
}

// StatusPluginConfig configures the status plugin.
type StatusPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
}

// AdminPluginConfig configures the admin plugin.
type AdminPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
}

// MFAPluginConfig configures the MFA (TOTP + backup codes) plugin.
type MFAPluginConfig struct {
	Enabled          bool   `yaml:"enabled" toml:"enabled"`
	EncryptionKeyEnv string `yaml:"encryption_key_env" toml:"encryption_key_env"`
	Issuer           string `yaml:"issuer" toml:"issuer"`
}

// PasskeyPluginConfig configures the WebAuthn / passkey plugin.
type PasskeyPluginConfig struct {
	Enabled  bool   `yaml:"enabled" toml:"enabled"`
	RPID     string `yaml:"rp_id" toml:"rp_id"`
	RPName   string `yaml:"rp_name" toml:"rp_name"`
	RPOrigin string `yaml:"rp_origin" toml:"rp_origin"`
}

// OAuthProvider configures one upstream OAuth/OIDC provider.
type OAuthProvider struct {
	Enabled         bool     `yaml:"enabled" toml:"enabled"`
	ClientIDEnv     string   `yaml:"client_id_env" toml:"client_id_env"`
	ClientSecretEnv string   `yaml:"client_secret_env" toml:"client_secret_env"`
	RedirectURL     string   `yaml:"redirect_url" toml:"redirect_url"`
	Scopes          []string `yaml:"scopes" toml:"scopes"`
	IssuerURL       string   `yaml:"issuer_url" toml:"issuer_url"`
}

// OAuthPluginConfig configures the OAuth client plugin (multi-provider).
type OAuthPluginConfig struct {
	Enabled   bool                     `yaml:"enabled" toml:"enabled"`
	Providers map[string]OAuthProvider `yaml:"providers" toml:"providers"`
}

// WebhooksPluginConfig configures outbound webhook delivery.
type WebhooksPluginConfig struct {
	Enabled          bool   `yaml:"enabled" toml:"enabled"`
	DefaultSecretEnv string `yaml:"default_secret_env" toml:"default_secret_env"`
	MaxAttempts      int    `yaml:"max_attempts" toml:"max_attempts"`
}

// AsymJWTPluginConfig configures asymmetric (RS256/ES256) JWT signing.
type AsymJWTPluginConfig struct {
	Enabled        bool   `yaml:"enabled" toml:"enabled"`
	KeyType        string `yaml:"key_type" toml:"key_type"` // "rs256" | "es256"
	PrivateKeyPath string `yaml:"private_key_path" toml:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path" toml:"public_key_path"`
	KeyID          string `yaml:"key_id" toml:"key_id"`
}

// OIDCPluginConfig configures the OIDC discovery + JWKS plugin.
type OIDCPluginConfig struct {
	Enabled bool   `yaml:"enabled" toml:"enabled"`
	Issuer  string `yaml:"issuer" toml:"issuer"`
}

// OAuth2ServerPluginConfig configures the embedded RFC 6749 server.
type OAuth2ServerPluginConfig struct {
	Enabled              bool          `yaml:"enabled" toml:"enabled"`
	AuthorizationCodeTTL time.Duration `yaml:"authorization_code_ttl" toml:"authorization_code_ttl"`
	DeviceCodeTTL        time.Duration `yaml:"device_code_ttl" toml:"device_code_ttl"`
	RequirePKCE          bool          `yaml:"require_pkce" toml:"require_pkce"`
}

// Default returns a Config populated with sensible development defaults
// and email_password enabled. Used by `yauth init`.
func Default() *Config {
	return &Config{
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "file:yauth.db?_pragma=foreign_keys(1)",
		},
		Server: ServerConfig{
			Addr:   ":3000",
			Prefix: "/api/auth",
		},
		Session: SessionConfig{
			TTL:            30 * 24 * time.Hour,
			CookieName:     "yauth_session",
			CookieSecure:   false,
			CookiePath:     "/",
			CookieSameSite: "lax",
		},
		Telemetry: TelemetryConfig{
			Enabled:      false,
			ServiceName:  "yauth",
			OTLPEndpoint: "http://localhost:4317",
		},
		Plugins: PluginsConfig{
			EmailPassword: EmailPasswordPluginConfig{
				Enabled:           true,
				MinPasswordLength: 12,
			},
		},
	}
}
