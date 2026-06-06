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
	Mailer    MailerConfig    `yaml:"mailer" toml:"mailer"`
	Plugins   PluginsConfig   `yaml:"plugins" toml:"plugins"`
	Cache     CacheConfig     `yaml:"cache" toml:"cache"`
}

// CacheConfig configures the optional read-cache decorator that wraps the
// primary repository. When Enabled is false the rest of the section is
// ignored. Today only Provider="redis" is implemented; future providers
// (memcached, in-process LRU) would slot in here.
type CacheConfig struct {
	Enabled  bool   `yaml:"enabled" toml:"enabled"`
	Provider string `yaml:"provider" toml:"provider"`

	// RedisAddr is the host:port the Redis decorator dials. Required
	// when Provider="redis".
	RedisAddr string `yaml:"redis_addr" toml:"redis_addr"`
	// RedisPasswordEnv is the env var holding the Redis AUTH password.
	// Empty string means no AUTH.
	RedisPasswordEnv string `yaml:"redis_password_env" toml:"redis_password_env"`
	// RedisDB is the numeric Redis logical database (0-15). Defaults to 0.
	RedisDB int `yaml:"redis_db" toml:"redis_db"`

	// KeyPrefix is prepended to every cache key. Defaults to "yauth:".
	// Useful when multiple yauth tenants share a Redis instance.
	KeyPrefix string `yaml:"key_prefix" toml:"key_prefix"`

	// DisableNegativeCache turns off short-TTL negative caching. Negative
	// caching mitigates enumeration thrash on hot read paths but masks
	// fresh writes for up to 60s.
	DisableNegativeCache bool `yaml:"disable_negative_cache" toml:"disable_negative_cache"`
}

// DatabaseConfig selects a driver and DSN. DSN may be a literal value
// or `env:VAR_NAME` to resolve from the environment at load time.
type DatabaseConfig struct {
	Driver string `yaml:"driver" toml:"driver"`
	DSN    string `yaml:"dsn" toml:"dsn"`

	// Schema selects a Postgres schema for table isolation. Empty (the
	// default) means "public". When set, the value is appended to the
	// DSN as `search_path=<schema>,public` so every query falls back
	// through the public schema. Ignored for non-Postgres drivers.
	Schema string `yaml:"schema" toml:"schema"`

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

	// BaseURL is the absolute URL the public API is reachable at,
	// e.g. "https://app.example.com". Used by plugins that build
	// outbound links (verification emails, password-reset links, OIDC
	// issuer, etc.) when they have no local override.
	BaseURL string `yaml:"base_url" toml:"base_url"`

	// AllowSignups controls whether /register accepts new accounts.
	// Defaults to true; flip to false to require admin-driven invites.
	AllowSignups *bool `yaml:"allow_signups,omitempty" toml:"allow_signups,omitempty"`

	// AutoAdminFirstUser, when true, promotes the first registered
	// user to role "admin" automatically. Subsequent users register
	// with the default role.
	AutoAdminFirstUser bool `yaml:"auto_admin_first_user" toml:"auto_admin_first_user"`

	// CORS controls cross-origin behaviour of the mounted Router. When
	// AllowedOrigins is empty the CORS middleware is not installed.
	CORS CORSConfig `yaml:"cors" toml:"cors"`
}

// CORSConfig configures the cross-origin middleware. Empty AllowedOrigins
// disables CORS entirely.
type CORSConfig struct {
	// AllowedOrigins is the list of origins allowed to call the API.
	// Use "*" to allow any origin (incompatible with AllowCredentials=true).
	AllowedOrigins []string `yaml:"allowed_origins" toml:"allowed_origins"`
	// AllowedMethods is the methods echoed back in
	// Access-Control-Allow-Methods. Defaults to a sensible set when empty.
	AllowedMethods []string `yaml:"allowed_methods" toml:"allowed_methods"`
	// AllowedHeaders is the headers echoed back in
	// Access-Control-Allow-Headers. Defaults to "Content-Type, Authorization".
	AllowedHeaders []string `yaml:"allowed_headers" toml:"allowed_headers"`
	// AllowCredentials sets Access-Control-Allow-Credentials. When true
	// AllowedOrigins must not contain "*"; the middleware reflects the
	// request's Origin instead.
	AllowCredentials bool `yaml:"allow_credentials" toml:"allow_credentials"`
	// MaxAge sets Access-Control-Max-Age on preflight responses.
	MaxAge time.Duration `yaml:"max_age" toml:"max_age"`
}

// MailerConfig selects an outbound mailer for the host. Provider "logging"
// (the default) is a DEV stand-in that writes the would-be email — including
// verification/reset/magic-link tokens — to the log and sends nothing; use
// "smtp" in production. See `yauth docs mailer`.
type MailerConfig struct {
	Provider string     `yaml:"provider" toml:"provider" enum:"logging,smtp" doc:"Outbound mailer. 'logging' (default) is DEV ONLY: it logs the would-be email body — including single-use verification/reset/magic-link bearer tokens — and sends NO real email. Set 'smtp' for production. See 'yauth docs mailer'."`
	From     string     `yaml:"from" toml:"from" doc:"Envelope/From address for outbound mail. Required when provider=smtp."`
	SMTP     SMTPConfig `yaml:"smtp" toml:"smtp" doc:"SMTP connection settings (used when provider=smtp)."`
}

// SMTPConfig holds SMTP connection details. Username/password are
// resolved from environment variables to keep the config file safe to
// commit.
type SMTPConfig struct {
	Host        string `yaml:"host" toml:"host" doc:"SMTP server hostname (required when provider=smtp)."`
	Port        int    `yaml:"port" toml:"port" doc:"SMTP server port, e.g. 587 (required when provider=smtp)."`
	UsernameEnv string `yaml:"username_env" toml:"username_env" doc:"Name of the env var holding the SMTP username (the value is read at runtime; the var name, not the secret, lives in config)."`
	PasswordEnv string `yaml:"password_env" toml:"password_env" doc:"Name of the env var holding the SMTP password."`
	TLS         bool   `yaml:"tls" toml:"tls" doc:"Use TLS for the SMTP connection."`
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
	// OTLPProtocol selects the OTLP transport when yauth manages the
	// exporter: "grpc" (default) or "http" (the OTLP/HTTP receiver, usually
	// port 4318). Empty falls back to OTEL_EXPORTER_OTLP_PROTOCOL. Set "http"
	// when your collector only exposes the OTLP/HTTP receiver.
	OTLPProtocol string `yaml:"otlp_protocol" toml:"otlp_protocol"`
	// HTTPMiddleware toggles yauth's own HTTP server-span middleware. It
	// defaults to true; set it to false when the application already wraps
	// its handler tree in an HTTP instrumentation (otelhttp or equivalent)
	// to avoid emitting a second server span per request.
	HTTPMiddleware *bool `yaml:"http_middleware" toml:"http_middleware"`
	// ManageProvider controls whether yauth stands up its own OTLP exporter
	// and registers the global TracerProvider (true, the default), or simply
	// records into the TracerProvider the host application has already
	// configured (false). Set it false when your app owns OpenTelemetry
	// setup — yauth then participates in your existing pipeline instead of
	// opening a second export stream, per OTel's guidance that only the
	// application configures the SDK. OTLPEndpoint/OTLPProtocol are ignored
	// in attach mode.
	ManageProvider *bool `yaml:"manage_provider" toml:"manage_provider"`
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

	// BootstrapAdmin deterministically provisions an admin user at startup
	// when no admin exists yet — the secure default for seeding the first
	// administrator (replaces auto_admin_first_user, which promotes whoever
	// registers first publicly). See BootstrapAdminConfig.
	BootstrapAdmin BootstrapAdminConfig `yaml:"bootstrap_admin" toml:"bootstrap_admin"`

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

// BootstrapAdminConfig provisions the first administrator deterministically
// at startup. When Enabled and no admin user exists yet, NewFromConfig creates
// a user with role "admin" and must_change_password=true. If Password is set,
// it is used (and never logged); otherwise a strong random password satisfying
// the configured policy is generated and logged exactly once at creation
// (WARN). The operation is idempotent and multi-replica safe: it relies on the
// email unique constraint so a restart, or two replicas racing, never creates
// a duplicate or re-logs the password.
//
// Prefer this over auto_admin_first_user. The two are mutually exclusive in
// practice: a bootstrapped admin makes a user exist, so auto_admin_first_user
// (which only promotes when NO user exists) never fires afterward.
type BootstrapAdminConfig struct {
	// Enabled turns on startup admin provisioning.
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// Email is the admin account's email address (required when Enabled).
	Email string `yaml:"email" toml:"email"`
	// Password, when set, is the admin's initial password. It is used as-is
	// and NEVER logged. Leave empty to have yauth generate and log a strong
	// random password once at creation. The user must change it on first
	// login either way (must_change_password is set).
	Password string `yaml:"password,omitempty" toml:"password,omitempty"`
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

// APIKeyPluginConfig configures the api-key plugin. The credential is always
// read from the fixed X-Api-Key header.
type APIKeyPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// Prefix is the leading identifier in "<prefix>_<8hex>_<32hex>". Default "yak".
	Prefix string `yaml:"prefix" toml:"prefix"`
	// MaxKeysPerUser caps how many keys one user may own. Default 25.
	MaxKeysPerUser int `yaml:"max_keys_per_user" toml:"max_keys_per_user"`
	// HeaderName is accepted for backward compatibility but ignored — the
	// credential header is always X-Api-Key.
	// Deprecated: ignored; will be removed in a future release.
	HeaderName string `yaml:"header_name,omitempty" toml:"header_name,omitempty"`
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

	// MaxLockoutDuration caps the per-step LockoutDurations[i] used by
	// the escalation ladder. A zero value means "no cap" — the existing
	// LockoutDurations entries apply unchanged. Default: 1h.
	MaxLockoutDuration time.Duration `yaml:"max_lockout_duration" toml:"max_lockout_duration"`

	// AutoUnlock controls whether expired locks are cleared lazily on
	// the next login attempt. When false, an admin must POST /unlock to
	// clear a lock — the cooldown timer is ignored. nil pointer = true
	// (the safe default; no operator action required).
	AutoUnlock *bool `yaml:"auto_unlock,omitempty" toml:"auto_unlock,omitempty"`
}

// StatusPluginConfig configures the status plugin.
type StatusPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
}

// AdminPluginConfig configures the admin plugin.
type AdminPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`

	// AllowMachineCallers controls whether bearer-JWT or X-Api-Key
	// callers may pass the RequireAdmin gate. The default (false) is
	// strict: only cookie-resolved sessions count, even if the bearer
	// token or api-key belongs to an admin user. Set true to allow
	// machine-to-machine admin automation. Tracked via AuthUser.Method.
	AllowMachineCallers bool `yaml:"allow_machine_callers" toml:"allow_machine_callers"`
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
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// EncryptionKeyEnv names the env var holding the base64-encoded 32-byte
	// AES-256 key used to encrypt upstream tokens at rest. Required when
	// enabled. Generate one with `yauth gen-secrets`.
	EncryptionKeyEnv string                   `yaml:"encryption_key_env" toml:"encryption_key_env"`
	Providers        map[string]OAuthProvider `yaml:"providers" toml:"providers"`
}

// WebhooksPluginConfig configures outbound webhook delivery. Per-webhook HMAC
// secrets are issued by the create endpoint; there is no global secret here.
type WebhooksPluginConfig struct {
	Enabled     bool `yaml:"enabled" toml:"enabled"`
	MaxAttempts int  `yaml:"max_attempts" toml:"max_attempts"`
	// DefaultSecretEnv is accepted for backward compatibility but ignored —
	// webhook signing secrets are issued per-endpoint at creation time.
	// Deprecated: ignored; will be removed in a future release.
	DefaultSecretEnv string `yaml:"default_secret_env,omitempty" toml:"default_secret_env,omitempty"`
}

// AsymJWTPluginConfig configures asymmetric (RS256/ES256) JWT signing.
//
// Operators supply the key material via filesystem path
// (PrivateKeyPath/PublicKeyPath) OR via an environment variable holding
// the PEM bytes (PrivateKeyPEMEnv/PublicKeyPEMEnv). The two modes are
// mutually exclusive — Validate rejects configs that mix them. The env
// path suits secret managers (Vault, AWS Secrets Manager) that mount
// values into the process environment rather than the filesystem.
type AsymJWTPluginConfig struct {
	Enabled        bool   `yaml:"enabled" toml:"enabled"`
	KeyType        string `yaml:"key_type" toml:"key_type"` // "rs256" | "es256"
	PrivateKeyPath string `yaml:"private_key_path" toml:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path" toml:"public_key_path"`

	// PrivateKeyPEMEnv names the environment variable whose value is the
	// PEM-encoded private key. Mutually exclusive with PrivateKeyPath.
	PrivateKeyPEMEnv string `yaml:"private_key_pem_env" toml:"private_key_pem_env"`
	// PublicKeyPEMEnv names the environment variable whose value is the
	// PEM-encoded public key. Mutually exclusive with PublicKeyPath.
	PublicKeyPEMEnv string `yaml:"public_key_pem_env" toml:"public_key_pem_env"`

	KeyID string `yaml:"key_id" toml:"key_id"`
}

// OIDCPluginConfig configures the OIDC discovery + JWKS plugin.
type OIDCPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// Issuer is the OIDC "iss" value and the origin for absolute URLs in the
	// discovery doc. Empty falls back to server.base_url.
	Issuer string `yaml:"issuer" toml:"issuer"`
	// BasePath is the external path prefix the router is mounted under, e.g.
	// "/api/auth". Empty falls back to server.prefix.
	BasePath string `yaml:"base_path" toml:"base_path"`

	// IDTokenTTL is the lifetime stamped onto id_tokens minted by the
	// oauth2-server when oidc is loaded. Defaults to 1h when zero. The
	// oidc plugin itself does not mint tokens today; the value is wired
	// through PluginHost so a future oauth2-server revision can pick it
	// up without re-plumbing.
	IDTokenTTL time.Duration `yaml:"id_token_ttl" toml:"id_token_ttl"`

	// ClaimsSupported is advertised under "claims_supported" in the
	// discovery document. Defaults to the OIDC core baseline
	// (sub/email/email_verified/name/aud/exp/iat/iss) when nil.
	ClaimsSupported []string `yaml:"claims_supported" toml:"claims_supported"`
}

// OAuth2ServerPluginConfig configures the embedded RFC 6749 / 6750 / 7591 /
// 7636 / 8414 / 8628 authorization server. PKCE (S256) is always required for
// the authorization-code flow — there is no knob to disable it.
type OAuth2ServerPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// Issuer is the JWT "iss" and the origin for absolute metadata URLs. Set it
	// to the exact public origin clients reach. Empty falls back to server.base_url.
	Issuer string `yaml:"issuer" toml:"issuer"`
	// BasePath is the external path prefix the router is mounted under, e.g.
	// "/api/auth". Empty falls back to server.prefix.
	BasePath             string        `yaml:"base_path" toml:"base_path"`
	AuthorizationCodeTTL time.Duration `yaml:"authorization_code_ttl" toml:"authorization_code_ttl"`
	DeviceCodeTTL        time.Duration `yaml:"device_code_ttl" toml:"device_code_ttl"`
	// DevicePollInterval is the seconds clients should poll the token endpoint
	// during the device flow. Default 5.
	DevicePollInterval int `yaml:"device_poll_interval" toml:"device_poll_interval"`
	// VerificationURI is the user-facing device-flow entry URL. Default "/oauth/device".
	VerificationURI string `yaml:"verification_uri" toml:"verification_uri"`
	// ConsentRequired forces the consent prompt even when a prior grant exists.
	ConsentRequired bool `yaml:"consent_required" toml:"consent_required"`
	// AccessTTL is the lifetime of issued access tokens. Empty → plugin default (15m).
	AccessTTL time.Duration `yaml:"access_ttl" toml:"access_ttl"`
	// RefreshTTL is the lifetime of issued refresh tokens. Empty → plugin default (30d).
	RefreshTTL time.Duration `yaml:"refresh_ttl" toml:"refresh_ttl"`
	// BackchannelLogoutTimeout bounds each OIDC Back-Channel Logout delivery
	// (the OP→RP logout_token POST). Empty → the plugin default (5s).
	BackchannelLogoutTimeout time.Duration `yaml:"backchannel_logout_timeout" toml:"backchannel_logout_timeout"`

	// RequirePKCE is accepted for backward compatibility but ignored — PKCE
	// (S256) is always required for the authorization-code flow.
	// Deprecated: ignored; will be removed in a future release.
	RequirePKCE bool `yaml:"require_pkce,omitempty" toml:"require_pkce,omitempty"`

	// DCREnabled turns on the RFC 7591 dynamic client registration endpoint
	// (POST /oauth/register). When true, public loopback-only clients
	// (localhost/127.0.0.1/::1) may self-register anonymously — what local MCP
	// clients need. Non-loopback / confidential registrations require an admin.
	DCREnabled bool `yaml:"dcr_enabled" toml:"dcr_enabled"`
	// DCRRequireAdminForLoopback gates EVERY registration behind an admin,
	// including loopback-only public clients.
	DCRRequireAdminForLoopback bool `yaml:"dcr_require_admin_for_loopback" toml:"dcr_require_admin_for_loopback"`
	// DCRAllowConfidentialClients lets DCR create confidential clients (default
	// is public/PKCE only).
	DCRAllowConfidentialClients bool `yaml:"dcr_allow_confidential_clients" toml:"dcr_allow_confidential_clients"`
	// AllowPrivateNetworkJWKSURI permits private_key_jwt clients to use loopback
	// / RFC 1918 jwks_uri (SSRF protection off). Dev/test only.
	AllowPrivateNetworkJWKSURI bool `yaml:"allow_private_network_jwks_uri" toml:"allow_private_network_jwks_uri"`
	// DCRStaleClientTTL enables the sweep of unused dynamically-registered
	// clients older than this. 0 (default) disables the sweep.
	DCRStaleClientTTL time.Duration `yaml:"dcr_stale_client_ttl" toml:"dcr_stale_client_ttl"`
	// DCRStaleSweepInterval is how often the stale-client sweep runs. Default 24h.
	DCRStaleSweepInterval time.Duration `yaml:"dcr_stale_sweep_interval" toml:"dcr_stale_sweep_interval"`
}

// Default returns a Config populated with sensible development defaults
// and email_password enabled. Used by `yauth init`.
func Default() *Config {
	allowSignups := true
	return &Config{
		Database: DatabaseConfig{
			Driver: "pgx",
			DSN:    "postgres://postgres:postgres@localhost:5432/yauth?sslmode=disable",
		},
		Server: ServerConfig{
			Addr:         ":3000",
			Prefix:       "/api/auth",
			AllowSignups: &allowSignups,
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
		Mailer: MailerConfig{
			Provider: "logging",
		},
		Plugins: PluginsConfig{
			EmailPassword: EmailPasswordPluginConfig{
				Enabled:           true,
				MinPasswordLength: 12,
			},
		},
	}
}
