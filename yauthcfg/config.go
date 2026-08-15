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

	// CrossSiteWrites controls the cross-site state-change guard: a
	// state-changing request carrying the ambient session cookie that the
	// BROWSER reports as cross-site is refused. ON by default.
	CrossSiteWrites CrossSiteWriteConfig `yaml:"cross_site_writes" toml:"cross_site_writes"`

	// SecurityHeaders controls the response-header floor the mounted
	// Router applies to every response. ON by default; see
	// SecurityHeadersConfig for why turning it off is a decision.
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers" toml:"security_headers"`

	// TrustedProxies lists the peers whose X-Forwarded-For / X-Real-IP
	// yauth believes when it decides a request's client IP — the address
	// stored on a session, written to every audit row, carried on every
	// auth event, and used as the per-IP rate-limit bucket.
	//
	// Entries are literal IPs, CIDRs, or one of the keywords:
	//
	//	private  loopback + RFC1918 + CGNAT + link-local + unique-local
	//	all      trust every peer (pre-hardening behaviour)
	//	none     never believe a forwarding header
	//
	// OMITTED means ["private"]. That keeps the recorded IP correct for
	// the usual deployment — an ingress, sidecar or local nginx on private
	// space — while a listener exposed directly to clients no longer
	// believes a header the client itself wrote. Add your load balancer's
	// or CDN's ranges when the hop in front of yauth has a public address.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty" toml:"trusted_proxies,omitempty" doc:"Peers whose X-Forwarded-For / X-Real-IP is believed when resolving the client IP (sessions, audit rows, auth events, rate-limit buckets, IP binding). Literal IPs, CIDRs, or the keywords private|all|none. Omitted means [\"private\"]: forwarding headers are honoured only from a loopback/RFC1918/link-local peer."`
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

// CrossSiteWriteConfig configures the cross-site state-change guard. Before it
// existed, every cookie-authenticated write in yauth authorized on the ambient
// cookie alone: any page an admin had open could POST /admin/users/{id}/suspend
// (bodyless, so a plain auto-submitting form reached it) and the write landed.
//
// The guard uses the browser's own Sec-Fetch-Site / Origin signals, and it is
// deliberately narrow: same-origin and SAME-SITE requests still pass, as do
// callers that send neither header (curl, CI, server-side clients) and every
// machine credential (bearer, X-Api-Key), which a cross-site page cannot make
// a browser attach in the first place.
type CrossSiteWriteConfig struct {
	// Allow turns the guard OFF. Omitted/false enforces it — a security
	// default that has to be opted into is the misconfiguration this
	// setting exists to prevent.
	Allow bool `yaml:"allow" toml:"allow" doc:"Permit cross-site state-changing requests authenticated by the session cookie. Default false (the guard is enforced). Turning this on restores the pre-guard behaviour: any page a signed-in user has open can drive their session."`

	// Origins lists the cross-site origins allowed to make state-changing
	// calls with a session cookie. Omitted inherits
	// server.cors.allowed_origins.
	Origins []string `yaml:"origins,omitempty" toml:"origins,omitempty" doc:"Origins permitted to make cross-site state-changing calls with a session cookie, e.g. [\"https://app.example.com\"]. Omitted inherits server.cors.allowed_origins. Set it explicitly when CORS is terminated by a gateway in front of yauth, so server.cors.allowed_origins is empty."`
}

// SecurityHeadersConfig configures the response-header floor applied to every
// response the mounted Router emits: X-Content-Type-Options, Referrer-Policy,
// X-Frame-Options and Content-Security-Policy. Before it existed every yauth
// response went out bare, which left the browser-facing, state-changing
// /oauth/end_session page framable and clickjackable.
//
// The middleware only fills in headers that are still unset, so an embedding
// application that already writes its own policy always wins over these.
type SecurityHeadersConfig struct {
	// Enabled is a tri-state pointer: nil = default (true), &true and
	// &false explicit. Default ON deliberately — a security default that
	// has to be opted into is the misconfiguration this setting exists to
	// prevent. Set it false only when a reverse proxy in front of yauth
	// already sets an equivalent set.
	Enabled *bool `yaml:"enabled,omitempty" toml:"enabled,omitempty" doc:"Emit X-Content-Type-Options, Referrer-Policy, X-Frame-Options and Content-Security-Policy on every response. Omitted means true. Headers an embedding application already set are never overwritten."`

	// HSTS is the Strict-Transport-Security value, e.g.
	// "max-age=31536000; includeSubDomains". EMPTY (the default) means the
	// header is NEVER sent, and even when set it is only sent on requests
	// that arrived over TLS. Both guards matter: an unconditional HSTS
	// header breaks plain-HTTP local development and can strand a domain
	// in browsers for the whole max-age.
	HSTS string `yaml:"hsts,omitempty" toml:"hsts,omitempty" doc:"Strict-Transport-Security value, e.g. \"max-age=31536000; includeSubDomains\". Empty (default) never emits the header; when set it is emitted only on requests that arrived over TLS."`

	// Override replaces the default value of individual headers, keyed by
	// canonical header name — e.g. {"X-Frame-Options": "SAMEORIGIN"} for
	// a console that genuinely frames itself, or a Content-Security-Policy
	// that has to allow a subresource. Names outside the four defaults are
	// ignored. An override is still only applied when the header is unset.
	Override map[string]string `yaml:"override,omitempty" toml:"override,omitempty" doc:"Per-header replacements for the defaults, keyed by header name (X-Content-Type-Options, Referrer-Policy, X-Frame-Options, Content-Security-Policy). Other names are ignored."`
}

// MailerConfig selects an outbound mailer for the host. Provider "logging"
// (the default) is a DEV stand-in that writes the would-be email — including
// verification/reset/magic-link tokens — to the log and sends nothing; use
// "smtp" or "cloudflare" in production. See `yauth docs mailer`.
type MailerConfig struct {
	Provider   string           `yaml:"provider" toml:"provider" enum:"logging,smtp,cloudflare" doc:"Outbound mailer. 'logging' (default) is DEV ONLY: it logs the would-be email body — including single-use verification/reset/magic-link bearer tokens — and sends NO real email. Set 'smtp' or 'cloudflare' for production. See 'yauth docs mailer'."`
	From       string           `yaml:"from" toml:"from" doc:"Envelope/From address for outbound mail. Required when provider is smtp or cloudflare."`
	SMTP       SMTPConfig       `yaml:"smtp" toml:"smtp" doc:"SMTP connection settings (used when provider=smtp)."`
	Cloudflare CloudflareConfig `yaml:"cloudflare" toml:"cloudflare" doc:"Cloudflare Email Service settings (used when provider=cloudflare)."`
}

// CloudflareConfig holds Cloudflare Email Service (REST API) details. The
// API token is resolved from an environment variable to keep the config
// file safe to commit. The domain of MailerConfig.From must be onboarded
// for Email Sending on the account identified by AccountID.
type CloudflareConfig struct {
	AccountID   string `yaml:"account_id" toml:"account_id" doc:"Cloudflare account ID that owns the onboarded sending domain (required when provider=cloudflare)."`
	APITokenEnv string `yaml:"api_token_env" toml:"api_token_env" doc:"Name of the env var holding a Cloudflare API token with the 'Email Sending: Edit' permission (the value is read at runtime; the var name, not the secret, lives in config). Required when provider=cloudflare."`
	BaseURL     string `yaml:"base_url" toml:"base_url" doc:"Override the Cloudflare API root. Empty uses https://api.cloudflare.com/client/v4 — set this only for a proxy or a test double."`
}

// SMTPConfig holds SMTP connection details. Username/password are
// resolved from environment variables to keep the config file safe to
// commit.
type SMTPConfig struct {
	Host        string `yaml:"host" toml:"host" doc:"SMTP server hostname (required when provider=smtp)."`
	Port        int    `yaml:"port" toml:"port" doc:"SMTP server port, e.g. 587 (required when provider=smtp)."`
	UsernameEnv string `yaml:"username_env" toml:"username_env" doc:"Name of the env var holding the SMTP username (the value is read at runtime; the var name, not the secret, lives in config)."`
	PasswordEnv string `yaml:"password_env" toml:"password_env" doc:"Name of the env var holding the SMTP password."`
	TLS         bool   `yaml:"tls" toml:"tls" doc:"DEPRECATED — use tls_mode. true means implicit TLS (port 465); false means an OPPORTUNISTIC STARTTLS upgrade that an on-path attacker can strip. Honoured only when tls_mode is unset."`
	// TLSMode replaces TLS. The bool could only say "implicit" or
	// "upgrade if offered" — it had no way to say "refuse to send unless
	// the link is encrypted", which is the only safe posture for a
	// message body carrying a single-use account-takeover token.
	TLSMode string `yaml:"tls_mode" toml:"tls_mode" enum:"implicit,starttls,opportunistic,none" doc:"SMTP transport security. 'starttls' REQUIRES the STARTTLS upgrade and refuses to send without it — prefer it for any relay reached over a network. 'implicit' handshakes before the greeting (port 465). 'opportunistic' upgrades only when the server advertises STARTTLS, so an on-path attacker can strip it and read password-reset and magic-link tokens in cleartext. 'none' never upgrades. Empty derives from the deprecated tls flag (implicit when true, opportunistic otherwise)."`
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
// yauth.yaml. Every rule here is enforced on the route(s) implementing that
// operation; an omitted rule keeps yauth's default and an explicit `max: 0`
// turns the limiter off. Defaults are applied in NewFromConfig when the
// section is omitted.
//
// Routes are grouped by operation, and the routes of one operation share a
// single per-IP bucket:
//
//	login            POST /login, POST /token
//	register         POST /register
//	forgot_password  POST /forgot-password
//	magic_link_send  POST /magic-link/send
//	unlock_request   POST /account/request-unlock
//	mfa_verify       POST /mfa/verify, POST /token/mfa,
//	                 POST /mfa/totp/setup, DELETE /mfa/totp,
//	                 POST /mfa/backup-codes/regenerate
//	oauth_token      POST /oauth/token, POST /oauth/device/code
//	oauth_introspect POST /oauth/introspect, POST /oauth/revoke
//
// The three MFA management routes join mfa_verify because they check the same
// six-digit secret via the X-MFA-Code step-up header; sharing the bucket stops
// an attacker with a session guessing there at full speed. GET
// /mfa/backup-codes and POST /mfa/totp/confirm are deliberately NOT metered —
// the first is a read with nothing to guess, the second validates against a
// candidate secret the caller was just shown in full.
//
// oauth_token and oauth_introspect meter endpoints that need NO credential to
// reach a 64 MiB argon2id client-secret verification — only a client_id, which
// is public by construction. They are separate ops because their honest call
// rates differ by an order of magnitude: a browser login costs exactly one
// /oauth/token call, while a resource server introspects once per inbound
// request.
//
// RAISE oauth_token if you run device flow at scale or a non-caching M2M
// fleet: an RFC 8628 device polls POST /oauth/token every
// plugins.oauth2_server.device_poll_interval seconds (default 5, i.e. 12
// requests a minute per device in flight), and the bucket is per CLIENT IP —
// so every device behind one NAT or egress gateway shares it. `max: 0` is an
// explicit "no limit" for operators who meter these routes at the edge instead.
type RateLimitConfig struct {
	Login          RateLimitRule `yaml:"login" toml:"login"`
	Register       RateLimitRule `yaml:"register" toml:"register"`
	ForgotPassword RateLimitRule `yaml:"forgot_password" toml:"forgot_password"`
	MagicLinkSend  RateLimitRule `yaml:"magic_link_send" toml:"magic_link_send"`
	UnlockRequest  RateLimitRule `yaml:"unlock_request" toml:"unlock_request"`
	MFAVerify      RateLimitRule `yaml:"mfa_verify" toml:"mfa_verify"`

	OAuthToken      RateLimitRule `yaml:"oauth_token" toml:"oauth_token"`
	OAuthIntrospect RateLimitRule `yaml:"oauth_introspect" toml:"oauth_introspect"`
}

// RateLimitRule is one (max, window) pair.
//
// Max is a pointer so an omitted key (keep the default) stays distinct from
// `max: 0` (no limit). With a plain int the two were the same value, so the
// documented "0 = no limit" could not be expressed at all.
type RateLimitRule struct {
	Max    *int          `yaml:"max,omitempty" toml:"max,omitempty" doc:"Requests allowed per window, per client IP. Omit to keep yauth's default; 0 means no limit."`
	Window time.Duration `yaml:"window" toml:"window" doc:"Fixed window the max applies over. Omit to keep yauth's default (60s)."`
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
	Organizations OrganizationsPluginConfig `yaml:"organizations" toml:"organizations"`
	SCIM          SCIMPluginConfig          `yaml:"scim" toml:"scim"`
	SSOOIDC       SSOOIDCPluginConfig       `yaml:"sso_oidc" toml:"sso_oidc"`
}

// EmailPasswordPluginConfig configures plugins/emailpassword.
type EmailPasswordPluginConfig struct {
	Enabled                  bool          `yaml:"enabled" toml:"enabled"`
	MinPasswordLength        int           `yaml:"min_password_length" toml:"min_password_length"`
	RequireEmailVerification bool          `yaml:"require_email_verification" toml:"require_email_verification"`
	RememberMeTTL            time.Duration `yaml:"remember_me_ttl" toml:"remember_me_ttl"`

	// RevealRegistrationOutcome opts OUT of enumeration-neutral /register:
	// true restores the 201 + user + session cookie for a fresh account, which
	// tells an anonymous caller whether the address already has one. See
	// emailpassword.Config.RevealRegistrationOutcome. Default false.
	RevealRegistrationOutcome bool `yaml:"reveal_registration_outcome" toml:"reveal_registration_outcome"`

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

	// SatisfiesMFA declares that clicking a magic link counts as the
	// second factor, so a TOTP-enrolled user is not stepped up after
	// /magic-link/verify. Default false: a link proves control of an
	// inbox, usually the same channel as password reset, so it is
	// treated as a first factor and the login completes at /mfa/verify.
	SatisfiesMFA bool `yaml:"satisfies_mfa" toml:"satisfies_mfa" doc:"Treat clicking a magic link as the second factor. Default false: a link only proves control of an inbox, so a TOTP-enrolled user is stepped up and finishes at /mfa/verify."`
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

	// AllowMachineCallers controls whether bearer-JWT or USER-scoped
	// X-Api-Key callers may pass the RequireAdmin gate. The default
	// (false) is strict: only cookie-resolved sessions count, even if the
	// bearer token or api-key belongs to an admin user. Set true to allow
	// machine-to-machine admin automation. Tracked via AuthUser.Method.
	//
	// An ORG-scoped API key (service account) is refused whatever this
	// says: it carries the authority stamped on the key, not the global
	// role of the human who created it. Admin automation needs a
	// user-scoped key owned by an admin.
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

	// SatisfiesMFA declares whether a passkey assertion is itself the
	// second factor. nil pointer = true: a passkey is possession plus
	// user verification and is phishing-resistant, so /passkey/login/finish
	// completes the login in one leg. Set false to demand a TOTP step-up
	// anyway — which prompts existing passkey users who have TOTP
	// enrolled for a code they were never asked for before.
	SatisfiesMFA *bool `yaml:"satisfies_mfa,omitempty" toml:"satisfies_mfa,omitempty" doc:"Treat a USER-VERIFIED passkey assertion as the second factor. nil = true: possession plus a biometric/PIN is phishing-resistant, so the login completes in one leg. The credit is graded on the assertion's UV flag — an authenticator that answers UV=0 proved possession only, so a TOTP-enrolled user is stepped up regardless. false demands a TOTP step-up as well."`
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

	// SatisfiesMFA declares whether the upstream provider's own
	// authentication counts as the second factor. nil pointer = true (the
	// long-standing behaviour). Set false to demand local TOTP anyway;
	// because the callback is a browser redirect and cannot carry a
	// challenge, a step-up then fails closed with 403 and no session.
	SatisfiesMFA *bool `yaml:"satisfies_mfa,omitempty" toml:"satisfies_mfa,omitempty" doc:"Treat the upstream provider's authentication as the second factor. nil = true. false fails the login closed with 403 — the callback is a browser redirect and cannot carry an MFA challenge."`

	// LoginStateBinding ties a federated login to the browser that started it.
	// See auth/login_binding.go: without it, a finished-but-undelivered
	// .../callback?code=…&state=… URL is a portable credential — the attacker
	// authenticates at the IdP as themselves, mails the URL to a victim, and
	// the victim's browser is handed a session cookie for the ATTACKER's
	// account. Empty means "auto".
	LoginStateBinding string `yaml:"login_state_binding,omitempty" toml:"login_state_binding,omitempty" enum:"auto,required,off" doc:"Bind an OAuth login to the browser that started it, closing login CSRF / session fixation on the callback. \"auto\" (default) binds when cookie_secure is true — the binding cookie must be SameSite=None to survive an IdP's form_post, which browsers only honour with Secure, so plain HTTP is NOT covered. \"required\" always binds. \"off\" disables it, for deployments that cannot carry the cookie (a native client that fetches /authorize with its own HTTP client, or cross-device login continuation)."`
}

// SSOOIDCPluginConfig configures the sso_oidc plugin — this app acting as an
// OIDC Relying Party toward an upstream IdP ("Sign in with <IdP>"). The
// connections themselves are data, not config: global (org-less) or
// org-scoped rows managed at runtime via /sso/connections and
// /organizations/{id}/sso/connections. This block only mounts the plugin.
type SSOOIDCPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// EncryptionKeyEnv names the env var holding the base64-encoded 32-byte
	// AES-256 key that encrypts each connection's IdP client_secret at rest.
	// Required when enabled. Generate one with `yauth gen-secrets`.
	EncryptionKeyEnv string `yaml:"encryption_key_env" toml:"encryption_key_env"`
	// StateTTL bounds the /sso/login -> /sso/callback round trip. Zero means
	// the plugin default (10m).
	StateTTL time.Duration `yaml:"state_ttl" toml:"state_ttl"`
	// AllowedRedirectURLs is the allow-list of post-login redirect_url
	// targets. Empty means redirect_url is ignored entirely (the safest
	// default).
	AllowedRedirectURLs []string `yaml:"allowed_redirect_urls" toml:"allowed_redirect_urls"`
	// SelfIssuer is this app's OWN OIDC issuer URL. When set (and asym_jwt is
	// enabled) the runtime federate endpoint signs a software_statement so the
	// app can self-register at a trusted upstream IdP with no admin key.
	SelfIssuer string `yaml:"self_issuer" toml:"self_issuer"`

	// SatisfiesMFA declares whether the upstream IdP's own authentication
	// counts as the second factor. nil pointer = true (the long-standing
	// behaviour, and the usual reason an org buys SSO). Set false to
	// demand local TOTP anyway; because the callback is a browser redirect
	// and cannot carry a challenge, a step-up then fails closed with 403
	// and no session.
	SatisfiesMFA *bool `yaml:"satisfies_mfa,omitempty" toml:"satisfies_mfa,omitempty" doc:"Treat the upstream IdP's authentication as the second factor. nil = true — the usual reason an org buys SSO. false fails the login closed with 403 — the callback is a browser redirect and cannot carry an MFA challenge."`

	// AllowPrivateNetworkIDP opts the outbound IdP calls into loopback /
	// RFC 1918 destinations. See ssooidc.Config.AllowPrivateNetworkIDP: a
	// connection's discovery_url is chosen by an ORG admin and then dialled
	// by the server on /test, on every login and on back-channel logout, so
	// the default is off. Turn it on for an in-cluster IdP.
	AllowPrivateNetworkIDP bool `yaml:"allow_private_network_idp,omitempty" toml:"allow_private_network_idp,omitempty" doc:"Permit SSO connections whose IdP is on a loopback / RFC 1918 address (an in-cluster Keycloak at http://keycloak.identity.svc:8080). Omitted means false: a connection's discovery_url is chosen by an org admin and then dialled by the server, so a private destination is refused at dial time. The cloud metadata range 169.254.0.0/16 stays refused either way."`

	// LoginStateBinding is the sso_oidc twin of the oauth knob of the same
	// name — the /sso/login → /sso/callback round trip had exactly the same
	// hole. Empty means "auto".
	LoginStateBinding string `yaml:"login_state_binding,omitempty" toml:"login_state_binding,omitempty" enum:"auto,required,off" doc:"Bind an SSO login to the browser that started it, closing login CSRF / session fixation on /sso/callback. \"auto\" (default) binds when cookie_secure is true — the binding cookie must be SameSite=None to survive an IdP's form_post, which browsers only honour with Secure, so plain HTTP is NOT covered. \"required\" always binds. \"off\" disables it, for deployments that cannot carry the cookie."`
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

	// EncryptionKeyEnv names the env var holding the key material that
	// per-endpoint webhook secrets are sealed with at rest. Every other
	// plugin that stores something encrypted has this knob
	// (plugins.mfa/oauth/sso_oidc.encryption_key_env); webhooks did not, so
	// on the declarative path webhooks.Config.EncryptionKey was always empty
	// and the plugin fell back to HKDF(PluginHost.JWTSecret()). That chained
	// every yauth_webhooks.secret row to the BEARER plugin's JWT secret —
	// rotating JWT_SECRET, a routine operation whose whole point is to
	// invalidate tokens, silently made those rows undecryptable — and left a
	// deployment that runs webhooks WITHOUT bearer unable to store a signing
	// secret at all, with no way out from config.
	//
	// Unset keeps the historical behaviour exactly: fall back to the JWT
	// secret, and if there is none, the plugin's loud boot-time refusal.
	EncryptionKeyEnv string `yaml:"encryption_key_env,omitempty" toml:"encryption_key_env,omitempty" doc:"Env var holding the key webhook signing secrets are encrypted with at rest (HKDF-SHA256 input; any length, 32+ bytes recommended). Omitted falls back to the bearer plugin's JWT secret, which means rotating JWT_SECRET makes every stored webhook secret undecryptable — and a deployment without bearer cannot store one at all. WARNING: this is one-way. Setting it on a deployment whose secrets were already sealed under the JWT secret makes those existing rows undecryptable, so each webhook's secret must be rotated after the change."`

	// AllowPrivateDestinations opts into private-network webhook receivers.
	// See webhooks.Config.AllowPrivateDestinations: a webhook URL is chosen
	// by a deployment admin and then dialled by the server, so an unfiltered
	// one is an SSRF primitive. Off by default; in-cluster deployments need
	// it on.
	AllowPrivateDestinations bool `yaml:"allow_private_destinations,omitempty" toml:"allow_private_destinations,omitempty" doc:"Permit webhook receivers on loopback / RFC 1918 addresses (an in-cluster collector or sidecar). Omitted means false: a private destination is refused when the webhook is created AND when it is dialled, because a webhook URL is admin-chosen and the server connects to it on every matching event. The cloud metadata range 169.254.0.0/16 stays refused either way."`
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
	// DCRTrustedIssuers is the allow-list of peer issuer URLs whose signed
	// software_statement authorizes keyless confidential DCR (no admin
	// credential). The registrant proves control of a trusted issuer; its
	// statement is verified against that issuer's published JWKS.
	DCRTrustedIssuers []string `yaml:"dcr_trusted_issuers" toml:"dcr_trusted_issuers"`
	// AllowPrivateNetworkJWKSURI permits private_key_jwt clients to use loopback
	// / RFC 1918 jwks_uri (SSRF protection off). Dev/test only.
	AllowPrivateNetworkJWKSURI bool `yaml:"allow_private_network_jwks_uri" toml:"allow_private_network_jwks_uri"`
	// DCRStaleClientTTL enables the sweep of unused dynamically-registered
	// clients older than this. 0 (default) disables the sweep.
	DCRStaleClientTTL time.Duration `yaml:"dcr_stale_client_ttl" toml:"dcr_stale_client_ttl"`
	// DCRStaleSweepInterval is how often the stale-client sweep runs. Default 24h.
	DCRStaleSweepInterval time.Duration `yaml:"dcr_stale_sweep_interval" toml:"dcr_stale_sweep_interval"`
}

// OrganizationsPluginConfig configures the multi-tenant organizations plugin
// (organizations, memberships, invitations, org-scoped groups, and org-scoped
// API keys). Enable it alongside the api_key plugin: org-scoped keys share the
// api-key prefix so one resolver path validates both user- and org-scoped
// credentials.
type OrganizationsPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// APIKeyPrefix is the prefix-tag for org-scoped API keys. Empty falls back to
	// the api_key plugin's prefix (default "yak"), so the key the apikey plugin
	// mints and the key an org mints validate through one resolver.
	APIKeyPrefix string `yaml:"api_key_prefix" toml:"api_key_prefix"`
	// InvitationTTL is the lifetime of newly-minted invitations. 0 → plugin default (7d).
	InvitationTTL time.Duration `yaml:"invitation_ttl" toml:"invitation_ttl"`
	// DefaultInviteRole is assigned to invitees when the request omits a role.
	// Empty → plugin default ("member").
	DefaultInviteRole string `yaml:"default_invite_role" toml:"default_invite_role"`
	// AllowDirectMemberEnrollment restores the pre-release behaviour of
	// POST /organizations/{id}/members: any org admin may enrol any user id
	// as an ACTIVE member with no invitation and no verified domain, and the
	// target is never asked. Default false, which is the safe value: without
	// it, a non-install-admin caller may only enrol users whose email domain
	// the org has VERIFIED; everyone else must be invited and accept.
	//
	// Turning it on re-opens the id_token groups-claim path — an active
	// membership is what the group routes require, and group names reach the
	// `groups` claim with no organization predicate — so set it only where
	// the org-admin role is already an operator-level trust boundary, such
	// as a realm-flat console driving the API as an org owner while holding
	// the global role "user".
	AllowDirectMemberEnrollment bool `yaml:"allow_direct_member_enrollment" toml:"allow_direct_member_enrollment"`
}

// SCIMPluginConfig configures the SCIM 2.0 provisioning plugin (org-scoped
// /scim/v2/...). SCIM is organization-scoped and its bearer credential is an
// org-scoped API key, so it requires the organizations + api_key plugins and
// its APIKeyPrefix MUST match theirs.
type SCIMPluginConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
	// APIKeyPrefix is the leading prefix-tag of SCIM bearer keys. Empty falls back
	// to the api_key plugin's prefix (default "yak"). MUST match it.
	APIKeyPrefix string `yaml:"api_key_prefix" toml:"api_key_prefix"`
	// BasePath is the external URL prefix the router is mounted under (e.g.
	// "/api/auth"), used only to build absolute SCIM self/Location URLs. Empty
	// falls back to the shared oidc/oauth2_server base path (server.prefix).
	BasePath string `yaml:"base_path" toml:"base_path"`
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
