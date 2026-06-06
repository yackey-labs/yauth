package yauth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	yauthMigrate "github.com/yackey-labs/yauth/migrate"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/magiclink"
	smtpmailer "github.com/yackey-labs/yauth/plugins/mailer/smtp"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/plugins/oauth"
	"github.com/yackey-labs/yauth/plugins/oauth/providers"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/plugins/passkey"
	"github.com/yackey-labs/yauth/plugins/status"
	"github.com/yackey-labs/yauth/plugins/webhooks"
	yauthrepo "github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/repo/pgxrepo"
	"github.com/yackey-labs/yauth/repo/redisrepo"
	"github.com/yackey-labs/yauth/telemetry"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// NewFromConfig builds a fully-wired *YAuth from a yauthcfg.Config. It wires
// every enabled plugin (resolving secrets/keys from the config's *_env / *_path
// fields) and returns a ready-to-mount instance — it is exactly
// [NewBuilderFromConfig] followed by Build().
//
// Use this for the all-declarative path. To start from yaml and ALSO add your
// own plugins in Go, use [NewBuilderFromConfig] instead.
//
// Migration policy: NewFromConfig NEVER calls AutoMigrate by default.
// Run `yauth migrate` (cmd/yauth) as a one-shot job before rolling out
// app replicas — concurrent AutoMigrate calls race in multi-replica
// deployments. The optional cfg.Database.AutoMigrate flag overrides
// this for development only and prints a stderr warning when set.
func NewFromConfig(ctx context.Context, cfg *yauthcfg.Config, opts ...ConfigOption) (*YAuth, error) {
	b, err := NewBuilderFromConfig(ctx, cfg, opts...)
	if err != nil {
		return nil, err
	}
	y, err := b.Build()
	if err != nil {
		return nil, err
	}

	// Secure admin bootstrap runs after the instance is built (so the repo is
	// fully decorated) and assumes the schema already exists — consumers run
	// `yauth migrate` before `serve`. It is idempotent and multi-replica safe;
	// see bootstrapAdmin. A failure here is logged, not fatal: a transient DB
	// error on one replica must not take the process down when the admin may
	// already exist (another replica won the race) or be created on the next
	// restart.
	if cfg.Plugins.EmailPassword.Enabled && cfg.Plugins.EmailPassword.BootstrapAdmin.Enabled {
		logger := resolveConfigOptions(opts).logger
		bootstrapAdmin(ctx, y.Repo(), logger, cfg.Plugins.EmailPassword.BootstrapAdmin, effectiveBootstrapPolicy(cfg.Plugins.EmailPassword))
	}

	return y, nil
}

// effectiveBootstrapPolicy returns the password policy a bootstrap-generated
// password must satisfy — the same policy /register enforces, with the
// MinPasswordLength=12 baseline applied when no explicit policy min is set
// (mirroring emailpassword.New + validatePasswordComplexity).
func effectiveBootstrapPolicy(ep yauthcfg.EmailPasswordPluginConfig) passwordpolicy.Policy {
	pol := passwordpolicy.Policy{
		MinLength:      ep.PasswordPolicy.MinLength,
		MaxLength:      ep.PasswordPolicy.MaxLength,
		RequireUpper:   ep.PasswordPolicy.RequireUpper,
		RequireLower:   ep.PasswordPolicy.RequireLower,
		RequireDigit:   ep.PasswordPolicy.RequireDigit,
		RequireSpecial: ep.PasswordPolicy.RequireSpecial,
		DisallowCommon: ep.PasswordPolicy.DisallowCommon,
	}
	if pol.MinLength == 0 {
		min := ep.MinPasswordLength
		if min <= 0 {
			min = 12
		}
		pol.MinLength = min
	}
	return pol
}

// ConfigOption tweaks how NewFromConfig / NewBuilderFromConfig assemble the
// instance. It is the yaml-path equivalent of the builder's With* methods for
// the few things the config file cannot carry (e.g. a live *slog.Logger).
type ConfigOption func(*configOptions)

type configOptions struct {
	logger *slog.Logger

	repo    yauthrepo.Repository
	repoSet bool
	pool    *pgxpool.Pool
	poolSet bool
}

func resolveConfigOptions(opts []ConfigOption) configOptions {
	o := configOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}
	return o
}

// WithConfigLogger sets the structured logger used by the config-built
// instance — both the startup config advisories below and, via the builder's
// WithLogger, all runtime logging. Defaults to slog.Default().
func WithConfigLogger(l *slog.Logger) ConfigOption {
	return func(o *configOptions) { o.logger = l }
}

// WithRepo injects a pre-built [repo.Repository], bypassing the cfg.Database
// driver switch entirely. Use it to share a repo your app already owns — e.g.
// a cache-decorated repo, a test fake, or pgxrepo.New(yourPool) over a pool
// you opened once for the whole process.
//
// When a repo is injected, yauth treats it as the complete storage layer and
// does NOT touch cfg.Database (no pool is opened, no driver is dialed), does
// NOT apply the cfg.Cache decorator (compose your own around the injected
// repo), and does NOT run cfg.Database.AutoMigrate (you own migrations — run
// `yauth migrate` or migrate.Run against your pool). If any of those config
// fields are set alongside an injected repo they are ignored with a startup
// WARN, in keeping with yauth's fail-loud-over-silent stance.
//
// WithRepo and [WithPool] are mutually exclusive; setting both is an error.
func WithRepo(r yauthrepo.Repository) ConfigOption {
	return func(o *configOptions) { o.repo = r; o.repoSet = true }
}

// WithPool injects an existing *pgxpool.Pool so yauth reuses it instead of
// opening a second pool to the same Postgres. Unlike [WithRepo], this stays on
// the pgx path: cfg.Cache still wraps the resulting repo and
// cfg.Database.AutoMigrate still runs against the shared pool — so the
// declarative cache/migrate wiring keeps working while one pool serves both
// your app and yauth.
//
// Because OpenTelemetry pool tracing is a pool-construction option
// (pgxrepo.WithOTelTracing), it cannot be applied to an already-built pool. If
// you want yauth's queries traced, build your pool with tracing yourself
// (pgxrepo.Open(ctx, dsn, pgxrepo.WithOTelTracing()) or the equivalent
// otelpgx tracer); cfg.Telemetry does not retrofit it onto an injected pool.
//
// WithPool and [WithRepo] are mutually exclusive; setting both is an error.
func WithPool(p *pgxpool.Pool) ConfigOption {
	return func(o *configOptions) { o.pool = p; o.poolSet = true }
}

// NewBuilderFromConfig wires a *YAuthBuilder from a yauthcfg.Config — the same
// repo, telemetry, mailer, and plugin wiring NewFromConfig performs — but stops
// short of Build() so callers can extend it. This is the mix-and-match entry
// point: declarative yaml for the standard plugins, plus the builder API for
// anything custom or programmatic.
//
//	b, err := yauth.NewBuilderFromConfig(ctx, cfg)
//	if err != nil { ... }
//	ya, err := b.WithPlugin(myInHousePlugin).Build()
func NewBuilderFromConfig(ctx context.Context, cfg *yauthcfg.Config, opts ...ConfigOption) (*YAuthBuilder, error) {
	if cfg == nil {
		return nil, errors.New("yauth: NewFromConfig requires a non-nil config")
	}
	o := resolveConfigOptions(opts)
	logger := o.logger
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("yauth: invalid config: %w", err)
	}
	// Surface deprecated-but-set config fields at startup (same channel as the
	// auto_migrate warning below). Non-fatal; they are ignored.
	for _, warn := range cfg.DeprecationWarnings() {
		logger.Warn("yauth: deprecated config field set (ignored)", "detail", warn)
	}

	if o.repoSet && o.poolSet {
		return nil, errors.New("yauth: WithRepo and WithPool are mutually exclusive — pass at most one")
	}
	if o.repoSet && o.repo == nil {
		return nil, errors.New("yauth: WithRepo was given a nil repository")
	}
	if o.poolSet && o.pool == nil {
		return nil, errors.New("yauth: WithPool was given a nil *pgxpool.Pool")
	}

	var repo yauthrepo.Repository
	// skipCacheWrap is set when the caller owns the full repo layer (WithRepo):
	// the cfg.Cache decorator is theirs to compose, not ours to bolt on.
	skipCacheWrap := false

	switch {
	case o.repoSet:
		// Injected repo: it IS the storage layer. cfg.Database is not consulted
		// (no pool opened, no driver dialed), the cache decorator is the
		// caller's to compose, and migrations are the caller's to run. Warn —
		// don't silently ignore — when conflicting config is set alongside it.
		if cfg.Cache.Enabled {
			logger.Warn("yauth: cfg.Cache ignored — a repo was injected via WithRepo (compose the cache decorator around it yourself)")
		}
		if cfg.Database.AutoMigrate {
			logger.Warn("yauth: cfg.Database.auto_migrate ignored — a repo was injected via WithRepo (you own migrations: run `yauth migrate`)")
		}
		repo = o.repo
		skipCacheWrap = true
	case o.poolSet:
		// Injected pool: stay on the pgx path so cfg.Cache wrapping and
		// cfg.Database.AutoMigrate keep working, but reuse the caller's pool
		// instead of opening a second one. (OTel pool tracing is a
		// construction-time option and cannot be retrofitted here — see
		// WithPool's doc.)
		if cfg.Database.AutoMigrate {
			logger.Warn("yauth: database.auto_migrate=true is for DEV/TEST only — use `yauth migrate` in production")
			if err := yauthMigrate.Run(ctx, pgxrepo.StdDB(o.pool), "pgx"); err != nil {
				return nil, fmt.Errorf("yauth: auto_migrate failed: %w", err)
			}
		}
		repo = pgxrepo.New(o.pool)
	case cfg.Database.Driver == "memory" || cfg.Database.Driver == "mem":
		// In-process, non-persistent backend (no DSN, no migrations). For dev,
		// tests, and ephemeral throwaway instances — data is lost on restart and
		// it is single-process only.
		repo = memrepo.New()
	case cfg.Database.Driver == "pgx":
		poolOpts := []pgxrepo.PoolOption{}
		if cfg.Telemetry.Enabled {
			poolOpts = append(poolOpts, pgxrepo.WithOTelTracing())
		}
		pool, err := pgxrepo.Open(ctx, cfg.Database.DSN, poolOpts...)
		if err != nil {
			return nil, err
		}
		if err := pool.Ping(ctx); err != nil {
			return nil, fmt.Errorf("yauth: database unreachable: %w", err)
		}
		if cfg.Database.AutoMigrate {
			logger.Warn("yauth: database.auto_migrate=true is for DEV/TEST only — use `yauth migrate` in production")
			if err := yauthMigrate.Run(ctx, pgxrepo.StdDB(pool), "pgx"); err != nil {
				return nil, fmt.Errorf("yauth: auto_migrate failed: %w", err)
			}
		}
		repo = pgxrepo.New(pool)
	default:
		return nil, fmt.Errorf("yauth: unsupported database driver %q (supported: pgx, memory)", cfg.Database.Driver)
	}
	if cfg.Cache.Enabled && !skipCacheWrap {
		decorated, err := buildCacheDecorator(repo, cfg.Cache)
		if err != nil {
			return nil, err
		}
		repo = decorated
	}
	builder := New(repo, configToYAuthConfig(cfg)).WithLogger(logger)

	// Build the host's mailer once and share it across plugins. Each
	// plugin satisfies its own Mailer interface structurally — *smtp.Mailer
	// has every method any of the three plugin interfaces require.
	mailer, err := buildMailer(cfg.Mailer)
	if err != nil {
		return nil, err
	}

	if cfg.Telemetry.Enabled {
		builder = builder.WithTelemetry(telemetry.Config{Enabled: true})

		// Manage the provider ourselves by default; in attach mode the host
		// app already configured OpenTelemetry, so we record into its
		// existing TracerProvider rather than opening a second export stream.
		manageProvider := cfg.Telemetry.ManageProvider == nil || *cfg.Telemetry.ManageProvider
		if manageProvider {
			shutdown, err := telemetry.Init(ctx, telemetry.Config{
				Enabled:     true,
				Endpoint:    cfg.Telemetry.OTLPEndpoint,
				Protocol:    cfg.Telemetry.OTLPProtocol,
				ServiceName: cfg.Telemetry.ServiceName,
			})
			if err != nil {
				return nil, fmt.Errorf("yauth: telemetry init: %w", err)
			}
			builder = builder.WithTelemetryShutdown(shutdown)
		}

		if cfg.Telemetry.HTTPMiddleware != nil {
			builder = builder.WithTraceMiddleware(*cfg.Telemetry.HTTPMiddleware)
		}
	}

	if cfg.Plugins.EmailPassword.Enabled {
		ep := cfg.Plugins.EmailPassword
		epCfg := emailpassword.Config{
			MinPasswordLength:        ep.MinPasswordLength,
			RequireEmailVerification: ep.RequireEmailVerification,
			RememberMeTTL:            ep.RememberMeTTL,
			VerificationTokenTTL:     ep.VerificationTokenTTL,
			PasswordResetTokenTTL:    ep.PasswordResetTokenTTL,
			VerificationLinkBaseURL:  ep.VerificationLinkBaseURL,
			PasswordResetLinkBaseURL: ep.PasswordResetLinkBaseURL,
			PasswordPolicy: passwordpolicy.Policy{
				MinLength:      ep.PasswordPolicy.MinLength,
				MaxLength:      ep.PasswordPolicy.MaxLength,
				RequireUpper:   ep.PasswordPolicy.RequireUpper,
				RequireLower:   ep.PasswordPolicy.RequireLower,
				RequireDigit:   ep.PasswordPolicy.RequireDigit,
				RequireSpecial: ep.PasswordPolicy.RequireSpecial,
				DisallowCommon: ep.PasswordPolicy.DisallowCommon,
				HistoryCount:   ep.PasswordPolicy.HistoryCount,
			},
		}
		if ep.HIBPCheck != nil {
			epCfg.HIBPCheck = *ep.HIBPCheck
			epCfg.HIBPCheckSet = true
		}
		if mailer != nil {
			epCfg.Mailer = mailer
		}
		builder = builder.WithPlugin(emailpassword.New(epCfg))
	}

	builder, err = addAuthPlugins(builder, cfg, mailer)
	if err != nil {
		return nil, err
	}

	return builder, nil
}

// firstNonEmpty returns a if it is non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// resolveAESKey loads a 32-byte AES key from the named env var. It accepts the
// base64-std form emitted by `yauth gen-secrets`, or a raw 32-byte value.
func resolveAESKey(envName string) ([32]byte, error) {
	var key [32]byte
	raw := os.Getenv(envName)
	if raw == "" {
		return key, fmt.Errorf("env %q is empty or unset", envName)
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	if len(raw) == 32 {
		copy(key[:], raw)
		return key, nil
	}
	return key, fmt.Errorf("env %q must hold a base64-encoded 32-byte key (or 32 raw bytes)", envName)
}

// buildOAuthProviders maps the yaml provider catalog onto concrete
// oauth.Provider implementations, resolving client credentials from env. The
// map key is the provider slug: "google" and "github" use the built-in
// constructors; any other name is treated as a generic OIDC provider whose
// endpoints are discovered from issuer_url.
func buildOAuthProviders(c yauthcfg.OAuthPluginConfig) ([]oauth.Provider, error) {
	var provs []oauth.Provider
	for name, pc := range c.Providers {
		if !pc.Enabled {
			continue
		}
		clientID := os.Getenv(pc.ClientIDEnv)
		clientSecret := os.Getenv(pc.ClientSecretEnv)
		switch name {
		case "google":
			provs = append(provs, providers.Google(providers.GoogleConfig{
				ClientID: clientID, ClientSecret: clientSecret,
				RedirectURL: pc.RedirectURL, Scopes: pc.Scopes,
			}))
		case "github":
			provs = append(provs, providers.GitHub(providers.GitHubConfig{
				ClientID: clientID, ClientSecret: clientSecret,
				RedirectURL: pc.RedirectURL, Scopes: pc.Scopes,
			}))
		default:
			p, err := providers.OIDC(providers.OIDCConfig{
				ProviderName: name, ClientID: clientID, ClientSecret: clientSecret,
				RedirectURL: pc.RedirectURL, Scopes: pc.Scopes, DiscoveryURL: pc.IssuerURL,
			})
			if err != nil {
				return nil, fmt.Errorf("yauth: oauth provider %q: %w", name, err)
			}
			provs = append(provs, p)
		}
	}
	return provs, nil
}

// addAuthPlugins wires every enabled plugin beyond email_password from the
// declarative config onto the builder, resolving secrets/keys from the
// environment. Returns the first construction error. Plugins are added in the
// same order as yauthcfg.EnabledPlugins so asymjwt's signer is registered
// before oidc/oauth2server (which read it).
func addAuthPlugins(builder *YAuthBuilder, cfg *yauthcfg.Config, mailer *smtpmailer.Mailer) (*YAuthBuilder, error) {
	p := &cfg.Plugins

	// One IdP issuer/base-path, applied to both oidc and oauth2server so their
	// metadata can never disagree. Either plugin's field, or server.*, sets it.
	idpIssuer := firstNonEmpty(firstNonEmpty(p.OAuth2Server.Issuer, p.OIDC.Issuer), cfg.Server.BaseURL)
	idpBasePath := firstNonEmpty(firstNonEmpty(p.OAuth2Server.BasePath, p.OIDC.BasePath), cfg.Server.Prefix)

	if p.Bearer.Enabled {
		secret := []byte(os.Getenv(p.Bearer.JWTSecretEnv))
		if len(secret) == 0 {
			return nil, fmt.Errorf("yauth: bearer enabled but env %q is empty or unset", p.Bearer.JWTSecretEnv)
		}
		builder = builder.WithJWTSecret(secret)
		builder = builder.WithPlugin(bearer.New(bearer.Config{
			AccessTTL:  p.Bearer.AccessTTL,
			RefreshTTL: p.Bearer.RefreshTTL,
			Issuer:     p.Bearer.Issuer,
		}))
	}

	if p.APIKey.Enabled {
		builder = builder.WithPlugin(apikey.New(apikey.Config{
			Prefix:         p.APIKey.Prefix,
			MaxKeysPerUser: p.APIKey.MaxKeysPerUser,
		}))
	}

	if p.MagicLink.Enabled {
		mlCfg := magiclink.Config{TokenTTL: p.MagicLink.TTL}
		if mailer != nil {
			mlCfg.Mailer = mailer
		}
		builder = builder.WithPlugin(magiclink.New(mlCfg))
	}

	if p.AccountLock.Enabled {
		lkCfg := lockout.Config{
			MaxAttempts:        p.AccountLock.MaxAttempts,
			MaxLockoutDuration: p.AccountLock.MaxLockoutDuration,
			AutoUnlock:         p.AccountLock.AutoUnlock,
		}
		if p.AccountLock.LockoutDuration > 0 {
			lkCfg.LockoutDurations = []time.Duration{p.AccountLock.LockoutDuration}
		}
		if mailer != nil {
			lkCfg.Mailer = mailer
		}
		builder = builder.WithPlugin(lockout.New(lkCfg))
	}

	if p.Status.Enabled {
		builder = builder.WithPlugin(status.New())
	}

	if p.Admin.Enabled {
		builder = builder.WithPlugin(admin.New())
	}

	if p.MFA.Enabled {
		key, err := resolveAESKey(p.MFA.EncryptionKeyEnv)
		if err != nil {
			return nil, fmt.Errorf("yauth: mfa encryption key: %w", err)
		}
		plug, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: p.MFA.Issuer})
		if err != nil {
			return nil, fmt.Errorf("yauth: mfa: %w", err)
		}
		builder = builder.WithPlugin(plug)
	}

	if p.Passkey.Enabled {
		plug, err := passkey.New(passkey.Config{
			RPID:      p.Passkey.RPID,
			RPName:    p.Passkey.RPName,
			RPOrigins: []string{p.Passkey.RPOrigin},
		})
		if err != nil {
			return nil, fmt.Errorf("yauth: passkey: %w", err)
		}
		builder = builder.WithPlugin(plug)
	}

	if p.OAuth.Enabled {
		key, err := resolveAESKey(p.OAuth.EncryptionKeyEnv)
		if err != nil {
			return nil, fmt.Errorf("yauth: oauth encryption key: %w", err)
		}
		provs, err := buildOAuthProviders(p.OAuth)
		if err != nil {
			return nil, err
		}
		plug, err := oauth.New(oauth.Config{EncryptionKey: key, Providers: provs})
		if err != nil {
			return nil, fmt.Errorf("yauth: oauth: %w", err)
		}
		builder = builder.WithPlugin(plug)
	}

	if p.Webhooks.Enabled {
		builder = builder.WithPlugin(webhooks.New(webhooks.Config{
			MaxAttempts: p.Webhooks.MaxAttempts,
		}))
	}

	if p.AsymJWT.Enabled {
		asymCfg := asymjwt.Config{
			KeyType:        strings.ToUpper(p.AsymJWT.KeyType), // builder wants JWS-canonical uppercase
			KID:            p.AsymJWT.KeyID,
			PrivateKeyPath: p.AsymJWT.PrivateKeyPath,
			PublicKeyPath:  p.AsymJWT.PublicKeyPath,
		}
		if p.AsymJWT.PrivateKeyPEMEnv != "" {
			asymCfg.PrivateKeyPEM = []byte(os.Getenv(p.AsymJWT.PrivateKeyPEMEnv))
		}
		if p.AsymJWT.PublicKeyPEMEnv != "" {
			asymCfg.PublicKeyPEM = []byte(os.Getenv(p.AsymJWT.PublicKeyPEMEnv))
		}
		plug, err := asymjwt.New(asymCfg)
		if err != nil {
			return nil, fmt.Errorf("yauth: asym_jwt: %w", err)
		}
		builder = builder.WithPlugin(plug)
	}

	if p.OIDC.Enabled {
		builder = builder.WithPlugin(oidc.New(oidc.Config{
			Issuer:          idpIssuer,
			BasePath:        idpBasePath,
			IDTokenTTL:      p.OIDC.IDTokenTTL,
			ClaimsSupported: p.OIDC.ClaimsSupported,
		}))
	}

	if p.OAuth2Server.Enabled {
		builder = builder.WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:                      idpIssuer,
			BasePath:                    idpBasePath,
			AccessTTL:                   p.OAuth2Server.AccessTTL,
			RefreshTTL:                  p.OAuth2Server.RefreshTTL,
			AuthCodeTTL:                 p.OAuth2Server.AuthorizationCodeTTL,
			DeviceCodeTTL:               p.OAuth2Server.DeviceCodeTTL,
			DevicePollInterval:          p.OAuth2Server.DevicePollInterval,
			VerificationURI:             p.OAuth2Server.VerificationURI,
			ConsentRequired:             p.OAuth2Server.ConsentRequired,
			DCREnabled:                  p.OAuth2Server.DCREnabled,
			DCRRequireAdminForLoopback:  p.OAuth2Server.DCRRequireAdminForLoopback,
			DCRAllowConfidentialClients: p.OAuth2Server.DCRAllowConfidentialClients,
			AllowPrivateNetworkJWKSURI:  p.OAuth2Server.AllowPrivateNetworkJWKSURI,
			BackchannelLogoutTimeout:    p.OAuth2Server.BackchannelLogoutTimeout,
			DCRStaleClientTTL:           p.OAuth2Server.DCRStaleClientTTL,
			DCRStaleSweepInterval:       p.OAuth2Server.DCRStaleSweepInterval,
		}))
	}

	return builder, nil
}

// Migrate opens the database described by cfg and applies all pending
// migrations. Only driver="pgx" has migrations (goose); driver="memory" is
// in-process and needs none. Intended for the CLI and for tests; production
// should run `yauth migrate` as a separate job.
func Migrate(ctx context.Context, cfg *yauthcfg.Config) error {
	if cfg == nil {
		return errors.New("yauth: Migrate requires a non-nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("yauth: invalid config: %w", err)
	}
	switch cfg.Database.Driver {
	case "memory", "mem":
		return nil // in-memory backend has no schema to migrate
	case "pgx":
		sqlDB, err := openSQLDB(ctx, cfg.Database)
		if err != nil {
			return err
		}
		return yauthMigrate.Run(ctx, sqlDB, "pgx")
	default:
		return fmt.Errorf("yauth: unsupported database driver %q (supported: pgx, memory)", cfg.Database.Driver)
	}
}

// SchemaCheck connects to the database and verifies that the tables
// required by the enabled plugins are present. Returns a non-nil error
// listing any missing tables. Use it as a preflight check at app
// startup or in CI to catch unmigrated environments.
func SchemaCheck(ctx context.Context, cfg *yauthcfg.Config) error {
	if cfg == nil {
		return errors.New("yauth: SchemaCheck requires a non-nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("yauth: invalid config: %w", err)
	}
	if d := cfg.Database.Driver; d == "memory" || d == "mem" {
		return nil // in-memory backend always has every table
	}
	sqlDB, err := openSQLDB(ctx, cfg.Database)
	if err != nil {
		return err
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("yauth: database unreachable: %w", err)
	}

	have, err := listTables(ctx, sqlDB, cfg.Database.Driver, cfg.Database.Schema)
	if err != nil {
		return fmt.Errorf("yauth: list tables: %w", err)
	}
	haveSet := make(map[string]struct{}, len(have))
	for _, t := range have {
		haveSet[t] = struct{}{}
	}

	var missing []string
	for _, want := range cfg.ExpectedTables() {
		if _, ok := haveSet[want]; !ok {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("yauth: schema drift — missing tables: %s (run `yauth migrate`)", strings.Join(missing, ", "))
	}
	return nil
}

// openSQLDB returns a *sql.DB for the pgx driver — the only SQL backend.
// Used by Migrate and SchemaCheck. The in-memory backend has no *sql.DB.
func openSQLDB(ctx context.Context, d yauthcfg.DatabaseConfig) (*sql.DB, error) {
	if d.Driver != "pgx" {
		return nil, fmt.Errorf("yauth: SQL operations require driver=pgx, got %q", d.Driver)
	}
	pool, err := pgxrepo.Open(ctx, d.DSN)
	if err != nil {
		return nil, err
	}
	return pgxrepo.StdDB(pool), nil
}

func listTables(ctx context.Context, db *sql.DB, driver, schema string) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch driver {
	case "postgres", "pgx":
		pgSchema := schema
		if pgSchema == "" {
			pgSchema = "public"
		}
		rows, err = db.QueryContext(ctx, "SELECT tablename FROM pg_tables WHERE schemaname=$1 AND tablename LIKE 'yauth_%'", pgSchema)
	default:
		return nil, fmt.Errorf("listTables: unsupported driver %q", driver)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func configToYAuthConfig(c *yauthcfg.Config) YAuthConfig {
	out := NewDefaultConfig()
	if c.Session.TTL > 0 {
		out.SessionTTL = c.Session.TTL
	}
	if c.Session.CookieName != "" {
		out.CookieName = c.Session.CookieName
	}
	if c.Session.CookiePath != "" {
		out.CookiePath = c.Session.CookiePath
	}
	out.CookieDomain = c.Session.CookieDomain
	out.CookieSecure = c.Session.CookieSecure
	if c.Session.CookieSameSite != "" {
		out.CookieSameSite = c.Session.CookieSameSite
	}
	out.BaseURL = c.Server.BaseURL
	if c.Server.AllowSignups != nil {
		out.AllowSignups = *c.Server.AllowSignups
	}
	out.AutoAdminFirstUser = c.Server.AutoAdminFirstUser
	out.CORS = CORSConfig{
		AllowedOrigins:   c.Server.CORS.AllowedOrigins,
		AllowedMethods:   c.Server.CORS.AllowedMethods,
		AllowedHeaders:   c.Server.CORS.AllowedHeaders,
		AllowCredentials: c.Server.CORS.AllowCredentials,
		MaxAge:           c.Server.CORS.MaxAge,
	}
	out.SessionBinding = SessionBindingConfig{
		BindIP:           c.Session.BindIP,
		BindUA:           c.Session.BindUserAgent,
		IPMismatchAction: c.Session.IPMismatchAction,
		UAMismatchAction: c.Session.UAMismatchAction,
	}
	out.AllowAdminMachineCallers = c.Plugins.Admin.AllowMachineCallers
	overrideRule(&out.RateLimit.Login, c.RateLimit.Login)
	overrideRule(&out.RateLimit.Register, c.RateLimit.Register)
	overrideRule(&out.RateLimit.ForgotPassword, c.RateLimit.ForgotPassword)
	overrideRule(&out.RateLimit.MagicLinkSend, c.RateLimit.MagicLinkSend)
	overrideRule(&out.RateLimit.UnlockRequest, c.RateLimit.UnlockRequest)
	overrideRule(&out.RateLimit.MFAVerify, c.RateLimit.MFAVerify)
	return out
}

// buildMailer translates the cfg into a concrete mailer. Returns nil when
// no provider is configured (callers fall back to the plugin's default
// LoggingMailer). The returned *smtp.Mailer satisfies the Mailer interface
// of every plugin that needs a mailer.
func buildMailer(cfg yauthcfg.MailerConfig) (*smtpmailer.Mailer, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" || provider == "logging" {
		return nil, nil
	}
	if provider != "smtp" {
		return nil, fmt.Errorf("yauth: unsupported mailer.provider %q (logging | smtp)", cfg.Provider)
	}
	if cfg.SMTP.Host == "" || cfg.SMTP.Port == 0 {
		return nil, errors.New("yauth: mailer.smtp requires host and port")
	}
	if cfg.From == "" {
		return nil, errors.New("yauth: mailer.from is required when provider=smtp")
	}
	user := ""
	pass := ""
	if cfg.SMTP.UsernameEnv != "" {
		user = os.Getenv(cfg.SMTP.UsernameEnv)
	}
	if cfg.SMTP.PasswordEnv != "" {
		pass = os.Getenv(cfg.SMTP.PasswordEnv)
	}
	return smtpmailer.New(smtpmailer.Mailer{
		Host:     cfg.SMTP.Host,
		Port:     cfg.SMTP.Port,
		Username: user,
		Password: pass,
		From:     cfg.From,
		TLS:      cfg.SMTP.TLS,
	}), nil
}

func overrideRule(dst *RateLimitRule, src yauthcfg.RateLimitRule) {
	if src.Max > 0 {
		dst.Max = src.Max
	}
	if src.Window > 0 {
		dst.Window = src.Window
	}
}

// buildCacheDecorator wraps inner with the read-cache decorator selected
// by cfg. Today only cfg.Provider="redis" is supported. The Redis client
// is constructed but not pinged here; the decorator degrades to inner-only
// reads when Redis is unreachable, so a cold Redis at startup does not
// take the whole server down.
func buildCacheDecorator(inner yauthrepo.Repository, cfg yauthcfg.CacheConfig) (yauthrepo.Repository, error) {
	switch cfg.Provider {
	case "redis":
		password := ""
		if cfg.RedisPasswordEnv != "" {
			password = os.Getenv(cfg.RedisPasswordEnv)
		}
		client := redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: password,
			DB:       cfg.RedisDB,
		})
		opts := redisrepo.Options{
			KeyPrefix:            cfg.KeyPrefix,
			DisableNegativeCache: cfg.DisableNegativeCache,
		}
		return redisrepo.New(inner, client, opts), nil
	default:
		return nil, fmt.Errorf("yauth: unsupported cache.provider %q", cfg.Provider)
	}
}
