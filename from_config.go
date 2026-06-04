package yauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	yauthMigrate "github.com/yackey-labs/yauth/migrate"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	smtpmailer "github.com/yackey-labs/yauth/plugins/mailer/smtp"
	yauthrepo "github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/repo/pgxrepo"
	"github.com/yackey-labs/yauth/repo/redisrepo"
	"github.com/yackey-labs/yauth/telemetry"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// NewFromConfig builds a fully-wired *YAuth from a yauthcfg.Config.
//
// Migration policy: NewFromConfig NEVER calls AutoMigrate by default.
// Run `yauth migrate` (cmd/yauth) as a one-shot job before rolling out
// app replicas — concurrent AutoMigrate calls race in multi-replica
// deployments. The optional cfg.Database.AutoMigrate flag overrides
// this for development only and prints a stderr warning when set.
//
// Supported plugins for NewFromConfig today: email_password, telemetry.
// Bearer/api-key/etc. land in subsequent tasks (#10–#19) and will be
// wired into the same switch-by-section structure below.
func NewFromConfig(ctx context.Context, cfg *yauthcfg.Config) (*YAuth, error) {
	if cfg == nil {
		return nil, errors.New("yauth: NewFromConfig requires a non-nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("yauth: invalid config: %w", err)
	}

	var repo yauthrepo.Repository

	switch cfg.Database.Driver {
	case "memory", "mem":
		// In-process, non-persistent backend (no DSN, no migrations). For dev,
		// tests, and ephemeral throwaway instances — data is lost on restart and
		// it is single-process only.
		repo = memrepo.New()
	case "pgx":
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
			fmt.Fprintln(os.Stderr, "yauth: WARNING database.auto_migrate=true is for DEV/TEST only — use `yauth migrate` in production")
			if err := yauthMigrate.Run(ctx, pgxrepo.StdDB(pool), "pgx"); err != nil {
				return nil, fmt.Errorf("yauth: auto_migrate failed: %w", err)
			}
		}
		repo = pgxrepo.New(pool)
	default:
		return nil, fmt.Errorf("yauth: unsupported database driver %q (supported: pgx, memory)", cfg.Database.Driver)
	}
	if cfg.Cache.Enabled {
		decorated, err := buildCacheDecorator(repo, cfg.Cache)
		if err != nil {
			return nil, err
		}
		repo = decorated
	}
	builder := New(repo, configToYAuthConfig(cfg))

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

	// TODO(#10) bearer plugin wiring
	// TODO(#11) api-key plugin wiring
	// TODO(#12) magic-link / account-lock plugin wiring
	// TODO(#13) status / admin plugin wiring
	// TODO(#14) mfa plugin wiring
	// TODO(#15) passkey plugin wiring
	// TODO(#16) oauth client plugin wiring
	// TODO(#17) webhooks plugin wiring
	// TODO(#18) asym-jwt / oidc plugin wiring
	// TODO(#19) oauth2-server plugin wiring

	return builder.Build()
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
