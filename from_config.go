package yauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/yackey-labs/yauth-go/auth/passwordpolicy"
	yauthMigrate "github.com/yackey-labs/yauth-go/migrate"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	smtpmailer "github.com/yackey-labs/yauth-go/plugins/mailer/smtp"
	yauthrepo "github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
	"github.com/yackey-labs/yauth-go/repo/pgxrepo"
	"github.com/yackey-labs/yauth-go/repo/redisrepo"
	"github.com/yackey-labs/yauth-go/telemetry"
	"github.com/yackey-labs/yauth-go/yauthcfg"
	"gorm.io/gorm"
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

	if cfg.Database.Driver == "pgx" {
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
	} else {
		db, err := openDB(cfg.Database)
		if err != nil {
			return nil, err
		}
		if err := pingDB(ctx, db); err != nil {
			return nil, fmt.Errorf("yauth: database unreachable: %w", err)
		}
		if cfg.Telemetry.Enabled {
			if err := gormrepo.ApplyOTel(db); err != nil {
				return nil, fmt.Errorf("yauth: gorm otel: %w", err)
			}
		}
		if cfg.Database.AutoMigrate {
			fmt.Fprintln(os.Stderr, "yauth: WARNING database.auto_migrate=true is for DEV/TEST only — use `yauth migrate` in production")
			if err := gormrepo.Migrate(ctx, db); err != nil {
				return nil, fmt.Errorf("yauth: auto_migrate failed: %w", err)
			}
		}
		repo = gormrepo.New(db)
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
		shutdown, err := telemetry.Init(ctx, telemetry.Config{
			Enabled:     true,
			Endpoint:    cfg.Telemetry.OTLPEndpoint,
			ServiceName: cfg.Telemetry.ServiceName,
		})
		if err != nil {
			return nil, fmt.Errorf("yauth: telemetry init: %w", err)
		}
		builder = builder.
			WithTelemetry(telemetry.Config{Enabled: true}).
			WithTelemetryShutdown(shutdown)
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
// migrations. For driver="pgx" goose migrations are used; all other drivers
// (sqlite, postgres, mysql) use gormrepo AutoMigrate. Intended for the CLI
// and for tests; production should run `yauth migrate` as a separate job.
func Migrate(ctx context.Context, cfg *yauthcfg.Config) error {
	if cfg == nil {
		return errors.New("yauth: Migrate requires a non-nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("yauth: invalid config: %w", err)
	}
	if cfg.Database.Driver == "pgx" {
		sqlDB, err := openSQLDB(ctx, cfg.Database)
		if err != nil {
			return err
		}
		return yauthMigrate.Run(ctx, sqlDB, "pgx")
	}
	db, err := openDB(cfg.Database)
	if err != nil {
		return err
	}
	return gormrepo.Migrate(ctx, db)
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

func openDB(d yauthcfg.DatabaseConfig) (*gorm.DB, error) {
	switch d.Driver {
	case "sqlite":
		return gormrepo.OpenSQLite(d.DSN)
	case "postgres":
		return gormrepo.OpenPostgresSchema(d.DSN, d.Schema)
	case "mysql":
		return gormrepo.OpenMySQL(d.DSN)
	default:
		return nil, fmt.Errorf("yauth: unsupported database driver %q (use gormrepo drivers: sqlite | postgres | mysql)", d.Driver)
	}
}

func pingDB(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// openSQLDB returns a *sql.DB for any supported driver. Used by Migrate and SchemaCheck.
func openSQLDB(ctx context.Context, d yauthcfg.DatabaseConfig) (*sql.DB, error) {
	if d.Driver == "pgx" {
		pool, err := pgxrepo.Open(ctx, d.DSN)
		if err != nil {
			return nil, err
		}
		return pgxrepo.StdDB(pool), nil
	}
	gdb, err := openDB(d)
	if err != nil {
		return nil, err
	}
	return gdb.DB()
}

func listTables(ctx context.Context, db *sql.DB, driver, schema string) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch driver {
	case "sqlite":
		rows, err = db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'yauth_%'")
	case "postgres", "pgx":
		pgSchema := schema
		if pgSchema == "" {
			pgSchema = "public"
		}
		rows, err = db.QueryContext(ctx, "SELECT tablename FROM pg_tables WHERE schemaname=$1 AND tablename LIKE 'yauth_%'", pgSchema)
	case "mysql":
		rows, err = db.QueryContext(ctx, "SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = DATABASE() AND TABLE_NAME LIKE 'yauth_%'")
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
