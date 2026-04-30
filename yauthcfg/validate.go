package yauthcfg

import "fmt"

// Validate walks the config and returns the first error encountered.
// A non-nil result means the config is unsuitable for NewFromConfig.
func (c *Config) Validate() error {
	switch c.Database.Driver {
	case "sqlite", "postgres", "mysql":
	case "":
		return fmt.Errorf("database.driver is required (sqlite | postgres | mysql)")
	default:
		return fmt.Errorf("database.driver %q is not supported (sqlite | postgres | mysql)", c.Database.Driver)
	}
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}

	if c.Session.TTL < 0 {
		return fmt.Errorf("session.ttl must be non-negative")
	}
	if css := c.Session.CookieSameSite; css != "" {
		switch css {
		case "lax", "strict", "none", "Lax", "Strict", "None":
		default:
			return fmt.Errorf("session.cookie_same_site %q invalid (lax | strict | none)", css)
		}
	}

	p := &c.Plugins
	if p.EmailPassword.Enabled && p.EmailPassword.MinPasswordLength < 0 {
		return fmt.Errorf("plugins.email_password.min_password_length must be non-negative")
	}
	if p.Bearer.Enabled {
		if p.Bearer.JWTSecretEnv == "" {
			return fmt.Errorf("plugins.bearer.jwt_secret_env is required when bearer is enabled")
		}
		if p.Bearer.AccessTTL < 0 || p.Bearer.RefreshTTL < 0 {
			return fmt.Errorf("plugins.bearer access_ttl/refresh_ttl must be non-negative")
		}
	}
	if p.MFA.Enabled && p.MFA.EncryptionKeyEnv == "" {
		return fmt.Errorf("plugins.mfa.encryption_key_env is required when mfa is enabled")
	}
	if p.AsymJWT.Enabled {
		switch p.AsymJWT.KeyType {
		case "rs256", "es256":
		default:
			return fmt.Errorf("plugins.asym_jwt.key_type %q invalid (rs256 | es256)", p.AsymJWT.KeyType)
		}
		havePrivPath := p.AsymJWT.PrivateKeyPath != ""
		havePrivEnv := p.AsymJWT.PrivateKeyPEMEnv != ""
		havePubPath := p.AsymJWT.PublicKeyPath != ""
		havePubEnv := p.AsymJWT.PublicKeyPEMEnv != ""
		if havePrivPath && havePrivEnv {
			return fmt.Errorf("plugins.asym_jwt private_key_path and private_key_pem_env are mutually exclusive")
		}
		if havePubPath && havePubEnv {
			return fmt.Errorf("plugins.asym_jwt public_key_path and public_key_pem_env are mutually exclusive")
		}
		if !havePrivPath && !havePrivEnv {
			return fmt.Errorf("plugins.asym_jwt requires private_key_path or private_key_pem_env")
		}
		if !havePubPath && !havePubEnv {
			return fmt.Errorf("plugins.asym_jwt requires public_key_path or public_key_pem_env")
		}
	}
	if p.Passkey.Enabled && (p.Passkey.RPID == "" || p.Passkey.RPOrigin == "") {
		return fmt.Errorf("plugins.passkey requires rp_id and rp_origin")
	}

	if c.Cache.Enabled {
		switch c.Cache.Provider {
		case "redis":
			if c.Cache.RedisAddr == "" {
				return fmt.Errorf("cache.redis_addr is required when cache.provider=redis")
			}
		case "":
			return fmt.Errorf("cache.provider is required when cache.enabled=true (redis)")
		default:
			return fmt.Errorf("cache.provider %q is not supported (redis)", c.Cache.Provider)
		}
	}

	return nil
}

// EnabledPlugins returns the names of plugins whose `enabled` flag is
// set, in the order NewFromConfig wires them. Useful for `yauth status`
// and `yauth check`.
func (c *Config) EnabledPlugins() []string {
	var out []string
	p := &c.Plugins
	if p.EmailPassword.Enabled {
		out = append(out, "email_password")
	}
	if p.Bearer.Enabled {
		out = append(out, "bearer")
	}
	if p.APIKey.Enabled {
		out = append(out, "api_key")
	}
	if p.MagicLink.Enabled {
		out = append(out, "magic_link")
	}
	if p.AccountLock.Enabled {
		out = append(out, "account_lock")
	}
	if p.Status.Enabled {
		out = append(out, "status")
	}
	if p.Admin.Enabled {
		out = append(out, "admin")
	}
	if p.MFA.Enabled {
		out = append(out, "mfa")
	}
	if p.Passkey.Enabled {
		out = append(out, "passkey")
	}
	if p.OAuth.Enabled {
		out = append(out, "oauth")
	}
	if p.Webhooks.Enabled {
		out = append(out, "webhooks")
	}
	if p.AsymJWT.Enabled {
		out = append(out, "asym_jwt")
	}
	if p.OIDC.Enabled {
		out = append(out, "oidc")
	}
	if p.OAuth2Server.Enabled {
		out = append(out, "oauth2_server")
	}
	return out
}

// ExpectedTables returns the table names a fully-migrated DB should
// contain for the enabled plugins. Currently the migrator creates all
// tables regardless of plugin set, so the baseline list is the same
// for any non-empty enabled plugin set; this function will tighten as
// migrations become per-plugin.
func (c *Config) ExpectedTables() []string {
	base := []string{
		"yauth_users",
		"yauth_sessions",
		"yauth_audit_log",
		"yauth_rate_limits",
		"yauth_revocations",
	}
	p := &c.Plugins
	if p.EmailPassword.Enabled {
		base = append(base,
			"yauth_passwords",
			"yauth_password_history",
			"yauth_email_verifications",
			"yauth_password_resets",
		)
	}
	if p.Bearer.Enabled {
		base = append(base, "yauth_refresh_tokens")
	}
	if p.APIKey.Enabled {
		base = append(base, "yauth_api_keys")
	}
	if p.MagicLink.Enabled {
		base = append(base, "yauth_magic_links")
	}
	if p.AccountLock.Enabled {
		base = append(base, "yauth_account_locks", "yauth_unlock_tokens")
	}
	if p.MFA.Enabled {
		base = append(base, "yauth_totp_secrets", "yauth_backup_codes", "yauth_challenges")
	}
	if p.Passkey.Enabled {
		base = append(base, "yauth_webauthn_credentials")
	}
	if p.OAuth.Enabled {
		base = append(base, "yauth_oauth_accounts", "yauth_oauth_states", "yauth_oidc_nonces")
	}
	if p.Webhooks.Enabled {
		base = append(base, "yauth_webhooks", "yauth_webhook_deliveries")
	}
	if p.OAuth2Server.Enabled {
		base = append(base,
			"yauth_oauth2_clients",
			"yauth_authorization_codes",
			"yauth_consents",
			"yauth_device_codes",
		)
	}
	return base
}
