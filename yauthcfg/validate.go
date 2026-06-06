package yauthcfg

import (
	"fmt"
	"strings"
)

// Validate walks the config and returns the first error encountered.
// A non-nil result means the config is unsuitable for NewFromConfig.
func (c *Config) Validate() error {
	switch c.Database.Driver {
	case "sqlite", "postgres", "mysql", "pgx", "memory", "mem":
	case "":
		return fmt.Errorf("database.driver is required (sqlite | postgres | mysql | pgx | memory)")
	default:
		return fmt.Errorf("database.driver %q is not supported (sqlite | postgres | mysql | pgx | memory)", c.Database.Driver)
	}
	// The in-memory backend (memrepo) is non-persistent and needs no DSN.
	if c.Database.Driver != "memory" && c.Database.Driver != "mem" && c.Database.DSN == "" {
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
	if p.EmailPassword.BootstrapAdmin.Enabled && strings.TrimSpace(p.EmailPassword.BootstrapAdmin.Email) == "" {
		return fmt.Errorf("plugins.email_password.bootstrap_admin.email is required when bootstrap_admin is enabled")
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
		// Accept either case: the Go builder uses the JWS-canonical uppercase
		// ("RS256"/"ES256"), so authors who copy that into yaml shouldn't be
		// rejected for casing.
		switch strings.ToLower(p.AsymJWT.KeyType) {
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
	if p.OAuth.Enabled && p.OAuth.EncryptionKeyEnv == "" {
		return fmt.Errorf("plugins.oauth.encryption_key_env is required when oauth is enabled")
	}
	if p.OAuth2Server.Enabled {
		if p.OAuth2Server.AccessTTL < 0 || p.OAuth2Server.BackchannelLogoutTimeout < 0 ||
			p.OAuth2Server.AuthorizationCodeTTL < 0 || p.OAuth2Server.DeviceCodeTTL < 0 {
			return fmt.Errorf("plugins.oauth2_server TTL/timeout values must be non-negative")
		}
	}
	// oidc and oauth2_server are one IdP: their issuer / base_path must agree.
	// NewFromConfig shares a single resolved value across both, so a config that
	// sets them to conflicting values is a bug — reject it rather than silently
	// picking one. Setting only one (or neither, falling back to server.*) is fine.
	if p.OIDC.Enabled && p.OAuth2Server.Enabled {
		if p.OIDC.Issuer != "" && p.OAuth2Server.Issuer != "" && p.OIDC.Issuer != p.OAuth2Server.Issuer {
			return fmt.Errorf("plugins.oidc.issuer (%q) and plugins.oauth2_server.issuer (%q) must match — set only one (or server.base_url) and the other inherits it", p.OIDC.Issuer, p.OAuth2Server.Issuer)
		}
		if p.OIDC.BasePath != "" && p.OAuth2Server.BasePath != "" && p.OIDC.BasePath != p.OAuth2Server.BasePath {
			return fmt.Errorf("plugins.oidc.base_path (%q) and plugins.oauth2_server.base_path (%q) must match — set only one (or server.prefix)", p.OIDC.BasePath, p.OAuth2Server.BasePath)
		}
	}

	// scim is organization-scoped: its bearer credential is an org-scoped API key
	// minted via the organizations plugin, so scim without organizations cannot
	// authenticate any request.
	if p.SCIM.Enabled && !p.Organizations.Enabled {
		return fmt.Errorf("plugins.scim requires plugins.organizations (SCIM is organization-scoped)")
	}
	// organizations + scim mint and validate org-scoped API keys through the
	// api-key resolver, so the api_key plugin must be enabled to recognise them.
	if (p.Organizations.Enabled || p.SCIM.Enabled) && !p.APIKey.Enabled {
		return fmt.Errorf("plugins.organizations/scim require plugins.api_key (org-scoped keys validate through the api-key resolver)")
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

// DeprecationWarnings returns advisories for deprecated config fields that are
// SET to a meaningful (non-zero) value. They are accepted for backward
// compatibility but ignored, so flag them rather than silently dropping intent.
// A zero/absent value (e.g. the `require_pkce: false` older scaffolds wrote)
// produces no warning. Surfaced by `yauth check`/`status` and at NewFromConfig
// startup; never fatal.
func (c *Config) DeprecationWarnings() []string {
	var w []string
	if c.Plugins.OAuth2Server.RequirePKCE {
		w = append(w, "plugins.oauth2_server.require_pkce is deprecated and ignored — PKCE (S256) is always enforced; remove it")
	}
	if c.Plugins.APIKey.HeaderName != "" {
		w = append(w, "plugins.api_key.header_name is deprecated and ignored — the credential header is always X-Api-Key; remove it")
	}
	if c.Plugins.Webhooks.DefaultSecretEnv != "" {
		w = append(w, "plugins.webhooks.default_secret_env is deprecated and ignored — webhook secrets are issued per-endpoint; remove it")
	}
	return w
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
	if p.Organizations.Enabled {
		out = append(out, "organizations")
	}
	if p.SCIM.Enabled {
		out = append(out, "scim")
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
	// organizations brings the multi-tenant + group tables; scim operates over
	// those same tables (org-scoped users/groups) and adds none of its own.
	if p.Organizations.Enabled {
		base = append(base,
			"yauth_organizations",
			"yauth_memberships",
			"yauth_invitations",
			"yauth_groups",
			"yauth_group_members",
			"yauth_organization_domains",
			"yauth_organization_policies",
		)
	}
	return base
}
