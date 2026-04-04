pub mod auth;
pub mod backends;
pub mod config;
pub mod domain;
pub mod error;
pub mod middleware;
pub mod plugin;
pub mod repo;
pub mod schema;
pub mod state;

pub(crate) mod otel;

pub mod plugins;
#[cfg(feature = "openapi")]
pub mod routes_meta;

#[cfg(feature = "telemetry")]
pub mod telemetry;

/// Validate a PostgreSQL schema name to prevent SQL injection.
/// PostgreSQL unquoted identifiers: `[a-z_][a-z0-9_$]*`, max 63 chars.
#[cfg(feature = "diesel-backend")]
pub(crate) fn validate_schema_name(
    name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if name.is_empty() || name.len() > 63 {
        return Err(format!("Invalid schema name '{}': must be 1-63 characters", name).into());
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first == b'_') {
        return Err(format!("Invalid schema name '{}': must start with a-z or _", name).into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(format!(
            "Invalid schema name '{}': only lowercase letters, digits, and underscores allowed",
            name
        )
        .into());
    }
    Ok(())
}

pub mod prelude {
    pub use crate::YAuthBuilder;
    pub use crate::config::*;
    pub use crate::error::{ApiError, api_err};
    pub use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
    pub use crate::state::YAuthState;
    pub use std::time::Duration;
}

use axum::Router;
use config::YAuthConfig;
use plugin::YAuthPlugin;
use repo::{DatabaseBackend, EnabledFeatures, RepoError};
use state::YAuthState;

pub struct YAuth {
    state: YAuthState,
}

impl YAuth {
    /// Get the merged declarative schema for all enabled plugins.
    ///
    /// Returns an error if there are duplicate table definitions or missing FK dependencies.
    pub fn schema(&self) -> Result<schema::YAuthSchema, schema::SchemaError> {
        let mut table_lists = vec![schema::core_schema()];
        for plugin in self.state.plugins.iter() {
            let s = plugin.schema();
            if !s.is_empty() {
                table_lists.push(s);
            }
        }
        schema::collect_schema(table_lists)
    }

    /// Generate DDL for the specified dialect.
    pub fn generate_ddl(&self, dialect: schema::Dialect) -> Result<String, schema::SchemaError> {
        let merged = self.schema()?;
        Ok(match dialect {
            schema::Dialect::Postgres => schema::generate_postgres_ddl(&merged),
            schema::Dialect::Sqlite => schema::generate_sqlite_ddl(&merged),
            schema::Dialect::Mysql => schema::generate_mysql_ddl(&merged),
        })
    }

    pub fn router(&self) -> Router<YAuthState> {
        let ctx = plugin::PluginContext::new(&self.state);
        let mut public_router = Router::new();
        let mut protected_router = Router::new();

        // Public core routes (config endpoint — no auth required)
        public_router = public_router.merge(crate::plugins::core_public_routes());

        // Core routes (session + logout) require authentication
        protected_router = protected_router.merge(crate::plugins::core_routes(&ctx));

        // Mount plugin routes — public and protected separately
        for plugin in self.state.plugins.iter() {
            if let Some(public) = plugin.public_routes(&ctx) {
                public_router = public_router.merge(public);
            }
            if let Some(protected) = plugin.protected_routes(&ctx) {
                protected_router = protected_router.merge(protected);
            }
        }

        // Apply auth middleware to all protected routes
        let protected_router = protected_router.layer(axum::middleware::from_fn_with_state(
            self.state.clone(),
            middleware::auth_middleware,
        ));

        public_router
            .merge(protected_router)
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1 MB
    }

    pub fn state(&self) -> &YAuthState {
        &self.state
    }

    pub fn into_state(self) -> YAuthState {
        self.state
    }
}

pub struct YAuthBuilder {
    backend: Box<dyn DatabaseBackend>,
    config: YAuthConfig,
    plugins: Vec<Box<dyn YAuthPlugin>>,
    #[cfg(feature = "email-password")]
    email_password_config: Option<config::EmailPasswordConfig>,
    #[cfg(feature = "passkey")]
    passkey_config: Option<config::PasskeyConfig>,
    #[cfg(feature = "mfa")]
    mfa_config: Option<config::MfaConfig>,
    #[cfg(feature = "oauth")]
    oauth_config: Option<config::OAuthConfig>,
    #[cfg(feature = "bearer")]
    bearer_config: Option<config::BearerConfig>,
    #[cfg(feature = "magic-link")]
    magic_link_config: Option<config::MagicLinkConfig>,
    #[cfg(feature = "oauth2-server")]
    oauth2_server_config: Option<config::OAuth2ServerConfig>,
    #[cfg(feature = "account-lockout")]
    account_lockout_config: Option<config::AccountLockoutConfig>,
    #[cfg(feature = "webhooks")]
    webhook_config: Option<config::WebhookConfig>,
    #[cfg(feature = "oidc")]
    oidc_config: Option<config::OidcConfig>,
}

impl YAuthBuilder {
    pub fn new(backend: impl DatabaseBackend + 'static, config: YAuthConfig) -> Self {
        Self {
            backend: Box::new(backend),
            config,
            plugins: Vec::new(),
            #[cfg(feature = "email-password")]
            email_password_config: None,
            #[cfg(feature = "passkey")]
            passkey_config: None,
            #[cfg(feature = "mfa")]
            mfa_config: None,
            #[cfg(feature = "oauth")]
            oauth_config: None,
            #[cfg(feature = "bearer")]
            bearer_config: None,
            #[cfg(feature = "magic-link")]
            magic_link_config: None,
            #[cfg(feature = "oauth2-server")]
            oauth2_server_config: None,
            #[cfg(feature = "account-lockout")]
            account_lockout_config: None,
            #[cfg(feature = "webhooks")]
            webhook_config: None,
            #[cfg(feature = "oidc")]
            oidc_config: None,
        }
    }

    #[cfg(feature = "email-password")]
    pub fn with_email_password(mut self, config: config::EmailPasswordConfig) -> Self {
        self.email_password_config = Some(config);
        self
    }

    #[cfg(feature = "passkey")]
    pub fn with_passkey(mut self, config: config::PasskeyConfig) -> Self {
        self.passkey_config = Some(config);
        self
    }

    #[cfg(feature = "mfa")]
    pub fn with_mfa(mut self, config: config::MfaConfig) -> Self {
        self.mfa_config = Some(config);
        self
    }

    #[cfg(feature = "bearer")]
    pub fn with_bearer(mut self, config: config::BearerConfig) -> Self {
        self.bearer_config = Some(config);
        self
    }

    #[cfg(feature = "oauth")]
    pub fn with_oauth(mut self, config: config::OAuthConfig) -> Self {
        self.oauth_config = Some(config);
        self
    }

    #[cfg(feature = "magic-link")]
    pub fn with_magic_link(mut self, config: config::MagicLinkConfig) -> Self {
        self.magic_link_config = Some(config);
        self
    }

    #[cfg(feature = "oauth2-server")]
    pub fn with_oauth2_server(mut self, config: config::OAuth2ServerConfig) -> Self {
        self.oauth2_server_config = Some(config);
        self
    }

    #[cfg(feature = "account-lockout")]
    pub fn with_account_lockout(mut self, config: config::AccountLockoutConfig) -> Self {
        self.account_lockout_config = Some(config);
        self
    }

    #[cfg(feature = "webhooks")]
    pub fn with_webhooks(mut self, config: config::WebhookConfig) -> Self {
        self.webhook_config = Some(config);
        self
    }

    #[cfg(feature = "oidc")]
    pub fn with_oidc(mut self, config: config::OidcConfig) -> Self {
        self.oidc_config = Some(config);
        self
    }

    #[cfg(feature = "api-key")]
    pub fn with_api_key(mut self) -> Self {
        self.plugins.push(Box::new(plugins::api_key::ApiKeyPlugin));
        self
    }

    #[cfg(feature = "admin")]
    pub fn with_admin(mut self) -> Self {
        self.plugins.push(Box::new(plugins::admin::AdminPlugin));
        self
    }

    #[cfg(feature = "status")]
    pub fn with_status(mut self) -> Self {
        self.plugins.push(Box::new(plugins::status::StatusPlugin));
        self
    }

    pub fn with_plugin(mut self, plugin: Box<dyn YAuthPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    #[allow(unused_mut)]
    pub async fn build(mut self) -> Result<YAuth, RepoError> {
        // Run migrations
        let features = EnabledFeatures::from_compile_flags();
        self.backend.migrate(&features).await?;

        // Build repositories from the backend — now includes all ephemeral stores
        let repos = self.backend.repositories();

        // Build dummy hash for timing-safe login
        let dummy_hash = auth::password::hash_password_sync("dummy-password-for-timing")
            .expect("Failed to generate dummy hash");

        // Build rate limiter
        let rate_limiter = auth::rate_limit::RateLimiter::new(10, 60);

        // Build email service
        let email_service = self.config.smtp.as_ref().map(|smtp| {
            auth::email::EmailService::new(
                smtp.host.clone(),
                smtp.port,
                smtp.from.clone(),
                self.config.base_url.clone(),
            )
        });

        // Build the plugins list before constructing state.
        // Account lockout must be registered BEFORE email-password so it
        // intercepts LoginSucceeded/LoginFailed events first.
        #[cfg(feature = "account-lockout")]
        if self.account_lockout_config.is_some() {
            self.plugins
                .insert(0, Box::new(plugins::account_lockout::AccountLockoutPlugin));
        }

        #[cfg(feature = "email-password")]
        if let Some(ref ep_config) = self.email_password_config {
            self.plugins.insert(
                0,
                Box::new(plugins::email_password::EmailPasswordPlugin::new(
                    ep_config.clone(),
                )),
            );
        }

        // Passkey needs state for WebAuthn init, but we need a temporary state ref.
        // Build a partial state first, then construct passkey plugin.
        let state = YAuthState {
            repos,
            config: std::sync::Arc::new(self.config),
            dummy_hash,
            rate_limiter,
            email_service,
            plugins: std::sync::Arc::new(Vec::new()), // placeholder, replaced below
            #[cfg(feature = "email-password")]
            email_password_config: self.email_password_config.clone().unwrap_or_default(),
            #[cfg(feature = "bearer")]
            bearer_config: {
                let cfg = self
                    .bearer_config
                    .clone()
                    .expect("Bearer feature requires .with_bearer(config)");
                if cfg.jwt_secret.is_empty() {
                    panic!(
                        "BearerConfig.jwt_secret must not be empty — tokens would be trivially forgeable"
                    );
                }
                cfg
            },
            #[cfg(feature = "mfa")]
            mfa_config: self.mfa_config.clone().unwrap_or_default(),
            #[cfg(feature = "oauth")]
            oauth_config: self
                .oauth_config
                .clone()
                .unwrap_or_else(|| config::OAuthConfig {
                    providers: Vec::new(),
                }),
            #[cfg(feature = "magic-link")]
            magic_link_config: self.magic_link_config.clone().unwrap_or_default(),
            #[cfg(feature = "oauth2-server")]
            oauth2_server_config: self.oauth2_server_config.clone().unwrap_or_default(),
            #[cfg(feature = "account-lockout")]
            account_lockout_config: self.account_lockout_config.clone().unwrap_or_default(),
            #[cfg(feature = "oidc")]
            oidc_config: self.oidc_config.clone().unwrap_or_default(),
        };

        #[cfg(feature = "passkey")]
        if let Some(pk_config) = self.passkey_config {
            let insert_pos = self
                .plugins
                .iter()
                .position(|p| p.name() != "email-password")
                .unwrap_or(self.plugins.len());
            self.plugins.insert(
                insert_pos,
                Box::new(plugins::passkey::PasskeyPlugin::new(pk_config, &state)),
            );
        }

        #[cfg(feature = "mfa")]
        if let Some(mfa_config) = self.mfa_config {
            self.plugins
                .push(Box::new(plugins::mfa::MfaPlugin::new(mfa_config)));
        }

        #[cfg(feature = "oauth")]
        if self.oauth_config.is_some() {
            self.plugins.push(Box::new(plugins::oauth::OAuthPlugin));
        }

        #[cfg(feature = "bearer")]
        if let Some(bearer_config) = self.bearer_config {
            self.plugins
                .push(Box::new(plugins::bearer::BearerPlugin::new(bearer_config)));
        }

        #[cfg(feature = "magic-link")]
        if let Some(ml_config) = self.magic_link_config {
            self.plugins
                .push(Box::new(plugins::magic_link::MagicLinkPlugin::new(
                    ml_config,
                )));
        }

        #[cfg(feature = "oauth2-server")]
        if let Some(o2s_config) = self.oauth2_server_config {
            self.plugins
                .push(Box::new(plugins::oauth2_server::OAuth2ServerPlugin::new(
                    o2s_config,
                )));
        }

        #[cfg(feature = "webhooks")]
        if let Some(wh_config) = self.webhook_config {
            self.plugins
                .push(Box::new(plugins::webhooks::WebhookPlugin::new(wh_config)));
        }

        #[cfg(feature = "oidc")]
        if let Some(oidc_config) = self.oidc_config {
            self.plugins
                .push(Box::new(plugins::oidc::OidcPlugin::new(oidc_config)));
        }

        // Now set the real plugins on state
        let mut state = state;
        state.plugins = std::sync::Arc::new(self.plugins);

        Ok(YAuth { state })
    }
}
