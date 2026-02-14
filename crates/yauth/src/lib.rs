pub mod auth;
pub mod config;
pub mod error;
pub mod middleware;
pub mod plugin;
pub mod state;
pub mod stores;

pub mod plugins;
pub mod routes_meta;

#[cfg(feature = "telemetry")]
pub mod telemetry;

// Re-export entity and migration crates
pub use yauth_entity as entity;
pub use yauth_migration as migration;

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
use state::YAuthState;
use stores::StoreBackend;

pub struct YAuth {
    state: YAuthState,
}

impl YAuth {
    pub fn router(&self) -> Router<YAuthState> {
        let ctx = plugin::PluginContext::new(&self.state);
        let mut public_router = Router::new();
        let mut protected_router = Router::new();

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

        public_router.merge(protected_router)
    }

    pub fn state(&self) -> &YAuthState {
        &self.state
    }

    pub fn into_state(self) -> YAuthState {
        self.state
    }
}

pub struct YAuthBuilder {
    db: sea_orm::DatabaseConnection,
    config: YAuthConfig,
    plugins: Vec<Box<dyn YAuthPlugin>>,
    store_backend: StoreBackend,
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
}

impl YAuthBuilder {
    pub fn new(db: sea_orm::DatabaseConnection, config: YAuthConfig) -> Self {
        Self {
            db,
            config,
            plugins: Vec::new(),
            store_backend: StoreBackend::Memory,
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

    pub fn with_store_backend(mut self, backend: StoreBackend) -> Self {
        self.store_backend = backend;
        self
    }

    pub fn with_plugin(mut self, plugin: Box<dyn YAuthPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    #[allow(unused_mut)]
    pub fn build(mut self) -> YAuth {
        // Build dummy hash for timing-safe login
        let dummy_hash = auth::password::hash_password("dummy-password-for-timing")
            .expect("Failed to generate dummy hash");

        // Build rate limiter
        let rate_limiter = auth::rate_limit::RateLimiter::new(10, 60);

        // Build challenge store
        let challenge_store: std::sync::Arc<dyn stores::ChallengeStore> = match self.store_backend {
            StoreBackend::Memory => {
                std::sync::Arc::new(stores::memory::MemoryChallengeStore::new())
            }
            StoreBackend::Postgres => std::sync::Arc::new(
                stores::postgres::PostgresChallengeStore::new(self.db.clone()),
            ),
        };

        // Build rate limit store
        let rate_limit_store: std::sync::Arc<dyn stores::RateLimitStore> = match self.store_backend
        {
            StoreBackend::Memory => {
                std::sync::Arc::new(stores::memory::MemoryRateLimitStore::new(10, 60))
            }
            StoreBackend::Postgres => std::sync::Arc::new(
                stores::postgres::PostgresRateLimitStore::new(self.db.clone()),
            ),
        };

        // Build email service
        let email_service = self.config.smtp.as_ref().map(|smtp| {
            auth::email::EmailService::new(
                smtp.host.clone(),
                smtp.port,
                smtp.from.clone(),
                self.config.base_url.clone(),
            )
        });

        // Build the plugins list before constructing state
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
            db: self.db,
            config: std::sync::Arc::new(self.config),
            dummy_hash,
            rate_limiter,
            challenge_store,
            rate_limit_store,
            email_service,
            plugins: std::sync::Arc::new(Vec::new()), // placeholder, replaced below
            #[cfg(feature = "email-password")]
            email_password_config: self.email_password_config.clone().unwrap_or_default(),
            #[cfg(feature = "bearer")]
            bearer_config: self
                .bearer_config
                .clone()
                .unwrap_or_else(|| config::BearerConfig {
                    jwt_secret: String::new(),
                    access_token_ttl: std::time::Duration::from_secs(900),
                    refresh_token_ttl: std::time::Duration::from_secs(30 * 24 * 3600),
                }),
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
                .push(Box::new(plugins::magic_link::MagicLinkPlugin::new(ml_config)));
        }

        // Now set the real plugins on state
        let mut state = state;
        state.plugins = std::sync::Arc::new(self.plugins);

        YAuth { state }
    }
}
