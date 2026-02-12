use crate::auth::{email::EmailService, rate_limit::RateLimiter};
use crate::config::YAuthConfig;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::stores::{ChallengeStore, RateLimitStore};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[derive(Clone)]
pub struct YAuthState {
    pub db: DatabaseConnection,
    pub config: Arc<YAuthConfig>,
    pub dummy_hash: String,
    pub rate_limiter: RateLimiter,
    pub challenge_store: Arc<dyn ChallengeStore>,
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    pub email_service: Option<EmailService>,
    pub plugins: Arc<Vec<Box<dyn YAuthPlugin>>>,
    #[cfg(feature = "email-password")]
    pub email_password_config: crate::config::EmailPasswordConfig,
    #[cfg(feature = "bearer")]
    pub bearer_config: crate::config::BearerConfig,
    #[cfg(feature = "mfa")]
    pub mfa_config: crate::config::MfaConfig,
    #[cfg(feature = "oauth")]
    pub oauth_config: crate::config::OAuthConfig,
}

impl YAuthState {
    /// Emit an event to all plugins and return the first non-Continue response.
    pub fn emit_event(&self, event: &AuthEvent) -> EventResponse {
        let ctx = PluginContext::new(self);
        for plugin in self.plugins.iter() {
            let response = plugin.on_event(event, &ctx);
            match response {
                EventResponse::Continue => continue,
                other => return other,
            }
        }
        EventResponse::Continue
    }
}
