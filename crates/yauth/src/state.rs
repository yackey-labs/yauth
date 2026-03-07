use crate::auth::{email::EmailService, rate_limit::RateLimiter};
use crate::config::YAuthConfig;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::stores::{ChallengeStore, RateLimitStore};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, PaginatorTrait, Set};
use std::sync::Arc;
use uuid::Uuid;

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
    #[cfg(feature = "magic-link")]
    pub magic_link_config: crate::config::MagicLinkConfig,
    #[cfg(feature = "oauth2-server")]
    pub oauth2_server_config: crate::config::OAuth2ServerConfig,
    #[cfg(feature = "account-lockout")]
    pub account_lockout_config: crate::config::AccountLockoutConfig,
    #[cfg(feature = "oidc")]
    pub oidc_config: crate::config::OidcConfig,
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

    /// Returns true if auto_admin_first_user is enabled and no users exist yet.
    pub async fn should_auto_admin(&self) -> bool {
        if !self.config.auto_admin_first_user {
            return false;
        }
        let count = yauth_entity::users::Entity::find()
            .count(&self.db)
            .await
            .unwrap_or(1);
        count == 0
    }

    /// Write an audit log entry (best-effort, never fails the caller).
    pub async fn write_audit_log(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        metadata: Option<serde_json::Value>,
        ip_address: Option<String>,
    ) {
        let entry = yauth_entity::audit_log::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            event_type: Set(event_type.to_string()),
            metadata: Set(metadata),
            ip_address: Set(ip_address),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        };
        if let Err(e) = entry.insert(&self.db).await {
            tracing::error!("Failed to write audit log: {}", e);
        }
    }
}
