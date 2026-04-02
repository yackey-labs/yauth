use crate::auth::{email::EmailService, rate_limit::RateLimiter};
use crate::config::YAuthConfig;
use crate::db::models::NewAuditLog;
use crate::db::schema::{yauth_audit_log, yauth_users};
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::stores::{ChallengeStore, RateLimitStore, RevocationStore, SessionStore};
use diesel::QueryDsl;
use diesel::result::OptionalExtension;
use std::sync::Arc;
use uuid::Uuid;

pub type DbPool =
    diesel_async_crate::pooled_connection::deadpool::Pool<diesel_async_crate::AsyncPgConnection>;

#[derive(Clone)]
pub struct YAuthState {
    pub db: DbPool,
    pub config: Arc<YAuthConfig>,
    pub dummy_hash: String,
    pub rate_limiter: RateLimiter,
    pub challenge_store: Arc<dyn ChallengeStore>,
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    pub session_store: Arc<dyn SessionStore>,
    pub revocation_store: Arc<dyn RevocationStore>,
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

    pub async fn should_auto_admin(&self) -> bool {
        if !self.config.auto_admin_first_user {
            return false;
        }
        let mut conn = match self.db.get().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        use diesel_async_crate::RunQueryDsl;
        let exists: Option<Uuid> = yauth_users::table
            .select(yauth_users::id)
            .first::<Uuid>(&mut conn)
            .await
            .optional()
            .unwrap_or(Some(Uuid::nil()));
        exists.is_none()
    }

    pub async fn write_audit_log(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        metadata: Option<serde_json::Value>,
        ip_address: Option<String>,
    ) {
        let mut conn = match self.db.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to get connection for audit log: {}", e);
                return;
            }
        };
        use diesel_async_crate::RunQueryDsl;
        let new_log = NewAuditLog {
            id: Uuid::new_v4(),
            user_id,
            event_type: event_type.to_string(),
            metadata,
            ip_address,
            created_at: chrono::Utc::now().naive_utc(),
        };
        let result = diesel::insert_into(yauth_audit_log::table)
            .values(&new_log)
            .execute(&mut conn)
            .await;
        if let Err(e) = result {
            tracing::error!("Failed to write audit log: {}", e);
        }
    }
}
