use crate::auth::email::EmailService;
use crate::config::YAuthConfig;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::repo::Repositories;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(all(feature = "admin", feature = "oauth2-server"))]
#[derive(Debug, Clone)]
pub struct BannedClientInfo {
    pub reason: Option<String>,
    pub banned_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(feature = "diesel-pg-backend")]
pub type DbPool =
    diesel_async_crate::pooled_connection::deadpool::Pool<diesel_async_crate::AsyncPgConnection>;

#[derive(Clone)]
pub struct YAuthState {
    pub repos: Repositories,
    pub config: Arc<YAuthConfig>,
    pub dummy_hash: String,
    pub email_service: Option<EmailService>,
    pub plugins: Arc<Vec<Box<dyn YAuthPlugin>>>,
    #[cfg(feature = "email-password")]
    pub email_password_config: crate::config::EmailPasswordConfig,
    #[cfg(feature = "bearer")]
    pub bearer_config: crate::config::BearerConfig,
    /// Pre-parsed asymmetric signing material. `None` when `signing_algorithm`
    /// is HS256 or the `asymmetric-jwt` feature is disabled. Populated once
    /// at `YAuthBuilder::build()` time so PEMs are not re-parsed per request.
    #[cfg(feature = "asymmetric-jwt")]
    pub signing_keys: Option<Arc<crate::auth::signing::SigningKeys>>,
    /// In-memory registry of `private_key_jwt` client public keys, keyed by
    /// `client_id`. Populated at dynamic-client-registration time. Process-
    /// local — a restart requires clients to re-register. A DB-backed store
    /// is planned; until then users who need persistence should reseed from
    /// config at startup.
    #[cfg(all(feature = "asymmetric-jwt", feature = "oauth2-server"))]
    pub client_keys: Arc<
        std::sync::RwLock<std::collections::HashMap<String, crate::auth::client_keys::ClientKey>>,
    >,
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
    #[cfg(feature = "admin")]
    pub admin_config: crate::config::AdminConfig,
    /// In-memory registry of banned OAuth2 client IDs with reasons. A
    /// compromised client's `client_id` can be added here to reject all
    /// future authentication attempts (and any replayed tokens for it).
    /// Process-local; a DB-backed store is a follow-up.
    #[cfg(all(feature = "admin", feature = "oauth2-server"))]
    pub banned_clients: Arc<std::sync::RwLock<std::collections::HashMap<String, BannedClientInfo>>>,
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
        match self.repos.users.any_exists().await {
            Ok(exists) => !exists,
            Err(_) => false,
        }
    }

    pub async fn write_audit_log(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        metadata: Option<serde_json::Value>,
        ip_address: Option<String>,
    ) {
        let new_log = crate::domain::NewAuditLog {
            id: Uuid::now_v7(),
            user_id,
            event_type: event_type.to_string(),
            metadata,
            ip_address,
            created_at: chrono::Utc::now().naive_utc(),
        };
        if let Err(e) = self.repos.audit.create(new_log).await {
            crate::otel::record_error("audit_log_write_failed", &e);
        }
    }
}
