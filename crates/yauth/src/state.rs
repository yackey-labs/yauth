use crate::auth::{email::EmailService, rate_limit::RateLimiter};
use crate::config::YAuthConfig;
use crate::plugin::{AuthEvent, EventResponse, PluginContext, YAuthPlugin};
use crate::stores::{ChallengeStore, RateLimitStore};
use std::sync::Arc;
use uuid::Uuid;

#[cfg(all(feature = "seaorm", feature = "diesel-async"))]
compile_error!("Features `seaorm` and `diesel-async` are mutually exclusive. Enable only one.");

#[cfg(feature = "seaorm")]
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, PaginatorTrait, Set};

#[cfg(feature = "seaorm")]
pub type DbPool = DatabaseConnection;

#[cfg(feature = "diesel-async")]
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

    #[cfg(feature = "seaorm")]
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

    #[cfg(feature = "diesel-async")]
    pub async fn should_auto_admin(&self) -> bool {
        if !self.config.auto_admin_first_user {
            return false;
        }
        let mut conn = match self.db.get().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        use diesel_async_crate::RunQueryDsl;
        let exists: Option<ExistsRow> =
            diesel::sql_query("SELECT 1 AS one FROM yauth_users LIMIT 1")
                .get_result::<ExistsRow>(&mut conn)
                .await
                .optional()
                .unwrap_or(Some(ExistsRow { one: 1 }));
        exists.is_none()
    }

    #[cfg(feature = "seaorm")]
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

    #[cfg(feature = "diesel-async")]
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
        let result = diesel::sql_query(
            "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::new_v4())
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(event_type.to_string())
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(metadata)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(ip_address)
        .bind::<diesel::sql_types::Timestamptz, _>(chrono::Utc::now())
        .execute(&mut conn)
        .await;
        if let Err(e) = result {
            tracing::error!("Failed to write audit log: {}", e);
        }
    }
}

#[cfg(feature = "diesel-async")]
#[derive(diesel::QueryableByName)]
#[allow(dead_code)]
struct ExistsRow {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    one: i32,
}

#[cfg(feature = "diesel-async")]
use diesel::result::OptionalExtension;
