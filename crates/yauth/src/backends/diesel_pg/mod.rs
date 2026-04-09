//! Diesel backend implementation for yauth.
//!
//! This module contains the `DieselPgBackend` struct, Diesel-annotated models,
//! schema definitions, migration runner, and all repository implementations.

mod models;
pub mod schema;

mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;

#[cfg(feature = "account-lockout")]
mod account_lockout_repo;
#[cfg(feature = "api-key")]
mod api_key_repo;
mod audit_repo;
#[cfg(feature = "bearer")]
mod bearer_repo;
#[cfg(feature = "magic-link")]
mod magic_link_repo;
#[cfg(feature = "mfa")]
mod mfa_repo;
#[cfg(feature = "oauth2-server")]
mod oauth2_server_repo;
#[cfg(feature = "oauth")]
mod oauth_repo;
#[cfg(feature = "passkey")]
mod passkey_repo;
#[cfg(feature = "email-password")]
mod password_repo;
mod user_repo;
#[cfg(feature = "webhooks")]
mod webhooks_repo;

use std::sync::Arc;

use crate::repo::{DatabaseBackend, RepoError, Repositories};
use crate::state::DbPool;

// Re-export Diesel pool types for consumers who need direct pool access
pub use diesel_async_crate::AsyncPgConnection;
pub use diesel_async_crate::RunQueryDsl;
pub use diesel_async_crate::pooled_connection::AsyncDieselConnectionManager;
pub use diesel_async_crate::pooled_connection::deadpool::Pool as DieselPool;

/// The Diesel-based database backend for yauth.
///
/// Owns a connection pool and implements `DatabaseBackend` to provide
/// all repository implementations.
pub struct DieselPgBackend {
    pool: DbPool,
    /// PostgreSQL schema name (e.g., "public" or "auth"). Stored for diagnostics.
    #[allow(dead_code)]
    schema: String,
}

impl DieselPgBackend {
    /// Create from an existing pool (for consumers who manage their own pool).
    pub fn from_pool(pool: DbPool) -> Self {
        setup_diesel_instrumentation();
        Self {
            pool,
            schema: "public".to_string(),
        }
    }

    /// Create from an existing pool with a custom schema.
    pub fn from_pool_with_schema(pool: DbPool, schema: &str) -> Result<Self, RepoError> {
        crate::validate_schema_name(schema).map_err(RepoError::Internal)?;
        setup_diesel_instrumentation();
        Ok(Self {
            pool,
            schema: schema.to_string(),
        })
    }
}

impl DatabaseBackend for DieselPgBackend {
    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::DieselUserRepo::new(self.pool.clone())),
            sessions: Arc::new(user_repo::DieselSessionRepo::new(self.pool.clone())),
            audit: Arc::new(audit_repo::DieselAuditLogRepo::new(self.pool.clone())),
            session_ops: Arc::new(session_ops_repo::DieselSessionOpsRepo::new(
                self.pool.clone(),
            )),
            challenges: Arc::new(challenge_repo::DieselChallengeRepo::new(self.pool.clone())),
            rate_limits: Arc::new(rate_limit_repo::DieselRateLimitRepo::new(self.pool.clone())),
            revocations: Arc::new(revocation_repo::DieselRevocationRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::DieselPasswordRepo::new(self.pool.clone())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::DieselEmailVerificationRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::DieselPasswordResetRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::DieselPasskeyRepo::new(self.pool.clone())),

            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::DieselTotpRepo::new(self.pool.clone())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::DieselBackupCodeRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::DieselOauthAccountRepo::new(self.pool.clone())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::DieselOauthStateRepo::new(self.pool.clone())),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::DieselApiKeyRepo::new(self.pool.clone())),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::DieselRefreshTokenRepo::new(self.pool.clone())),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::DieselMagicLinkRepo::new(self.pool.clone())),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::DieselOauth2ClientRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::DieselAuthorizationCodeRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::DieselConsentRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::DieselDeviceCodeRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::DieselAccountLockRepo::new(
                self.pool.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::DieselUnlockTokenRepo::new(
                self.pool.clone(),
            )),

            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::DieselWebhookRepo::new(self.pool.clone())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::DieselWebhookDeliveryRepo::new(
                self.pool.clone(),
            )),
        }
    }
}

/// Set up Diesel query instrumentation for OTel tracing.
/// Only active when `telemetry` feature is enabled.
fn setup_diesel_instrumentation() {
    #[cfg(feature = "telemetry")]
    {
        use diesel::connection::set_default_instrumentation;
        use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
        use opentelemetry::{Context, KeyValue, global};
        use opentelemetry_semantic_conventions::attribute::{DB_OPERATION_NAME, DB_SYSTEM_NAME};

        fn extract_db_operation(query: &str) -> &str {
            let trimmed = query.trim_start();
            if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
                let op = &trimmed[..pos];
                match op {
                    s if s.eq_ignore_ascii_case("SELECT") => "SELECT",
                    s if s.eq_ignore_ascii_case("INSERT") => "INSERT",
                    s if s.eq_ignore_ascii_case("UPDATE") => "UPDATE",
                    s if s.eq_ignore_ascii_case("DELETE") => "DELETE",
                    _ => op,
                }
            } else {
                trimmed
            }
        }

        struct QueryTracing {
            span_cx: Option<Context>,
        }

        impl diesel::connection::Instrumentation for QueryTracing {
            fn on_connection_event(&mut self, event: diesel::connection::InstrumentationEvent<'_>) {
                match event {
                    diesel::connection::InstrumentationEvent::StartQuery { query, .. } => {
                        let query_str = format!("{query}");
                        let operation = extract_db_operation(&query_str);
                        let tracer = global::tracer("yauth");
                        let span = tracer
                            .span_builder(format!("{operation} db"))
                            .with_kind(SpanKind::Client)
                            .with_attributes(vec![
                                KeyValue::new(DB_SYSTEM_NAME, "postgresql"),
                                KeyValue::new(DB_OPERATION_NAME, operation.to_string()),
                            ])
                            .start(&tracer);
                        let cx = Context::current().with_span(span);
                        self.span_cx = Some(cx);
                    }
                    diesel::connection::InstrumentationEvent::FinishQuery { error, .. } => {
                        if let Some(ref cx) = self.span_cx {
                            if let Some(err) = error {
                                let span = cx.span();
                                span.add_event(
                                    "query_error".to_string(),
                                    vec![KeyValue::new("error.message", err.to_string())],
                                );
                                span.set_status(Status::error(err.to_string()));
                            }
                            cx.span().end();
                        }
                        self.span_cx.take();
                    }
                    _ => {}
                }
            }
        }

        let _ = set_default_instrumentation(|| Some(Box::new(QueryTracing { span_cx: None })));
    }
}
