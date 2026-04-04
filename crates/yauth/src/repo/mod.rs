//! Repository traits, error types, and backend abstraction.
//!
//! This module defines the contract between yauth's auth logic and the
//! persistence layer. All repository traits are sealed — only backends
//! inside the yauth crate can implement them.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;

use crate::error::{ApiError, api_err};

// ──────────────────────────────────────────────
// Sealed trait — prevents downstream implementations
// ──────────────────────────────────────────────

pub(crate) mod sealed {
    pub trait Sealed {}
}

// ──────────────────────────────────────────────
// RepoError
// ──────────────────────────────────────────────

/// Error type for repository operations.
///
/// Named `RepoError` (not `AuthError`) to distinguish from `ApiError`.
/// Implements `std::error::Error` + `Display` via `thiserror`.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// A uniqueness constraint was violated (duplicate email, API key name, etc.).
    #[error("conflict: {0}")]
    Conflict(String),

    /// The requested entity does not exist.
    /// Use for handlers that expect a result — repo methods that do lookups
    /// return `Result<Option<T>, RepoError>` instead.
    #[error("not found")]
    NotFound,

    /// An internal/infrastructure error (connection pool, query failure, etc.).
    #[error("{0}")]
    Internal(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl From<RepoError> for ApiError {
    fn from(e: RepoError) -> Self {
        match e {
            RepoError::Conflict(msg) => api_err(StatusCode::CONFLICT, &msg),
            RepoError::NotFound => api_err(StatusCode::NOT_FOUND, "Not found"),
            RepoError::Internal(e) => {
                crate::otel::record_error("repo_error", &e);
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        }
    }
}

// ──────────────────────────────────────────────
// RepoFuture type alias
// ──────────────────────────────────────────────

/// Boxed future for repository trait methods.
///
/// Required for object safety — `impl Future` makes traits non-dyn-compatible,
/// and we need `Arc<dyn XxxRepository>`. The heap allocation is negligible
/// compared to actual DB I/O.
pub type RepoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RepoError>> + Send + 'a>>;

// ──────────────────────────────────────────────
// EnabledFeatures
// ──────────────────────────────────────────────

/// Compile-time feature flags, materialized as a runtime struct.
///
/// Used by `DatabaseBackend::migrate()` to know which migrations to run.
/// Built from `cfg!()` macros, NOT from runtime config.
pub struct EnabledFeatures {
    pub email_password: bool,
    pub passkey: bool,
    pub mfa: bool,
    pub oauth: bool,
    pub bearer: bool,
    pub api_key: bool,
    pub magic_link: bool,
    pub admin: bool,
    pub oauth2_server: bool,
    pub account_lockout: bool,
    pub webhooks: bool,
    pub oidc: bool,
}

impl EnabledFeatures {
    pub fn from_compile_flags() -> Self {
        Self {
            email_password: cfg!(feature = "email-password"),
            passkey: cfg!(feature = "passkey"),
            mfa: cfg!(feature = "mfa"),
            oauth: cfg!(feature = "oauth"),
            bearer: cfg!(feature = "bearer"),
            api_key: cfg!(feature = "api-key"),
            magic_link: cfg!(feature = "magic-link"),
            admin: cfg!(feature = "admin"),
            oauth2_server: cfg!(feature = "oauth2-server"),
            account_lockout: cfg!(feature = "account-lockout"),
            webhooks: cfg!(feature = "webhooks"),
            oidc: cfg!(feature = "oidc"),
        }
    }
}

// ──────────────────────────────────────────────
// Repository trait modules
// ──────────────────────────────────────────────

mod user;
pub use user::*;

mod audit;
pub use audit::*;

#[cfg(feature = "email-password")]
mod password;
#[cfg(feature = "email-password")]
pub use password::*;

#[cfg(feature = "passkey")]
mod passkey;
#[cfg(feature = "passkey")]
pub use passkey::*;

#[cfg(feature = "mfa")]
mod mfa;
#[cfg(feature = "mfa")]
pub use mfa::*;

#[cfg(feature = "oauth")]
mod oauth;
#[cfg(feature = "oauth")]
pub use oauth::*;

#[cfg(feature = "api-key")]
mod api_key;
#[cfg(feature = "api-key")]
pub use api_key::*;

#[cfg(feature = "bearer")]
mod bearer;
#[cfg(feature = "bearer")]
pub use bearer::*;

#[cfg(feature = "magic-link")]
mod magic_link;
#[cfg(feature = "magic-link")]
pub use magic_link::*;

#[cfg(feature = "oauth2-server")]
mod oauth2_server;
#[cfg(feature = "oauth2-server")]
pub use oauth2_server::*;

#[cfg(feature = "account-lockout")]
mod account_lockout;
#[cfg(feature = "account-lockout")]
pub use account_lockout::*;

#[cfg(feature = "webhooks")]
mod webhooks;
#[cfg(feature = "webhooks")]
pub use webhooks::*;

// ──────────────────────────────────────────────
// Repositories struct
// ──────────────────────────────────────────────

/// Holds all repository trait objects. Constructed by `DatabaseBackend::repositories()`.
///
/// Replaces the raw `DbPool` in `YAuthState` (in M2).
#[derive(Clone)]
pub struct Repositories {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub audit: Arc<dyn AuditLogRepository>,

    #[cfg(feature = "email-password")]
    pub passwords: Arc<dyn PasswordRepository>,
    #[cfg(feature = "email-password")]
    pub email_verifications: Arc<dyn EmailVerificationRepository>,
    #[cfg(feature = "email-password")]
    pub password_resets: Arc<dyn PasswordResetRepository>,

    #[cfg(feature = "passkey")]
    pub passkeys: Arc<dyn PasskeyRepository>,

    #[cfg(feature = "mfa")]
    pub totp: Arc<dyn TotpRepository>,
    #[cfg(feature = "mfa")]
    pub backup_codes: Arc<dyn BackupCodeRepository>,

    #[cfg(feature = "oauth")]
    pub oauth_accounts: Arc<dyn OauthAccountRepository>,
    #[cfg(feature = "oauth")]
    pub oauth_states: Arc<dyn OauthStateRepository>,

    #[cfg(feature = "api-key")]
    pub api_keys: Arc<dyn ApiKeyRepository>,

    #[cfg(feature = "bearer")]
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,

    #[cfg(feature = "magic-link")]
    pub magic_links: Arc<dyn MagicLinkRepository>,

    #[cfg(feature = "oauth2-server")]
    pub oauth2_clients: Arc<dyn Oauth2ClientRepository>,
    #[cfg(feature = "oauth2-server")]
    pub authorization_codes: Arc<dyn AuthorizationCodeRepository>,
    #[cfg(feature = "oauth2-server")]
    pub consents: Arc<dyn ConsentRepository>,
    #[cfg(feature = "oauth2-server")]
    pub device_codes: Arc<dyn DeviceCodeRepository>,

    #[cfg(feature = "account-lockout")]
    pub account_locks: Arc<dyn AccountLockRepository>,
    #[cfg(feature = "account-lockout")]
    pub unlock_tokens: Arc<dyn UnlockTokenRepository>,

    #[cfg(feature = "webhooks")]
    pub webhooks_repo: Arc<dyn WebhookRepository>,
    #[cfg(feature = "webhooks")]
    pub webhook_deliveries: Arc<dyn WebhookDeliveryRepository>,
}

// ──────────────────────────────────────────────
// DatabaseBackend trait
// ──────────────────────────────────────────────

/// Abstraction over the persistence layer.
///
/// NOT sealed — consumers may implement custom backends (e.g., wrapping sqlx).
/// Uses `BoxFuture` for `migrate()` to stay object-safe for `Box<dyn DatabaseBackend>`.
pub trait DatabaseBackend: Send + Sync {
    /// Run migrations for the enabled features.
    ///
    /// - Diesel backend: executes feature-gated SQL migrations.
    /// - In-memory backend: no-op.
    /// - External migrations: no-op (assumes schema already exists).
    fn migrate(
        &self,
        features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>>;

    /// Construct the full `Repositories` struct. Called once during `build()`.
    fn repositories(&self) -> Repositories;

    /// Optional: expose a Postgres connection pool for ephemeral stores.
    ///
    /// Returns `None` for non-Postgres backends. When `None`, the builder
    /// uses memory-based ephemeral stores unless Redis is explicitly configured.
    #[cfg(feature = "diesel-backend")]
    fn postgres_pool_for_stores(&self) -> Option<crate::state::DbPool> {
        None
    }
}

/// Blanket impl so `Box<dyn DatabaseBackend>` can be passed directly to `YAuthBuilder::new`.
impl DatabaseBackend for Box<dyn DatabaseBackend> {
    fn migrate(
        &self,
        features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        (**self).migrate(features)
    }

    fn repositories(&self) -> Repositories {
        (**self).repositories()
    }

    #[cfg(feature = "diesel-backend")]
    fn postgres_pool_for_stores(&self) -> Option<crate::state::DbPool> {
        (**self).postgres_pool_for_stores()
    }
}
