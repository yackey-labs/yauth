//! In-memory backend implementation for yauth.
//!
//! This module provides `InMemoryBackend`, a fully in-memory database backend
//! that stores all data in `Arc<RwLock<HashMap>>` collections. It requires zero
//! external dependencies (no Postgres, no Redis) and is ideal for testing and
//! development.
//!
//! Key invariants enforced:
//! - Case-insensitive email uniqueness on user creation
//! - Expiration on read for tokens (password resets, email verifications, etc.)
//! - Cascade delete when a user is removed
//! - Uniqueness constraints matching Postgres behavior

mod challenge_repo;
pub(crate) mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;

mod user_repo;

#[cfg(feature = "email-password")]
mod password_repo;

#[cfg(feature = "passkey")]
mod passkey_repo;

#[cfg(feature = "mfa")]
mod mfa_repo;

#[cfg(feature = "oauth")]
mod oauth_repo;

#[cfg(feature = "api-key")]
mod api_key_repo;

#[cfg(feature = "bearer")]
mod bearer_repo;

#[cfg(feature = "magic-link")]
mod magic_link_repo;

#[cfg(feature = "oauth2-server")]
mod oauth2_server_repo;

#[cfg(feature = "account-lockout")]
mod account_lockout_repo;

#[cfg(feature = "webhooks")]
mod webhooks_repo;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::domain;
use crate::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

/// Shared in-memory storage for all entities.
///
/// Each entity type gets its own `RwLock<HashMap>`. All repo structs hold
/// `Arc` references to the same storage instance, enabling cascade deletes
/// from the user repo to clean up related entities.
/// Entry for the ephemeral challenge store (key → value + expiry).
pub(crate) struct ChallengeEntry {
    pub(crate) value: serde_json::Value,
    pub(crate) expires_at: Instant,
}

/// Entry for the ephemeral revocation store (jti → expiry).
pub(crate) struct RevocationEntry {
    pub(crate) expires_at: Instant,
}

/// Entry for the ephemeral rate limit store (fixed-window counter).
pub(crate) struct RateLimitEntry {
    pub(crate) count: u32,
    pub(crate) window_start: Instant,
}

#[derive(Clone)]
pub(crate) struct Storage {
    pub(crate) users: Arc<RwLock<HashMap<Uuid, domain::User>>>,
    pub(crate) sessions: Arc<RwLock<HashMap<Uuid, domain::Session>>>,
    pub(crate) audit_logs: Arc<RwLock<Vec<domain::NewAuditLog>>>,

    // Ephemeral stores (keyed by token_hash / string key)
    pub(crate) session_ops: Arc<tokio::sync::RwLock<HashMap<String, domain::StoredSession>>>,
    pub(crate) challenges: Arc<Mutex<HashMap<String, ChallengeEntry>>>,
    pub(crate) rate_limits: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    pub(crate) revocations: Arc<Mutex<HashMap<String, RevocationEntry>>>,

    #[cfg(feature = "email-password")]
    pub(crate) passwords: Arc<RwLock<HashMap<Uuid, domain::Password>>>,
    #[cfg(feature = "email-password")]
    pub(crate) email_verifications: Arc<RwLock<HashMap<Uuid, domain::EmailVerification>>>,
    #[cfg(feature = "email-password")]
    pub(crate) password_resets: Arc<RwLock<HashMap<Uuid, domain::PasswordReset>>>,

    #[cfg(feature = "passkey")]
    pub(crate) passkeys: Arc<RwLock<HashMap<Uuid, domain::WebauthnCredential>>>,

    #[cfg(feature = "mfa")]
    pub(crate) totp_secrets: Arc<RwLock<HashMap<Uuid, domain::TotpSecret>>>,
    #[cfg(feature = "mfa")]
    pub(crate) backup_codes: Arc<RwLock<HashMap<Uuid, domain::BackupCode>>>,

    #[cfg(feature = "oauth")]
    pub(crate) oauth_accounts: Arc<RwLock<HashMap<Uuid, domain::OauthAccount>>>,
    #[cfg(feature = "oauth")]
    pub(crate) oauth_states: Arc<RwLock<HashMap<String, domain::OauthState>>>,

    #[cfg(feature = "api-key")]
    pub(crate) api_keys: Arc<RwLock<HashMap<Uuid, domain::ApiKey>>>,

    #[cfg(feature = "bearer")]
    pub(crate) refresh_tokens: Arc<RwLock<HashMap<Uuid, domain::RefreshToken>>>,

    #[cfg(feature = "magic-link")]
    pub(crate) magic_links: Arc<RwLock<HashMap<Uuid, domain::MagicLink>>>,

    #[cfg(feature = "oauth2-server")]
    pub(crate) oauth2_clients: Arc<RwLock<HashMap<Uuid, domain::Oauth2Client>>>,
    #[cfg(feature = "oauth2-server")]
    pub(crate) authorization_codes: Arc<RwLock<HashMap<Uuid, domain::AuthorizationCode>>>,
    #[cfg(feature = "oauth2-server")]
    pub(crate) consents: Arc<RwLock<HashMap<Uuid, domain::Consent>>>,
    #[cfg(feature = "oauth2-server")]
    pub(crate) device_codes: Arc<RwLock<HashMap<Uuid, domain::DeviceCode>>>,

    #[cfg(feature = "account-lockout")]
    pub(crate) account_locks: Arc<RwLock<HashMap<Uuid, domain::AccountLock>>>,
    #[cfg(feature = "account-lockout")]
    pub(crate) unlock_tokens: Arc<RwLock<HashMap<Uuid, domain::UnlockToken>>>,

    #[cfg(feature = "webhooks")]
    pub(crate) webhooks: Arc<RwLock<HashMap<Uuid, domain::Webhook>>>,
    #[cfg(feature = "webhooks")]
    pub(crate) webhook_deliveries: Arc<RwLock<HashMap<Uuid, domain::WebhookDelivery>>>,
}

impl Storage {
    fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            audit_logs: Arc::new(RwLock::new(Vec::new())),

            session_ops: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            revocations: Arc::new(Mutex::new(HashMap::new())),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "mfa")]
            totp_secrets: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(RwLock::new(HashMap::new())),

            #[cfg(feature = "webhooks")]
            webhooks: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// In-memory database backend for yauth.
///
/// All data is stored in `Arc<RwLock<HashMap>>` collections. No external
/// dependencies are required. Construction is infallible.
///
/// # Example
///
/// ```rust,no_run
/// use yauth::backends::memory::InMemoryBackend;
/// use yauth::prelude::*;
///
/// let backend = InMemoryBackend::new();
/// let builder = YAuthBuilder::new(backend, YAuthConfig::default());
/// ```
pub struct InMemoryBackend {
    storage: Storage,
}

impl InMemoryBackend {
    /// Create a new in-memory backend with empty storage.
    ///
    /// This is infallible — nothing can fail when initializing empty HashMaps.
    pub fn new() -> Self {
        Self {
            storage: Storage::new(),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseBackend for InMemoryBackend {
    fn migrate(
        &self,
        _features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        // No-op: in-memory backend has no schema to migrate.
        Box::pin(async { Ok(()) })
    }

    fn repositories(&self) -> Repositories {
        Repositories {
            users: Arc::new(user_repo::InMemoryUserRepo::new(self.storage.clone())),
            sessions: Arc::new(user_repo::InMemorySessionRepo::new(
                self.storage.sessions.clone(),
            )),
            audit: Arc::new(user_repo::InMemoryAuditLogRepo::new(
                self.storage.audit_logs.clone(),
            )),
            session_ops: Arc::new(session_ops_repo::InMemorySessionOpsRepo::new(
                self.storage.session_ops.clone(),
            )),
            challenges: Arc::new(challenge_repo::InMemoryChallengeRepo::new(
                self.storage.challenges.clone(),
            )),
            rate_limits: Arc::new(rate_limit_repo::InMemoryRateLimitRepo::new(
                self.storage.rate_limits.clone(),
            )),
            revocations: Arc::new(revocation_repo::InMemoryRevocationRepo::new(
                self.storage.revocations.clone(),
            )),

            #[cfg(feature = "email-password")]
            passwords: Arc::new(password_repo::InMemoryPasswordRepo::new(
                self.storage.passwords.clone(),
            )),
            #[cfg(feature = "email-password")]
            email_verifications: Arc::new(password_repo::InMemoryEmailVerificationRepo::new(
                self.storage.email_verifications.clone(),
            )),
            #[cfg(feature = "email-password")]
            password_resets: Arc::new(password_repo::InMemoryPasswordResetRepo::new(
                self.storage.password_resets.clone(),
            )),

            #[cfg(feature = "passkey")]
            passkeys: Arc::new(passkey_repo::InMemoryPasskeyRepo::new(
                self.storage.passkeys.clone(),
            )),

            #[cfg(feature = "mfa")]
            totp: Arc::new(mfa_repo::InMemoryTotpRepo::new(
                self.storage.totp_secrets.clone(),
            )),
            #[cfg(feature = "mfa")]
            backup_codes: Arc::new(mfa_repo::InMemoryBackupCodeRepo::new(
                self.storage.backup_codes.clone(),
            )),

            #[cfg(feature = "oauth")]
            oauth_accounts: Arc::new(oauth_repo::InMemoryOauthAccountRepo::new(
                self.storage.oauth_accounts.clone(),
            )),
            #[cfg(feature = "oauth")]
            oauth_states: Arc::new(oauth_repo::InMemoryOauthStateRepo::new(
                self.storage.oauth_states.clone(),
            )),

            #[cfg(feature = "api-key")]
            api_keys: Arc::new(api_key_repo::InMemoryApiKeyRepo::new(
                self.storage.api_keys.clone(),
            )),

            #[cfg(feature = "bearer")]
            refresh_tokens: Arc::new(bearer_repo::InMemoryRefreshTokenRepo::new(
                self.storage.clone(),
            )),

            #[cfg(feature = "magic-link")]
            magic_links: Arc::new(magic_link_repo::InMemoryMagicLinkRepo::new(
                self.storage.magic_links.clone(),
            )),

            #[cfg(feature = "oauth2-server")]
            oauth2_clients: Arc::new(oauth2_server_repo::InMemoryOauth2ClientRepo::new(
                self.storage.oauth2_clients.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            authorization_codes: Arc::new(oauth2_server_repo::InMemoryAuthorizationCodeRepo::new(
                self.storage.authorization_codes.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            consents: Arc::new(oauth2_server_repo::InMemoryConsentRepo::new(
                self.storage.consents.clone(),
            )),
            #[cfg(feature = "oauth2-server")]
            device_codes: Arc::new(oauth2_server_repo::InMemoryDeviceCodeRepo::new(
                self.storage.device_codes.clone(),
            )),

            #[cfg(feature = "account-lockout")]
            account_locks: Arc::new(account_lockout_repo::InMemoryAccountLockRepo::new(
                self.storage.account_locks.clone(),
            )),
            #[cfg(feature = "account-lockout")]
            unlock_tokens: Arc::new(account_lockout_repo::InMemoryUnlockTokenRepo::new(
                self.storage.unlock_tokens.clone(),
            )),

            #[cfg(feature = "webhooks")]
            webhooks_repo: Arc::new(webhooks_repo::InMemoryWebhookRepo::new(
                self.storage.webhooks.clone(),
            )),
            #[cfg(feature = "webhooks")]
            webhook_deliveries: Arc::new(webhooks_repo::InMemoryWebhookDeliveryRepo::new(
                self.storage.webhook_deliveries.clone(),
            )),
        }
    }
}
