//! Shared Toasty repository implementations.
//!
//! These are dialect-agnostic — Toasty's `Db` type handles PG/MySQL/SQLite
//! differences internally. Each per-dialect backend re-exports from here.

mod audit_repo;
mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;
mod user_repo;

#[cfg(feature = "account-lockout")]
mod account_lockout_repo;
#[cfg(feature = "api-key")]
mod api_key_repo;
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
#[cfg(feature = "webhooks")]
mod webhooks_repo;

pub(crate) use audit_repo::*;
pub(crate) use challenge_repo::*;
pub(crate) use rate_limit_repo::*;
pub(crate) use revocation_repo::*;
pub(crate) use session_ops_repo::*;
pub(crate) use user_repo::*;

#[cfg(feature = "account-lockout")]
pub(crate) use account_lockout_repo::*;
#[cfg(feature = "api-key")]
pub(crate) use api_key_repo::*;
#[cfg(feature = "bearer")]
pub(crate) use bearer_repo::*;
#[cfg(feature = "magic-link")]
pub(crate) use magic_link_repo::*;
#[cfg(feature = "mfa")]
pub(crate) use mfa_repo::*;
#[cfg(feature = "oauth")]
pub(crate) use oauth_repo::*;
#[cfg(feature = "oauth2-server")]
pub(crate) use oauth2_server_repo::*;
#[cfg(feature = "passkey")]
pub(crate) use passkey_repo::*;
#[cfg(feature = "email-password")]
pub(crate) use password_repo::*;
#[cfg(feature = "webhooks")]
pub(crate) use webhooks_repo::*;

use std::sync::Arc;
use toasty::Db;
use yauth::repo::Repositories;

/// Build the `Repositories` struct from a Toasty `Db`.
/// Shared across all Toasty backends (PG, MySQL, SQLite).
pub(crate) fn build_repositories(db: &Db) -> Repositories {
    Repositories {
        users: Arc::new(ToastyUserRepo::new(db.clone())),
        sessions: Arc::new(ToastySessionRepo::new(db.clone())),
        audit: Arc::new(ToastyAuditLogRepo::new(db.clone())),
        session_ops: Arc::new(ToastySessionOpsRepo::new(db.clone())),
        challenges: Arc::new(ToastyChallengeRepo::new(db.clone())),
        rate_limits: Arc::new(ToastyRateLimitRepo::new(db.clone())),
        revocations: Arc::new(ToastyRevocationRepo::new(db.clone())),

        #[cfg(feature = "email-password")]
        passwords: Arc::new(ToastyPasswordRepo::new(db.clone())),
        #[cfg(feature = "email-password")]
        email_verifications: Arc::new(ToastyEmailVerificationRepo::new(db.clone())),
        #[cfg(feature = "email-password")]
        password_resets: Arc::new(ToastyPasswordResetRepo::new(db.clone())),

        #[cfg(feature = "passkey")]
        passkeys: Arc::new(ToastyPasskeyRepo::new(db.clone())),

        #[cfg(feature = "mfa")]
        totp: Arc::new(ToastyTotpRepo::new(db.clone())),
        #[cfg(feature = "mfa")]
        backup_codes: Arc::new(ToastyBackupCodeRepo::new(db.clone())),

        #[cfg(feature = "oauth")]
        oauth_accounts: Arc::new(ToastyOauthAccountRepo::new(db.clone())),
        #[cfg(feature = "oauth")]
        oauth_states: Arc::new(ToastyOauthStateRepo::new(db.clone())),

        #[cfg(feature = "api-key")]
        api_keys: Arc::new(ToastyApiKeyRepo::new(db.clone())),

        #[cfg(feature = "bearer")]
        refresh_tokens: Arc::new(ToastyRefreshTokenRepo::new(db.clone())),

        #[cfg(feature = "magic-link")]
        magic_links: Arc::new(ToastyMagicLinkRepo::new(db.clone())),

        #[cfg(feature = "oauth2-server")]
        oauth2_clients: Arc::new(ToastyOauth2ClientRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        authorization_codes: Arc::new(ToastyAuthorizationCodeRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        consents: Arc::new(ToastyConsentRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        device_codes: Arc::new(ToastyDeviceCodeRepo::new(db.clone())),

        #[cfg(feature = "account-lockout")]
        account_locks: Arc::new(ToastyAccountLockRepo::new(db.clone())),
        #[cfg(feature = "account-lockout")]
        unlock_tokens: Arc::new(ToastyUnlockTokenRepo::new(db.clone())),

        #[cfg(feature = "webhooks")]
        webhooks_repo: Arc::new(ToastyWebhookRepo::new(db.clone())),
        #[cfg(feature = "webhooks")]
        webhook_deliveries: Arc::new(ToastyWebhookDeliveryRepo::new(db.clone())),
    }
}
