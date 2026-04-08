//! Toasty-based PostgreSQL backend for yauth.
//!
//! Experimental: Toasty is pre-1.0. API may change.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use toasty::Db;
use yauth::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

// Entities are imported directly by each repo module via `crate::entities`.
// Helpers are imported directly by each repo module via `crate::helpers`.

// Core repo modules (always compiled)
mod audit_repo;
mod challenge_repo;
mod rate_limit_repo;
mod revocation_repo;
mod session_ops_repo;
mod user_repo;

// Feature-gated repo modules
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

/// Experimental: Toasty-based PostgreSQL backend.
///
/// Uses Toasty's derive-based models and query API for all operations.
/// Toasty's `Db` is cheaply cloneable (Arc-backed pool), so each repo
/// holds its own clone.
#[doc = "Experimental: Toasty is pre-1.0. API may change."]
pub struct ToastyPgBackend {
    db: Db,
}

impl ToastyPgBackend {
    /// Connect to PostgreSQL using a URL.
    ///
    /// Registers all yauth models and applies the `yauth_` table prefix.
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let db = Self::build_db(url)
            .await
            .map_err(|e| RepoError::Internal(format!("toasty connect error: {e}").into()))?;
        Ok(Self { db })
    }

    async fn build_db(url: &str) -> toasty::Result<Db> {
        let mut builder = Db::builder();
        builder
            .table_name_prefix("yauth_")
            .models(Self::all_models());
        builder.connect(url).await
    }

    /// Get a reference to the underlying Toasty `Db`.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Create all tables using `push_schema()`.
    /// Intended for test setup — not for production use.
    pub async fn create_tables(&self) -> Result<(), RepoError> {
        self.db
            .push_schema()
            .await
            .map_err(|e| RepoError::Internal(format!("push_schema error: {e}").into()))
    }

    /// Build the `ModelSet` with all yauth models based on enabled features.
    fn all_models() -> toasty::schema::app::ModelSet {
        toasty::models!(crate::*)
    }
}

impl DatabaseBackend for ToastyPgBackend {
    fn migrate(
        &self,
        features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        let required = collect_required_tables(features);
        Box::pin(async move { validate_schema(&self.db, &required).await })
    }

    fn repositories(&self) -> Repositories {
        build_repositories(&self.db)
    }
}

fn build_repositories(db: &Db) -> Repositories {
    Repositories {
        users: Arc::new(user_repo::ToastyUserRepo::new(db.clone())),
        sessions: Arc::new(user_repo::ToastySessionRepo::new(db.clone())),
        audit: Arc::new(audit_repo::ToastyAuditLogRepo::new(db.clone())),
        session_ops: Arc::new(session_ops_repo::ToastySessionOpsRepo::new(db.clone())),
        challenges: Arc::new(challenge_repo::ToastyChallengeRepo::new(db.clone())),
        rate_limits: Arc::new(rate_limit_repo::ToastyRateLimitRepo::new(db.clone())),
        revocations: Arc::new(revocation_repo::ToastyRevocationRepo::new(db.clone())),

        #[cfg(feature = "email-password")]
        passwords: Arc::new(password_repo::ToastyPasswordRepo::new(db.clone())),
        #[cfg(feature = "email-password")]
        email_verifications: Arc::new(password_repo::ToastyEmailVerificationRepo::new(db.clone())),
        #[cfg(feature = "email-password")]
        password_resets: Arc::new(password_repo::ToastyPasswordResetRepo::new(db.clone())),

        #[cfg(feature = "passkey")]
        passkeys: Arc::new(passkey_repo::ToastyPasskeyRepo::new(db.clone())),

        #[cfg(feature = "mfa")]
        totp: Arc::new(mfa_repo::ToastyTotpRepo::new(db.clone())),
        #[cfg(feature = "mfa")]
        backup_codes: Arc::new(mfa_repo::ToastyBackupCodeRepo::new(db.clone())),

        #[cfg(feature = "oauth")]
        oauth_accounts: Arc::new(oauth_repo::ToastyOauthAccountRepo::new(db.clone())),
        #[cfg(feature = "oauth")]
        oauth_states: Arc::new(oauth_repo::ToastyOauthStateRepo::new(db.clone())),

        #[cfg(feature = "api-key")]
        api_keys: Arc::new(api_key_repo::ToastyApiKeyRepo::new(db.clone())),

        #[cfg(feature = "bearer")]
        refresh_tokens: Arc::new(bearer_repo::ToastyRefreshTokenRepo::new(db.clone())),

        #[cfg(feature = "magic-link")]
        magic_links: Arc::new(magic_link_repo::ToastyMagicLinkRepo::new(db.clone())),

        #[cfg(feature = "oauth2-server")]
        oauth2_clients: Arc::new(oauth2_server_repo::ToastyOauth2ClientRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        authorization_codes: Arc::new(oauth2_server_repo::ToastyAuthorizationCodeRepo::new(
            db.clone(),
        )),
        #[cfg(feature = "oauth2-server")]
        consents: Arc::new(oauth2_server_repo::ToastyConsentRepo::new(db.clone())),
        #[cfg(feature = "oauth2-server")]
        device_codes: Arc::new(oauth2_server_repo::ToastyDeviceCodeRepo::new(db.clone())),

        #[cfg(feature = "account-lockout")]
        account_locks: Arc::new(account_lockout_repo::ToastyAccountLockRepo::new(db.clone())),
        #[cfg(feature = "account-lockout")]
        unlock_tokens: Arc::new(account_lockout_repo::ToastyUnlockTokenRepo::new(db.clone())),

        #[cfg(feature = "webhooks")]
        webhooks_repo: Arc::new(webhooks_repo::ToastyWebhookRepo::new(db.clone())),
        #[cfg(feature = "webhooks")]
        webhook_deliveries: Arc::new(webhooks_repo::ToastyWebhookDeliveryRepo::new(db.clone())),
    }
}

/// Collect required table names based on enabled features.
fn collect_required_tables(features: &EnabledFeatures) -> Vec<String> {
    let mut required: Vec<String> = vec![
        "yauth_users".into(),
        "yauth_sessions".into(),
        "yauth_audit_log".into(),
    ];

    if features.email_password {
        required.extend([
            "yauth_passwords".into(),
            "yauth_email_verifications".into(),
            "yauth_password_resets".into(),
        ]);
    }
    if features.passkey {
        required.push("yauth_webauthn_credentials".into());
    }
    if features.mfa {
        required.extend(["yauth_totp_secrets".into(), "yauth_backup_codes".into()]);
    }
    if features.oauth {
        required.extend(["yauth_oauth_accounts".into(), "yauth_oauth_states".into()]);
    }
    if features.api_key {
        required.push("yauth_api_keys".into());
    }
    if features.bearer {
        required.push("yauth_refresh_tokens".into());
    }
    if features.magic_link {
        required.push("yauth_magic_links".into());
    }
    if features.oauth2_server {
        required.extend([
            "yauth_oauth2_clients".into(),
            "yauth_authorization_codes".into(),
            "yauth_consents".into(),
            "yauth_device_codes".into(),
        ]);
    }
    if features.account_lockout {
        required.extend(["yauth_account_locks".into(), "yauth_unlock_tokens".into()]);
    }
    if features.webhooks {
        required.extend(["yauth_webhooks".into(), "yauth_webhook_deliveries".into()]);
    }

    required
}

/// Validate schema — best-effort for Toasty backends.
async fn validate_schema(db: &Db, _required: &[String]) -> Result<(), RepoError> {
    let _ = db;
    Ok(())
}
