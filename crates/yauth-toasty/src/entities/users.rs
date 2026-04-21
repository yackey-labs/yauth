//! Toasty model for `yauth_users`.
//!
//! Parent entity declaring `#[has_many]` / `#[has_one]` inverse relationships.
//! Child entities declare `#[belongs_to(key = user_id, references = id)]` with
//! a virtual `toasty::BelongsTo<YauthUser>` field.
//!
//! Entities with nullable `user_id` (`YauthAuditLog`, `YauthDeviceCode`) omit
//! `belongs_to` because Toasty requires non-optional FK fields for relationship
//! attributes.

use super::{
    YauthAccountLock, YauthApiKey, YauthAuthorizationCode, YauthBackupCode,
    YauthEmailVerification, YauthOauthAccount, YauthPasskey, YauthPasswordReset,
    YauthRefreshToken, YauthSession, YauthUnlockToken,
};
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "users"]
pub struct YauthUser {
    #[key]
    pub id: Uuid,

    #[unique]
    pub email: String,

    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,

    // 1:1 relationships
    #[has_one]
    pub password: toasty::HasOne<super::YauthPassword>,
    #[has_one]
    pub totp_secret: toasty::HasOne<super::YauthTotpSecret>,

    // 1:N relationships
    #[has_many]
    pub sessions: toasty::HasMany<YauthSession>,
    #[has_many]
    pub passkeys: toasty::HasMany<YauthPasskey>,
    #[has_many]
    pub email_verifications: toasty::HasMany<YauthEmailVerification>,
    #[has_many]
    pub password_resets: toasty::HasMany<YauthPasswordReset>,
    #[has_many]
    pub backup_codes: toasty::HasMany<YauthBackupCode>,
    #[has_many]
    pub oauth_accounts: toasty::HasMany<YauthOauthAccount>,
    #[has_many]
    pub api_keys: toasty::HasMany<YauthApiKey>,
    #[has_many]
    pub refresh_tokens: toasty::HasMany<YauthRefreshToken>,
    #[has_many]
    pub account_locks: toasty::HasMany<YauthAccountLock>,
    #[has_many]
    pub unlock_tokens: toasty::HasMany<YauthUnlockToken>,
    #[has_many]
    pub consents: toasty::HasMany<super::YauthConsent>,
    #[has_many]
    pub authorization_codes: toasty::HasMany<YauthAuthorizationCode>,
}
