use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "yauth_users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    pub banned_until: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::sessions::Entity")]
    Sessions,
    #[sea_orm(has_many = "super::audit_log::Entity")]
    AuditLog,
    #[cfg(feature = "email-password")]
    #[sea_orm(has_one = "super::passwords::Entity")]
    Password,
    #[cfg(feature = "email-password")]
    #[sea_orm(has_many = "super::email_verifications::Entity")]
    EmailVerifications,
    #[cfg(feature = "email-password")]
    #[sea_orm(has_many = "super::password_resets::Entity")]
    PasswordResets,
    #[cfg(feature = "passkey")]
    #[sea_orm(has_many = "super::webauthn_credentials::Entity")]
    WebauthnCredentials,
    #[cfg(feature = "mfa")]
    #[sea_orm(has_one = "super::totp_secrets::Entity")]
    TotpSecret,
    #[cfg(feature = "mfa")]
    #[sea_orm(has_many = "super::backup_codes::Entity")]
    BackupCodes,
    #[cfg(feature = "oauth")]
    #[sea_orm(has_many = "super::oauth_accounts::Entity")]
    OauthAccounts,
    #[cfg(feature = "api-key")]
    #[sea_orm(has_many = "super::api_keys::Entity")]
    ApiKeys,
    #[cfg(feature = "bearer")]
    #[sea_orm(has_many = "super::refresh_tokens::Entity")]
    RefreshTokens,
}

impl Related<super::sessions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sessions.def()
    }
}

impl Related<super::audit_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuditLog.def()
    }
}

#[cfg(feature = "email-password")]
impl Related<super::passwords::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Password.def()
    }
}

#[cfg(feature = "email-password")]
impl Related<super::email_verifications::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::EmailVerifications.def()
    }
}

#[cfg(feature = "email-password")]
impl Related<super::password_resets::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PasswordResets.def()
    }
}

#[cfg(feature = "passkey")]
impl Related<super::webauthn_credentials::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WebauthnCredentials.def()
    }
}

#[cfg(feature = "mfa")]
impl Related<super::totp_secrets::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TotpSecret.def()
    }
}

#[cfg(feature = "mfa")]
impl Related<super::backup_codes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BackupCodes.def()
    }
}

#[cfg(feature = "oauth")]
impl Related<super::oauth_accounts::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::OauthAccounts.def()
    }
}

#[cfg(feature = "api-key")]
impl Related<super::api_keys::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeys.def()
    }
}

#[cfg(feature = "bearer")]
impl Related<super::refresh_tokens::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RefreshTokens.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
