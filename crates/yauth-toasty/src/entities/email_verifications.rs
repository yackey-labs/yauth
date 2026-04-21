//! Toasty model for `yauth_email_verifications`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "email_verifications"]
pub struct YauthEmailVerification {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[unique]
    pub token_hash: String,

    pub expires_at: jiff::Timestamp,
    pub created_at: jiff::Timestamp,
}
