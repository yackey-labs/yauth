//! Toasty model for `yauth_totp_secrets`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "totp_secrets"]
pub struct YauthTotpSecret {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: jiff::Timestamp,
}
