//! Toasty model for `yauth_password_resets`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "password_resets"]
pub struct YauthPasswordReset {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[unique]
    pub token_hash: String,

    pub expires_at: jiff::Timestamp,
    pub used_at: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
}
