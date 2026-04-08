//! Toasty model for `yauth_passwords`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "passwords"]
pub struct YauthPassword {
    #[key]
    pub user_id: Uuid,
    pub password_hash: String,
}
