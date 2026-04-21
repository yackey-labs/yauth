//! Toasty model for `yauth_passwords`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "passwords"]
pub struct YauthPassword {
    #[key]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    pub password_hash: String,
}
