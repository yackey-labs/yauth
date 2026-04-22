//! Toasty model for `yauth_totp_secrets`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "totp_secrets"]
pub struct YauthTotpSecret {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub yauth_user: toasty::BelongsTo<YauthUser>,

    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: jiff::Timestamp,
}
