//! Toasty model for `yauth_unlock_tokens`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "unlock_tokens"]
pub struct YauthUnlockToken {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub yauth_user: toasty::BelongsTo<YauthUser>,

    #[unique]
    pub token_hash: String,

    pub expires_at: jiff::Timestamp,
    pub created_at: jiff::Timestamp,
}
