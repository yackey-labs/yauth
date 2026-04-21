//! Toasty model for `yauth_refresh_tokens`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "refresh_tokens"]
pub struct YauthRefreshToken {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    #[unique]
    pub token_hash: String,

    #[index]
    pub family_id: Uuid,

    pub expires_at: jiff::Timestamp,
    pub revoked: bool,
    pub created_at: jiff::Timestamp,
}
