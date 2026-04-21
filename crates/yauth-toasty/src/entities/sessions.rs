//! Toasty model for `yauth_sessions`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "sessions"]
pub struct YauthSession {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    #[unique]
    pub token_hash: String,

    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: jiff::Timestamp,
    pub created_at: jiff::Timestamp,
}
