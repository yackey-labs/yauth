//! Toasty model for `yauth_oauth_accounts`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "oauth_accounts"]
pub struct YauthOauthAccount {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    #[index]
    pub provider: String,

    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: jiff::Timestamp,
    pub expires_at: Option<jiff::Timestamp>,
    pub updated_at: jiff::Timestamp,
}
