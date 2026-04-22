//! Toasty model for `yauth_authorization_codes`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "authorization_codes"]
pub struct YauthAuthorizationCode {
    #[key]
    pub id: Uuid,

    #[unique]
    pub code_hash: String,

    pub client_id: String,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub yauth_user: toasty::BelongsTo<YauthUser>,

    #[serialize(json, nullable)]
    pub scopes: Option<serde_json::Value>,

    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: jiff::Timestamp,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: jiff::Timestamp,
}
