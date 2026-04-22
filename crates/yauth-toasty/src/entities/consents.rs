//! Toasty model for `yauth_consents`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "consents"]
pub struct YauthConsent {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub yauth_user: toasty::BelongsTo<YauthUser>,

    pub client_id: String,

    #[serialize(json, nullable)]
    pub scopes: Option<serde_json::Value>,

    pub created_at: jiff::Timestamp,
}
