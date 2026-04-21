//! Toasty model for `yauth_consents`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "consents"]
pub struct YauthConsent {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    pub client_id: String,

    #[serialize(json, nullable)]
    pub scopes: Option<serde_json::Value>,

    pub created_at: jiff::Timestamp,
}
