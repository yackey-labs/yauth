//! Toasty model for `yauth_api_keys`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "api_keys"]
pub struct YauthApiKey {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[unique]
    pub key_prefix: String,

    pub key_hash: String,
    pub name: String,

    #[serialize(json, nullable)]
    pub scopes: Option<serde_json::Value>,

    pub last_used_at: Option<jiff::Timestamp>,
    pub expires_at: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
}
