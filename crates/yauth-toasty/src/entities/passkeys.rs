//! Toasty model for `yauth_webauthn_credentials`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "webauthn_credentials"]
pub struct YauthPasskey {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,

    #[serialize(json)]
    pub credential: serde_json::Value,

    pub created_at: jiff::Timestamp,
    pub last_used_at: Option<jiff::Timestamp>,
}
