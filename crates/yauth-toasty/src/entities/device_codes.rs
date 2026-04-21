//! Toasty model for `yauth_device_codes`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "device_codes"]
pub struct YauthDeviceCode {
    #[key]
    pub id: Uuid,

    #[unique]
    pub device_code_hash: String,

    #[unique]
    pub user_code: String,

    pub client_id: String,

    #[serialize(json, nullable)]
    pub scopes: Option<serde_json::Value>,

    pub user_id: Option<Uuid>,
    pub status: String,
    pub interval: i32,
    pub expires_at: jiff::Timestamp,
    pub last_polled_at: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
}
