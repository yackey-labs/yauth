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
    /// JSON scopes, serialized as string.
    pub scopes: Option<String>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub interval: i32,
    pub expires_at: String,
    pub last_polled_at: Option<String>,
    pub created_at: String,
}
