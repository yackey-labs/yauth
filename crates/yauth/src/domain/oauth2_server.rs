use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Oauth2Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    pub grant_types: serde_json::Value,
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOauth2Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub client_name: Option<String>,
    pub grant_types: serde_json::Value,
    pub scopes: Option<serde_json::Value>,
    pub is_public: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Option<serde_json::Value>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuthorizationCode {
    pub id: Uuid,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Option<serde_json::Value>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewConsent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCode {
    pub id: Uuid,
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub interval: i32,
    pub expires_at: NaiveDateTime,
    pub last_polled_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDeviceCode {
    pub id: Uuid,
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Option<serde_json::Value>,
    pub user_id: Option<Uuid>,
    pub status: String,
    pub interval: i32,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}
