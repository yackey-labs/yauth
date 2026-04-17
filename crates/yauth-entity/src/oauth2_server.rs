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
    /// RFC 7591 `token_endpoint_auth_method`. `client_secret_post` / `basic` /
    /// `private_key_jwt` / `none`.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// PKCS#8 public PEM for `private_key_jwt` client auth (RFC 7523).
    #[serde(default)]
    pub public_key_pem: Option<String>,
    /// Reserved for JWKS-URI fetch support (not yet consumed at runtime).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// When set, the client is banned — all token issuance + outstanding
    /// token validation rejects it.
    #[serde(default)]
    pub banned_at: Option<NaiveDateTime>,
    #[serde(default)]
    pub banned_reason: Option<String>,
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
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub public_key_pem: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
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
