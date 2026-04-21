//! Toasty model for `yauth_oauth2_clients`.
//!
//! Inverse relationships (`has_many`) are omitted — see `users.rs` module doc.
//! Child entities (`YauthAuthorizationCode`, `YauthConsent`, `YauthDeviceCode`)
//! declare `#[belongs_to]` and provide `filter_by_client_id()` accessors.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "oauth2_clients"]
pub struct YauthOauth2Client {
    #[key]
    pub id: Uuid,

    #[unique]
    pub client_id: String,

    pub client_secret_hash: Option<String>,

    #[serialize(json)]
    pub redirect_uris: Vec<String>,

    pub client_name: Option<String>,

    #[serialize(json)]
    pub grant_types: Vec<String>,

    #[serialize(json, nullable)]
    pub scopes: Option<serde_json::Value>,

    pub is_public: bool,
    pub created_at: jiff::Timestamp,

    pub token_endpoint_auth_method: Option<String>,
    pub public_key_pem: Option<String>,
    pub jwks_uri: Option<String>,
    pub banned_at: Option<jiff::Timestamp>,
    pub banned_reason: Option<String>,
}
