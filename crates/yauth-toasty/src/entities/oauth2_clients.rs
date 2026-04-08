//! Toasty model for `yauth_oauth2_clients`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "oauth2_clients"]
pub struct YauthOauth2Client {
    #[key]
    pub id: Uuid,
    #[unique]
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    /// JSON redirect URIs, serialized as string.
    pub redirect_uris: String,
    pub client_name: Option<String>,
    /// JSON grant types, serialized as string.
    pub grant_types: String,
    /// JSON scopes, serialized as string.
    pub scopes: Option<String>,
    pub is_public: bool,
    pub created_at: String,
}
