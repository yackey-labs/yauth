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
    /// JSON scopes, serialized as string.
    pub scopes: Option<String>,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}
