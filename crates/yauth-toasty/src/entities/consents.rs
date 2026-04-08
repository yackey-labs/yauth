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
    /// JSON scopes, serialized as string.
    pub scopes: Option<String>,
    pub created_at: String,
}
