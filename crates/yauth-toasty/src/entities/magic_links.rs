//! Toasty model for `yauth_magic_links`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "magic_links"]
pub struct YauthMagicLink {
    #[key]
    pub id: Uuid,
    #[index]
    pub email: String,
    #[unique]
    pub token_hash: String,
    pub expires_at: String,
    pub used: bool,
    pub created_at: String,
}
