//! Toasty model for `yauth_refresh_tokens`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "refresh_tokens"]
pub struct YauthRefreshToken {
    #[key]
    pub id: Uuid,
    #[index]
    pub user_id: Uuid,
    #[unique]
    pub token_hash: String,
    #[index]
    pub family_id: Uuid,
    pub expires_at: String,
    pub revoked: bool,
    pub created_at: String,
}
