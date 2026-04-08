//! Toasty model for `yauth_unlock_tokens`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "unlock_tokens"]
pub struct YauthUnlockToken {
    #[key]
    pub id: Uuid,
    #[index]
    pub user_id: Uuid,
    #[unique]
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}
