//! Toasty model for `yauth_sessions`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "sessions"]
pub struct YauthSession {
    #[key]
    pub id: Uuid,
    #[index]
    pub user_id: Uuid,
    #[unique]
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}
