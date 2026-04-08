//! Toasty model for `yauth_oauth_accounts`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "oauth_accounts"]
pub struct YauthOauthAccount {
    #[key]
    pub id: Uuid,
    #[index]
    pub user_id: Uuid,
    #[index]
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: Option<String>,
    pub refresh_token_enc: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub updated_at: String,
}
