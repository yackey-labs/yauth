//! Toasty model for `yauth_oauth_states`.

#[derive(Debug, toasty::Model)]
#[table = "oauth_states"]
pub struct YauthOauthState {
    #[key]
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}
