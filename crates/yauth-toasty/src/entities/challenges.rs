//! Toasty model for `yauth_challenges`.

#[derive(Debug, toasty::Model)]
#[table = "challenges"]
pub struct YauthChallenge {
    #[key]
    pub key: String,

    #[serialize(json)]
    pub value: serde_json::Value,

    pub expires_at: jiff::Timestamp,
}
