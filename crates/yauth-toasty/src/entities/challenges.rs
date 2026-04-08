//! Toasty model for `yauth_challenges`.

#[derive(Debug, toasty::Model)]
#[table = "challenges"]
pub struct YauthChallenge {
    #[key]
    pub key: String,
    /// JSON value, serialized as string.
    pub value: String,
    pub expires_at: String,
}
