//! Toasty model for `yauth_revocations`.

#[derive(Debug, toasty::Model)]
#[table = "revocations"]
pub struct YauthRevocation {
    #[key]
    pub key: String,
    pub expires_at: String,
}
