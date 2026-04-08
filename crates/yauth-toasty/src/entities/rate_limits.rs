//! Toasty model for `yauth_rate_limits`.

#[derive(Debug, toasty::Model)]
#[table = "rate_limits"]
pub struct YauthRateLimit {
    #[key]
    pub key: String,
    pub count: i32,
    pub window_start: String,
}
