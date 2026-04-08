//! Toasty model for `yauth_users`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "users"]
pub struct YauthUser {
    #[key]
    pub id: Uuid,
    #[unique]
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub role: String,
    pub banned: bool,
    pub banned_reason: Option<String>,
    /// Stored as ISO 8601 string (chrono not supported by Toasty).
    pub banned_until: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
