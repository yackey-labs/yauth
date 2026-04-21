//! Toasty model for `yauth_users`.
//!
//! Inverse relationships (`has_many`/`has_one`) are omitted because Toasty's
//! cross-module pair verification doesn't resolve across sibling entity modules.
//! Child entities declare `#[belongs_to]` instead; use `Child::filter_by_user_id()`
//! for the same query semantics.

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
    pub banned_until: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}
