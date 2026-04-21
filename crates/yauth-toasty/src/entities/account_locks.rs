//! Toasty model for `yauth_account_locks`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "account_locks"]
pub struct YauthAccountLock {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    pub failed_count: i32,
    pub locked_until: Option<jiff::Timestamp>,
    pub lock_count: i32,
    pub locked_reason: Option<String>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}
