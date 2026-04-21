//! Toasty model for `yauth_backup_codes`.

use super::YauthUser;
use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "backup_codes"]
pub struct YauthBackupCode {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    #[belongs_to(key = user_id, references = id)]
    pub user: toasty::BelongsTo<YauthUser>,

    pub code_hash: String,
    pub used: bool,
    pub created_at: jiff::Timestamp,
}
