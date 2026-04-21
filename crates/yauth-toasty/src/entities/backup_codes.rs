//! Toasty model for `yauth_backup_codes`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "backup_codes"]
pub struct YauthBackupCode {
    #[key]
    pub id: Uuid,

    #[index]
    pub user_id: Uuid,

    pub code_hash: String,
    pub used: bool,
    pub created_at: jiff::Timestamp,
}
