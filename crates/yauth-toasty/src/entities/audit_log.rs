//! Toasty model for `yauth_audit_log`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "audit_log"]
pub struct YauthAuditLog {
    #[key]
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    /// JSON metadata, serialized as string.
    pub metadata: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
}
