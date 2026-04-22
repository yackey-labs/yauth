//! Toasty model for `yauth_audit_log`.

use uuid::Uuid;

#[derive(Debug, toasty::Model)]
#[table = "audit_log"]
pub struct YauthAuditLog {
    #[key]
    pub id: Uuid,

    pub user_id: Option<Uuid>,
    pub event_type: String,

    #[serialize(json, nullable)]
    pub metadata: Option<serde_json::Value>,

    pub ip_address: Option<String>,
    pub created_at: jiff::Timestamp,
}
