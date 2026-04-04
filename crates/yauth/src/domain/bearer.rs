use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub created_at: NaiveDateTime,
}
