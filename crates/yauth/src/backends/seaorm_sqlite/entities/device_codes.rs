//! SeaORM entity for `yauth_device_codes` (SQLite dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_device_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub device_code_hash: String,
    #[sea_orm(column_type = "Text")]
    pub user_code: String,
    #[sea_orm(column_type = "Text")]
    pub client_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub scopes: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub user_id: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    pub interval: i32,
    pub expires_at: DateTimeWithTimeZone,
    pub last_polled_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::DeviceCode {
        crate::domain::DeviceCode {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            client_id: self.client_id,
            scopes: self.scopes.and_then(|s| serde_json::from_str(&s).ok()),
            user_id: self
                .user_id
                .map(|s| crate::backends::seaorm_common::str_to_uuid(&s)),
            status: self.status,
            interval: self.interval,
            expires_at: self.expires_at.naive_utc(),
            last_polled_at: self.last_polled_at.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
        }
    }
}
