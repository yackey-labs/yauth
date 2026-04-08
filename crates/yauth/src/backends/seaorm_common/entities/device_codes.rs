//! SeaORM entity for `yauth_device_codes`.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_device_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Uuid")]
    pub id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub device_code_hash: String,
    #[sea_orm(column_type = "Text")]
    pub user_code: String,
    #[sea_orm(column_type = "Text")]
    pub client_id: String,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub scopes: Option<serde_json::Value>,
    #[sea_orm(column_type = "Uuid", nullable)]
    pub user_id: Option<Uuid>,
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
            id: self.id,
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            client_id: self.client_id,
            scopes: self.scopes,
            user_id: self.user_id,
            status: self.status,
            interval: self.interval,
            expires_at: self.expires_at.naive_utc(),
            last_polled_at: self.last_polled_at.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
        }
    }
}
