//! SeaORM entity for `yauth_webhooks` (SQLite dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_webhooks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub url: String,
    #[sea_orm(column_type = "Text")]
    pub secret: String,
    #[sea_orm(column_type = "Text")]
    pub events: String,
    pub active: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::webhook_deliveries::Entity")]
    Deliveries,
}

impl Related<super::webhook_deliveries::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Deliveries.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::Webhook {
        crate::domain::Webhook {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            url: self.url,
            secret: self.secret,
            events: crate::backends::seaorm_common::str_to_json(&self.events),
            active: self.active,
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}
