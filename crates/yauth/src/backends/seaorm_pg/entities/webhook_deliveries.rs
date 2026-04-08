//! SeaORM entity for `yauth_webhook_deliveries`.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_webhook_deliveries")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Uuid")]
    pub id: Uuid,
    #[sea_orm(column_type = "Uuid")]
    pub webhook_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub event_type: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub payload: serde_json::Value,
    pub status_code: Option<i16>,
    #[sea_orm(column_type = "Text", nullable)]
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::webhooks::Entity",
        from = "Column::WebhookId",
        to = "super::webhooks::Column::Id",
        on_delete = "Cascade"
    )]
    Webhook,
}

impl Related<super::webhooks::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Webhook.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::WebhookDelivery {
        crate::domain::WebhookDelivery {
            id: self.id,
            webhook_id: self.webhook_id,
            event_type: self.event_type,
            payload: self.payload,
            status_code: self.status_code,
            response_body: self.response_body,
            success: self.success,
            attempt: self.attempt,
            created_at: self.created_at.naive_utc(),
        }
    }
}
