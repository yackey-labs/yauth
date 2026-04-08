//! SeaORM entity for `yauth_audit_log` (MySQL dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_audit_log")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Char(Some(36))", nullable)]
    pub user_id: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub event_type: String,
    #[sea_orm(column_type = "Json", nullable)]
    pub metadata: Option<serde_json::Value>,
    #[sea_orm(column_type = "Text", nullable)]
    pub ip_address: Option<String>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_delete = "SetNull"
    )]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
