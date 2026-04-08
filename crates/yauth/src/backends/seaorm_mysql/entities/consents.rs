//! SeaORM entity for `yauth_consents` (MySQL dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_consents")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Char(Some(36))")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub client_id: String,
    #[sea_orm(column_type = "Json", nullable)]
    pub scopes: Option<serde_json::Value>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::Consent {
        crate::domain::Consent {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            user_id: crate::backends::seaorm_common::str_to_uuid(&self.user_id),
            client_id: self.client_id,
            scopes: self.scopes,
            created_at: self.created_at.naive_utc(),
        }
    }
}
