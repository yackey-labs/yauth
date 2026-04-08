//! SeaORM entity for `yauth_webauthn_credentials` (SQLite dialect).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_webauthn_credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub aaguid: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub device_name: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub credential: String,
    pub created_at: DateTimeWithTimeZone,
    pub last_used_at: Option<DateTimeWithTimeZone>,
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
    pub fn into_domain(self) -> crate::domain::WebauthnCredential {
        crate::domain::WebauthnCredential {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            user_id: crate::backends::seaorm_common::str_to_uuid(&self.user_id),
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: crate::backends::seaorm_common::str_to_json(&self.credential),
            created_at: self.created_at.naive_utc(),
            last_used_at: self.last_used_at.map(|dt| dt.naive_utc()),
        }
    }
}
