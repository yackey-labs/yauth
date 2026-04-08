//! SeaORM entity for `yauth_email_verifications`.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_email_verifications")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Uuid")]
    pub id: Uuid,
    #[sea_orm(column_type = "Uuid")]
    pub user_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub token_hash: String,
    pub expires_at: DateTimeWithTimeZone,
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
    pub fn into_domain(self) -> crate::domain::EmailVerification {
        crate::domain::EmailVerification {
            id: self.id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            expires_at: self.expires_at.naive_utc(),
            created_at: self.created_at.naive_utc(),
        }
    }
}
