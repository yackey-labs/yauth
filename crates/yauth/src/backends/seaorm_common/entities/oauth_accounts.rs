//! SeaORM entity for `yauth_oauth_accounts`.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_oauth_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Uuid")]
    pub id: Uuid,
    #[sea_orm(column_type = "Uuid")]
    pub user_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub provider: String,
    #[sea_orm(column_type = "Text")]
    pub provider_user_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub access_token_enc: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub refresh_token_enc: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: Option<DateTimeWithTimeZone>,
    pub updated_at: DateTimeWithTimeZone,
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
    pub fn into_domain(self) -> crate::domain::OauthAccount {
        crate::domain::OauthAccount {
            id: self.id,
            user_id: self.user_id,
            provider: self.provider,
            provider_user_id: self.provider_user_id,
            access_token_enc: self.access_token_enc,
            refresh_token_enc: self.refresh_token_enc,
            created_at: self.created_at.naive_utc(),
            expires_at: self.expires_at.map(|dt| dt.naive_utc()),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}
