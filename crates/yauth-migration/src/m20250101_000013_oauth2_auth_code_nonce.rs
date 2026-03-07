use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(YauthAuthorizationCodes::Table)
                    .add_column_if_not_exists(text_null(YauthAuthorizationCodes::Nonce))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(YauthAuthorizationCodes::Table)
                    .drop_column(YauthAuthorizationCodes::Nonce)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthAuthorizationCodes {
    Table,
    Nonce,
}
