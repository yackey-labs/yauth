use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add expires_at column (nullable — NULL means "no known expiry")
        manager
            .alter_table(
                Table::alter()
                    .table(YauthOauthAccounts::Table)
                    .add_column(
                        ColumnDef::new(YauthOauthAccounts::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add updated_at column with default of current timestamp
        manager
            .alter_table(
                Table::alter()
                    .table(YauthOauthAccounts::Table)
                    .add_column(
                        ColumnDef::new(YauthOauthAccounts::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(YauthOauthAccounts::Table)
                    .drop_column(YauthOauthAccounts::UpdatedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(YauthOauthAccounts::Table)
                    .drop_column(YauthOauthAccounts::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthOauthAccounts {
    Table,
    ExpiresAt,
    UpdatedAt,
}
