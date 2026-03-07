use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add nonce column to authorization_codes
        manager
            .alter_table(
                Table::alter()
                    .table(YauthAuthorizationCodes::Table)
                    .add_column_if_not_exists(text_null(YauthAuthorizationCodes::Nonce))
                    .to_owned(),
            )
            .await?;

        // Create oidc_nonces table
        manager
            .create_table(
                Table::create()
                    .table(YauthOidcNonces::Table)
                    .if_not_exists()
                    .col(uuid(YauthOidcNonces::Id).primary_key())
                    .col(text_uniq(YauthOidcNonces::NonceHash))
                    .col(uuid(YauthOidcNonces::AuthorizationCodeId))
                    .col(
                        timestamp_with_time_zone(YauthOidcNonces::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthOidcNonces::Table).to_owned())
            .await?;

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

#[derive(DeriveIden)]
enum YauthOidcNonces {
    Table,
    Id,
    NonceHash,
    AuthorizationCodeId,
    CreatedAt,
}
