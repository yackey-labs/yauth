use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250101_000001_core::YauthUsers;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(YauthOauthAccounts::Table)
                    .if_not_exists()
                    .col(uuid(YauthOauthAccounts::Id).primary_key())
                    .col(uuid(YauthOauthAccounts::UserId))
                    .col(string(YauthOauthAccounts::Provider))
                    .col(string(YauthOauthAccounts::ProviderUserId))
                    .col(text_null(YauthOauthAccounts::AccessTokenEnc))
                    .col(text_null(YauthOauthAccounts::RefreshTokenEnc))
                    .col(
                        timestamp_with_time_zone(YauthOauthAccounts::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthOauthAccounts::Table, YauthOauthAccounts::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_oauth_accounts_provider_user")
                    .table(YauthOauthAccounts::Table)
                    .col(YauthOauthAccounts::Provider)
                    .col(YauthOauthAccounts::ProviderUserId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_oauth_accounts_user_id")
                    .table(YauthOauthAccounts::Table)
                    .col(YauthOauthAccounts::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthOauthStates::Table)
                    .if_not_exists()
                    .col(string(YauthOauthStates::State).primary_key())
                    .col(string(YauthOauthStates::Provider))
                    .col(string_null(YauthOauthStates::RedirectUrl))
                    .col(timestamp_with_time_zone(YauthOauthStates::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(YauthOauthStates::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthOauthStates::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(YauthOauthAccounts::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthOauthAccounts {
    Table,
    Id,
    UserId,
    Provider,
    ProviderUserId,
    AccessTokenEnc,
    RefreshTokenEnc,
    CreatedAt,
}

#[derive(DeriveIden)]
enum YauthOauthStates {
    Table,
    State,
    Provider,
    RedirectUrl,
    ExpiresAt,
    CreatedAt,
}
