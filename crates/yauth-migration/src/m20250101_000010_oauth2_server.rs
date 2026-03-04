use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250101_000001_core::YauthUsers;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create yauth_oauth2_clients
        manager
            .create_table(
                Table::create()
                    .table(YauthOauth2Clients::Table)
                    .if_not_exists()
                    .col(uuid(YauthOauth2Clients::Id).primary_key())
                    .col(text_uniq(YauthOauth2Clients::ClientId))
                    .col(text_null(YauthOauth2Clients::ClientSecretHash))
                    .col(json(YauthOauth2Clients::RedirectUris))
                    .col(text_null(YauthOauth2Clients::ClientName))
                    .col(json(YauthOauth2Clients::GrantTypes))
                    .col(json_null(YauthOauth2Clients::Scopes))
                    .col(boolean(YauthOauth2Clients::IsPublic).default(false))
                    .col(
                        timestamp_with_time_zone(YauthOauth2Clients::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Create yauth_authorization_codes
        manager
            .create_table(
                Table::create()
                    .table(YauthAuthorizationCodes::Table)
                    .if_not_exists()
                    .col(uuid(YauthAuthorizationCodes::Id).primary_key())
                    .col(text_uniq(YauthAuthorizationCodes::CodeHash))
                    .col(text(YauthAuthorizationCodes::ClientId))
                    .col(uuid(YauthAuthorizationCodes::UserId))
                    .col(json_null(YauthAuthorizationCodes::Scopes))
                    .col(text(YauthAuthorizationCodes::RedirectUri))
                    .col(text(YauthAuthorizationCodes::CodeChallenge))
                    .col(text(YauthAuthorizationCodes::CodeChallengeMethod))
                    .col(timestamp_with_time_zone(YauthAuthorizationCodes::ExpiresAt))
                    .col(boolean(YauthAuthorizationCodes::Used).default(false))
                    .col(
                        timestamp_with_time_zone(YauthAuthorizationCodes::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                YauthAuthorizationCodes::Table,
                                YauthAuthorizationCodes::UserId,
                            )
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_authorization_codes_user_id")
                    .table(YauthAuthorizationCodes::Table)
                    .col(YauthAuthorizationCodes::UserId)
                    .to_owned(),
            )
            .await?;

        // Create yauth_consents
        manager
            .create_table(
                Table::create()
                    .table(YauthConsents::Table)
                    .if_not_exists()
                    .col(uuid(YauthConsents::Id).primary_key())
                    .col(uuid(YauthConsents::UserId))
                    .col(text(YauthConsents::ClientId))
                    .col(json_null(YauthConsents::Scopes))
                    .col(
                        timestamp_with_time_zone(YauthConsents::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthConsents::Table, YauthConsents::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_consents_user_client")
                    .table(YauthConsents::Table)
                    .col(YauthConsents::UserId)
                    .col(YauthConsents::ClientId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthConsents::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(YauthAuthorizationCodes::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(YauthOauth2Clients::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthOauth2Clients {
    Table,
    Id,
    ClientId,
    ClientSecretHash,
    RedirectUris,
    ClientName,
    GrantTypes,
    Scopes,
    IsPublic,
    CreatedAt,
}

#[derive(DeriveIden)]
enum YauthAuthorizationCodes {
    Table,
    Id,
    CodeHash,
    ClientId,
    UserId,
    Scopes,
    RedirectUri,
    CodeChallenge,
    CodeChallengeMethod,
    ExpiresAt,
    Used,
    CreatedAt,
}

#[derive(DeriveIden)]
enum YauthConsents {
    Table,
    Id,
    UserId,
    ClientId,
    Scopes,
    CreatedAt,
}
