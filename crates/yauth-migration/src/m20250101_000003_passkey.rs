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
                    .table(YauthWebauthnCredentials::Table)
                    .if_not_exists()
                    .col(uuid(YauthWebauthnCredentials::Id).primary_key())
                    .col(uuid(YauthWebauthnCredentials::UserId))
                    .col(string(YauthWebauthnCredentials::Name))
                    .col(string_null(YauthWebauthnCredentials::Aaguid))
                    .col(string_null(YauthWebauthnCredentials::DeviceName))
                    .col(json(YauthWebauthnCredentials::Credential))
                    .col(
                        timestamp_with_time_zone(YauthWebauthnCredentials::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(
                        YauthWebauthnCredentials::LastUsedAt,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                YauthWebauthnCredentials::Table,
                                YauthWebauthnCredentials::UserId,
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
                    .name("idx_yauth_webauthn_credentials_user_id")
                    .table(YauthWebauthnCredentials::Table)
                    .col(YauthWebauthnCredentials::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(YauthWebauthnCredentials::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthWebauthnCredentials {
    Table,
    Id,
    UserId,
    Name,
    Aaguid,
    DeviceName,
    Credential,
    CreatedAt,
    LastUsedAt,
}
