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
                    .table(YauthApiKeys::Table)
                    .if_not_exists()
                    .col(uuid(YauthApiKeys::Id).primary_key())
                    .col(uuid(YauthApiKeys::UserId))
                    .col(string_len_uniq(YauthApiKeys::KeyPrefix, 12))
                    .col(string_len(YauthApiKeys::KeyHash, 64))
                    .col(string(YauthApiKeys::Name))
                    .col(json_null(YauthApiKeys::Scopes))
                    .col(timestamp_with_time_zone_null(YauthApiKeys::LastUsedAt))
                    .col(timestamp_with_time_zone_null(YauthApiKeys::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(YauthApiKeys::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthApiKeys::Table, YauthApiKeys::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_api_keys_user_id")
                    .table(YauthApiKeys::Table)
                    .col(YauthApiKeys::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthApiKeys::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthApiKeys {
    Table,
    Id,
    UserId,
    KeyPrefix,
    KeyHash,
    Name,
    Scopes,
    LastUsedAt,
    ExpiresAt,
    CreatedAt,
}
