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
                    .table(YauthRefreshTokens::Table)
                    .if_not_exists()
                    .col(uuid(YauthRefreshTokens::Id).primary_key())
                    .col(uuid(YauthRefreshTokens::UserId))
                    .col(string_len_uniq(YauthRefreshTokens::TokenHash, 64))
                    .col(uuid(YauthRefreshTokens::FamilyId))
                    .col(timestamp_with_time_zone(YauthRefreshTokens::ExpiresAt))
                    .col(boolean(YauthRefreshTokens::Revoked).default(false))
                    .col(
                        timestamp_with_time_zone(YauthRefreshTokens::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthRefreshTokens::Table, YauthRefreshTokens::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_refresh_tokens_user_id")
                    .table(YauthRefreshTokens::Table)
                    .col(YauthRefreshTokens::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_refresh_tokens_family_id")
                    .table(YauthRefreshTokens::Table)
                    .col(YauthRefreshTokens::FamilyId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthRefreshTokens::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthRefreshTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    FamilyId,
    ExpiresAt,
    Revoked,
    CreatedAt,
}
