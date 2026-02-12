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
                    .table(YauthPasswords::Table)
                    .if_not_exists()
                    .col(uuid(YauthPasswords::UserId).primary_key())
                    .col(text(YauthPasswords::PasswordHash))
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthPasswords::Table, YauthPasswords::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthEmailVerifications::Table)
                    .if_not_exists()
                    .col(uuid(YauthEmailVerifications::Id).primary_key())
                    .col(uuid(YauthEmailVerifications::UserId))
                    .col(string_len_uniq(YauthEmailVerifications::TokenHash, 64))
                    .col(timestamp_with_time_zone(YauthEmailVerifications::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(YauthEmailVerifications::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                YauthEmailVerifications::Table,
                                YauthEmailVerifications::UserId,
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
                    .name("idx_yauth_email_verifications_user_id")
                    .table(YauthEmailVerifications::Table)
                    .col(YauthEmailVerifications::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthPasswordResets::Table)
                    .if_not_exists()
                    .col(uuid(YauthPasswordResets::Id).primary_key())
                    .col(uuid(YauthPasswordResets::UserId))
                    .col(string_len_uniq(YauthPasswordResets::TokenHash, 64))
                    .col(timestamp_with_time_zone(YauthPasswordResets::ExpiresAt))
                    .col(timestamp_with_time_zone_null(YauthPasswordResets::UsedAt))
                    .col(
                        timestamp_with_time_zone(YauthPasswordResets::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthPasswordResets::Table, YauthPasswordResets::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_password_resets_user_id")
                    .table(YauthPasswordResets::Table)
                    .col(YauthPasswordResets::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthPasswordResets::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(YauthEmailVerifications::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(YauthPasswords::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthPasswords {
    Table,
    UserId,
    PasswordHash,
}

#[derive(DeriveIden)]
enum YauthEmailVerifications {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum YauthPasswordResets {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    UsedAt,
    CreatedAt,
}
