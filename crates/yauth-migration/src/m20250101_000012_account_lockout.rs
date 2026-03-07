use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250101_000001_core::YauthUsers;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create yauth_account_locks table
        manager
            .create_table(
                Table::create()
                    .table(YauthAccountLocks::Table)
                    .if_not_exists()
                    .col(uuid(YauthAccountLocks::Id).primary_key())
                    .col(uuid_uniq(YauthAccountLocks::UserId))
                    .col(integer(YauthAccountLocks::FailedCount).default(0))
                    .col(timestamp_with_time_zone_null(
                        YauthAccountLocks::LockedUntil,
                    ))
                    .col(integer(YauthAccountLocks::LockCount).default(0))
                    .col(text_null(YauthAccountLocks::LockedReason))
                    .col(
                        timestamp_with_time_zone(YauthAccountLocks::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(YauthAccountLocks::UpdatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthAccountLocks::Table, YauthAccountLocks::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Index on user_id (unique already covers this, but explicit for clarity)
        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_account_locks_locked_until")
                    .table(YauthAccountLocks::Table)
                    .col(YauthAccountLocks::LockedUntil)
                    .to_owned(),
            )
            .await?;

        // Create yauth_unlock_tokens table
        manager
            .create_table(
                Table::create()
                    .table(YauthUnlockTokens::Table)
                    .if_not_exists()
                    .col(uuid(YauthUnlockTokens::Id).primary_key())
                    .col(uuid(YauthUnlockTokens::UserId))
                    .col(text_uniq(YauthUnlockTokens::TokenHash))
                    .col(timestamp_with_time_zone(YauthUnlockTokens::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(YauthUnlockTokens::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthUnlockTokens::Table, YauthUnlockTokens::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_unlock_tokens_user_id")
                    .table(YauthUnlockTokens::Table)
                    .col(YauthUnlockTokens::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_unlock_tokens_expires_at")
                    .table(YauthUnlockTokens::Table)
                    .col(YauthUnlockTokens::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthUnlockTokens::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(YauthAccountLocks::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthAccountLocks {
    Table,
    Id,
    UserId,
    FailedCount,
    LockedUntil,
    LockCount,
    LockedReason,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum YauthUnlockTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    CreatedAt,
}
