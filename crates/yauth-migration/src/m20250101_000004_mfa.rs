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
                    .table(YauthTotpSecrets::Table)
                    .if_not_exists()
                    .col(uuid(YauthTotpSecrets::Id).primary_key())
                    .col(uuid_uniq(YauthTotpSecrets::UserId))
                    .col(text(YauthTotpSecrets::EncryptedSecret))
                    .col(boolean(YauthTotpSecrets::Verified).default(false))
                    .col(
                        timestamp_with_time_zone(YauthTotpSecrets::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthTotpSecrets::Table, YauthTotpSecrets::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthBackupCodes::Table)
                    .if_not_exists()
                    .col(uuid(YauthBackupCodes::Id).primary_key())
                    .col(uuid(YauthBackupCodes::UserId))
                    .col(string_len(YauthBackupCodes::CodeHash, 64))
                    .col(boolean(YauthBackupCodes::Used).default(false))
                    .col(
                        timestamp_with_time_zone(YauthBackupCodes::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthBackupCodes::Table, YauthBackupCodes::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_backup_codes_user_id")
                    .table(YauthBackupCodes::Table)
                    .col(YauthBackupCodes::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthBackupCodes::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(YauthTotpSecrets::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthTotpSecrets {
    Table,
    Id,
    UserId,
    EncryptedSecret,
    Verified,
    CreatedAt,
}

#[derive(DeriveIden)]
enum YauthBackupCodes {
    Table,
    Id,
    UserId,
    CodeHash,
    Used,
    CreatedAt,
}
