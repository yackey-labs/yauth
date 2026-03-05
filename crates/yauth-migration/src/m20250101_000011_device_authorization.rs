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
                    .table(YauthDeviceCodes::Table)
                    .if_not_exists()
                    .col(uuid(YauthDeviceCodes::Id).primary_key())
                    .col(text_uniq(YauthDeviceCodes::DeviceCodeHash))
                    .col(text_uniq(YauthDeviceCodes::UserCode))
                    .col(text(YauthDeviceCodes::ClientId))
                    .col(json_null(YauthDeviceCodes::Scopes))
                    .col(uuid_null(YauthDeviceCodes::UserId))
                    .col(text(YauthDeviceCodes::Status).default("pending"))
                    .col(integer(YauthDeviceCodes::Interval).default(5))
                    .col(timestamp_with_time_zone(YauthDeviceCodes::ExpiresAt))
                    .col(timestamp_with_time_zone_null(
                        YauthDeviceCodes::LastPolledAt,
                    ))
                    .col(
                        timestamp_with_time_zone(YauthDeviceCodes::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthDeviceCodes::Table, YauthDeviceCodes::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_device_codes_user_code")
                    .table(YauthDeviceCodes::Table)
                    .col(YauthDeviceCodes::UserCode)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_device_codes_status_expires")
                    .table(YauthDeviceCodes::Table)
                    .col(YauthDeviceCodes::Status)
                    .col(YauthDeviceCodes::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthDeviceCodes::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthDeviceCodes {
    Table,
    Id,
    DeviceCodeHash,
    UserCode,
    ClientId,
    Scopes,
    UserId,
    Status,
    Interval,
    ExpiresAt,
    LastPolledAt,
    CreatedAt,
}
