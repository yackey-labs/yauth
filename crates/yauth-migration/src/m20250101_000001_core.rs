use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(YauthUsers::Table)
                    .if_not_exists()
                    .col(uuid(YauthUsers::Id).primary_key())
                    .col(string_uniq(YauthUsers::Email))
                    .col(string_null(YauthUsers::DisplayName))
                    .col(boolean(YauthUsers::EmailVerified).default(false))
                    .col(string(YauthUsers::Role).default("user"))
                    .col(boolean(YauthUsers::Banned).default(false))
                    .col(string_null(YauthUsers::BannedReason))
                    .col(timestamp_with_time_zone_null(YauthUsers::BannedUntil))
                    .col(
                        timestamp_with_time_zone(YauthUsers::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(YauthUsers::UpdatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthSessions::Table)
                    .if_not_exists()
                    .col(uuid(YauthSessions::Id).primary_key())
                    .col(uuid(YauthSessions::UserId))
                    .col(string_len_uniq(YauthSessions::TokenHash, 64))
                    .col(string_null(YauthSessions::IpAddress))
                    .col(string_null(YauthSessions::UserAgent))
                    .col(timestamp_with_time_zone(YauthSessions::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(YauthSessions::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthSessions::Table, YauthSessions::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_sessions_user_id")
                    .table(YauthSessions::Table)
                    .col(YauthSessions::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_sessions_token_hash")
                    .table(YauthSessions::Table)
                    .col(YauthSessions::TokenHash)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthAuditLog::Table)
                    .if_not_exists()
                    .col(uuid(YauthAuditLog::Id).primary_key())
                    .col(uuid_null(YauthAuditLog::UserId))
                    .col(string(YauthAuditLog::EventType))
                    .col(json_null(YauthAuditLog::Metadata))
                    .col(string_null(YauthAuditLog::IpAddress))
                    .col(
                        timestamp_with_time_zone(YauthAuditLog::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(YauthAuditLog::Table, YauthAuditLog::UserId)
                            .to(YauthUsers::Table, YauthUsers::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_audit_log_user_id")
                    .table(YauthAuditLog::Table)
                    .col(YauthAuditLog::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_audit_log_event_type")
                    .table(YauthAuditLog::Table)
                    .col(YauthAuditLog::EventType)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthAuditLog::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(YauthSessions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(YauthUsers::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum YauthUsers {
    Table,
    Id,
    Email,
    DisplayName,
    EmailVerified,
    Role,
    Banned,
    BannedReason,
    BannedUntil,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum YauthSessions {
    Table,
    Id,
    UserId,
    TokenHash,
    IpAddress,
    UserAgent,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum YauthAuditLog {
    Table,
    Id,
    UserId,
    EventType,
    Metadata,
    IpAddress,
    CreatedAt,
}
