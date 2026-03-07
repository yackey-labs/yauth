use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(YauthWebhooks::Table)
                    .if_not_exists()
                    .col(uuid(YauthWebhooks::Id).primary_key())
                    .col(text(YauthWebhooks::Url))
                    .col(text(YauthWebhooks::Secret))
                    .col(json(YauthWebhooks::Events))
                    .col(boolean(YauthWebhooks::Active).default(true))
                    .col(
                        timestamp_with_time_zone(YauthWebhooks::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(YauthWebhooks::UpdatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(YauthWebhookDeliveries::Table)
                    .if_not_exists()
                    .col(uuid(YauthWebhookDeliveries::Id).primary_key())
                    .col(uuid(YauthWebhookDeliveries::WebhookId))
                    .col(text(YauthWebhookDeliveries::EventType))
                    .col(json(YauthWebhookDeliveries::Payload))
                    .col(small_integer_null(YauthWebhookDeliveries::StatusCode))
                    .col(text_null(YauthWebhookDeliveries::ResponseBody))
                    .col(boolean(YauthWebhookDeliveries::Success).default(false))
                    .col(integer(YauthWebhookDeliveries::Attempt).default(1))
                    .col(
                        timestamp_with_time_zone(YauthWebhookDeliveries::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                YauthWebhookDeliveries::Table,
                                YauthWebhookDeliveries::WebhookId,
                            )
                            .to(YauthWebhooks::Table, YauthWebhooks::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_webhook_deliveries_webhook_id")
                    .table(YauthWebhookDeliveries::Table)
                    .col(YauthWebhookDeliveries::WebhookId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_webhook_deliveries_created_at")
                    .table(YauthWebhookDeliveries::Table)
                    .col(YauthWebhookDeliveries::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(YauthWebhookDeliveries::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(YauthWebhooks::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthWebhooks {
    Table,
    Id,
    Url,
    Secret,
    Events,
    Active,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum YauthWebhookDeliveries {
    Table,
    Id,
    WebhookId,
    EventType,
    Payload,
    StatusCode,
    ResponseBody,
    Success,
    Attempt,
    CreatedAt,
}
