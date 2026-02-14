use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(YauthMagicLinks::Table)
                    .if_not_exists()
                    .col(uuid(YauthMagicLinks::Id).primary_key())
                    .col(string(YauthMagicLinks::Email))
                    .col(string_len_uniq(YauthMagicLinks::TokenHash, 64))
                    .col(timestamp_with_time_zone(YauthMagicLinks::ExpiresAt))
                    .col(boolean(YauthMagicLinks::Used).default(false))
                    .col(
                        timestamp_with_time_zone(YauthMagicLinks::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_magic_links_email")
                    .table(YauthMagicLinks::Table)
                    .col(YauthMagicLinks::Email)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_yauth_magic_links_token_hash")
                    .table(YauthMagicLinks::Table)
                    .col(YauthMagicLinks::TokenHash)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(YauthMagicLinks::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum YauthMagicLinks {
    Table,
    Id,
    Email,
    TokenHash,
    ExpiresAt,
    Used,
    CreatedAt,
}
