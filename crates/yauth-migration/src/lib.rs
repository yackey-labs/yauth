pub use sea_orm_migration::prelude::*;

mod m20250101_000001_core;

#[cfg(feature = "email-password")]
mod m20250101_000002_email_password;

#[cfg(feature = "passkey")]
mod m20250101_000003_passkey;

#[cfg(feature = "mfa")]
mod m20250101_000004_mfa;

#[cfg(feature = "oauth")]
mod m20250101_000005_oauth;

#[cfg(feature = "bearer")]
mod m20250101_000006_bearer;

#[cfg(feature = "api-key")]
mod m20250101_000007_api_key;

#[cfg(feature = "magic-link")]
mod m20250101_000008_magic_link;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migration_table_name() -> sea_orm::DynIden {
        Alias::new("yauth_migrations").into_iden()
    }

    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        let mut migrations: Vec<Box<dyn MigrationTrait>> =
            vec![Box::new(m20250101_000001_core::Migration)];

        #[cfg(feature = "email-password")]
        migrations.push(Box::new(m20250101_000002_email_password::Migration));

        #[cfg(feature = "passkey")]
        migrations.push(Box::new(m20250101_000003_passkey::Migration));

        #[cfg(feature = "mfa")]
        migrations.push(Box::new(m20250101_000004_mfa::Migration));

        #[cfg(feature = "oauth")]
        migrations.push(Box::new(m20250101_000005_oauth::Migration));

        #[cfg(feature = "bearer")]
        migrations.push(Box::new(m20250101_000006_bearer::Migration));

        #[cfg(feature = "api-key")]
        migrations.push(Box::new(m20250101_000007_api_key::Migration));

        #[cfg(feature = "magic-link")]
        migrations.push(Box::new(m20250101_000008_magic_link::Migration));

        migrations
    }
}
