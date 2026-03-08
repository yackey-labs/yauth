#[cfg(feature = "seaorm")]
pub use sea_orm_migration::prelude::*;

#[cfg(feature = "seaorm")]
mod m20250101_000001_core;

#[cfg(all(feature = "seaorm", feature = "email-password"))]
mod m20250101_000002_email_password;

#[cfg(all(feature = "seaorm", feature = "passkey"))]
mod m20250101_000003_passkey;

#[cfg(all(feature = "seaorm", feature = "mfa"))]
mod m20250101_000004_mfa;

#[cfg(all(feature = "seaorm", feature = "oauth"))]
mod m20250101_000005_oauth;

#[cfg(all(feature = "seaorm", feature = "bearer"))]
mod m20250101_000006_bearer;

#[cfg(all(feature = "seaorm", feature = "api-key"))]
mod m20250101_000007_api_key;

#[cfg(all(feature = "seaorm", feature = "magic-link"))]
mod m20250101_000008_magic_link;

#[cfg(all(feature = "seaorm", feature = "oauth"))]
mod m20250101_000009_oauth_token_refresh;

#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
mod m20250101_000010_oauth2_server;
#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
mod m20250101_000011_device_authorization;

#[cfg(all(feature = "seaorm", feature = "oauth2-server"))]
mod m20250101_000013_oauth2_auth_code_nonce;

#[cfg(all(feature = "seaorm", feature = "account-lockout"))]
mod m20250101_000012_account_lockout;

#[cfg(all(feature = "seaorm", feature = "webhooks"))]
mod m20250101_000014_webhooks;

#[cfg(all(feature = "seaorm", feature = "oidc"))]
mod m20250101_000015_oidc;

#[cfg(feature = "seaorm")]
pub struct Migrator;

#[cfg(feature = "seaorm")]
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

        #[cfg(feature = "oauth")]
        migrations.push(Box::new(m20250101_000009_oauth_token_refresh::Migration));

        #[cfg(feature = "oauth2-server")]
        migrations.push(Box::new(m20250101_000010_oauth2_server::Migration));

        #[cfg(feature = "oauth2-server")]
        migrations.push(Box::new(m20250101_000011_device_authorization::Migration));

        #[cfg(feature = "oauth2-server")]
        migrations.push(Box::new(m20250101_000013_oauth2_auth_code_nonce::Migration));

        #[cfg(feature = "account-lockout")]
        migrations.push(Box::new(m20250101_000012_account_lockout::Migration));

        #[cfg(feature = "webhooks")]
        migrations.push(Box::new(m20250101_000014_webhooks::Migration));

        #[cfg(feature = "oidc")]
        migrations.push(Box::new(m20250101_000015_oidc::Migration));

        migrations
    }
}

#[cfg(feature = "diesel-async")]
pub mod diesel_migrations;
