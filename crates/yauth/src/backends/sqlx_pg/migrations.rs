//! Migration runner for sqlx-pg backend.
//! Reuses the same SQL as the diesel-pg migrations.

use sqlx::PgPool;

const CORE_UP: &str = include_str!("../../../diesel_migrations/00000000000001_core/up.sql");

#[cfg(feature = "email-password")]
const EMAIL_PASSWORD_UP: &str =
    include_str!("../../../diesel_migrations/00000000000002_email_password/up.sql");

#[cfg(feature = "passkey")]
const PASSKEY_UP: &str = include_str!("../../../diesel_migrations/00000000000003_passkey/up.sql");

#[cfg(feature = "mfa")]
const MFA_UP: &str = include_str!("../../../diesel_migrations/00000000000004_mfa/up.sql");

#[cfg(feature = "oauth")]
const OAUTH_UP: &str = include_str!("../../../diesel_migrations/00000000000005_oauth/up.sql");

#[cfg(feature = "bearer")]
const BEARER_UP: &str = include_str!("../../../diesel_migrations/00000000000006_bearer/up.sql");

#[cfg(feature = "api-key")]
const API_KEY_UP: &str = include_str!("../../../diesel_migrations/00000000000007_api_key/up.sql");

#[cfg(feature = "magic-link")]
const MAGIC_LINK_UP: &str =
    include_str!("../../../diesel_migrations/00000000000008_magic_link/up.sql");

#[cfg(feature = "oauth")]
const OAUTH_TOKEN_REFRESH_UP: &str =
    include_str!("../../../diesel_migrations/00000000000009_oauth_token_refresh/up.sql");

#[cfg(feature = "oauth2-server")]
const OAUTH2_SERVER_UP: &str =
    include_str!("../../../diesel_migrations/00000000000010_oauth2_server/up.sql");

#[cfg(feature = "oauth2-server")]
const DEVICE_AUTHORIZATION_UP: &str =
    include_str!("../../../diesel_migrations/00000000000011_device_authorization/up.sql");

#[cfg(feature = "account-lockout")]
const ACCOUNT_LOCKOUT_UP: &str =
    include_str!("../../../diesel_migrations/00000000000012_account_lockout/up.sql");

#[cfg(feature = "webhooks")]
const WEBHOOKS_UP: &str = include_str!("../../../diesel_migrations/00000000000014_webhooks/up.sql");

#[cfg(feature = "oidc")]
const OIDC_UP: &str = include_str!("../../../diesel_migrations/00000000000015_oidc/up.sql");

const FIX_JSON_JSONB_UP: &str =
    include_str!("../../../diesel_migrations/00000000000016_fix_json_to_jsonb/up.sql");

pub(crate) async fn run_migrations(
    pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Execute each migration SQL — they use IF NOT EXISTS, so re-running is safe
    sqlx::raw_sql(CORE_UP).execute(pool).await?;

    #[cfg(feature = "email-password")]
    sqlx::raw_sql(EMAIL_PASSWORD_UP).execute(pool).await?;

    #[cfg(feature = "passkey")]
    sqlx::raw_sql(PASSKEY_UP).execute(pool).await?;

    #[cfg(feature = "mfa")]
    sqlx::raw_sql(MFA_UP).execute(pool).await?;

    #[cfg(feature = "oauth")]
    {
        sqlx::raw_sql(OAUTH_UP).execute(pool).await?;
        sqlx::raw_sql(OAUTH_TOKEN_REFRESH_UP).execute(pool).await?;
    }

    #[cfg(feature = "bearer")]
    sqlx::raw_sql(BEARER_UP).execute(pool).await?;

    #[cfg(feature = "api-key")]
    sqlx::raw_sql(API_KEY_UP).execute(pool).await?;

    #[cfg(feature = "magic-link")]
    sqlx::raw_sql(MAGIC_LINK_UP).execute(pool).await?;

    #[cfg(feature = "oauth2-server")]
    {
        sqlx::raw_sql(OAUTH2_SERVER_UP).execute(pool).await?;
        sqlx::raw_sql(DEVICE_AUTHORIZATION_UP).execute(pool).await?;
    }

    #[cfg(feature = "account-lockout")]
    sqlx::raw_sql(ACCOUNT_LOCKOUT_UP).execute(pool).await?;

    #[cfg(feature = "webhooks")]
    sqlx::raw_sql(WEBHOOKS_UP).execute(pool).await?;

    #[cfg(feature = "oidc")]
    sqlx::raw_sql(OIDC_UP).execute(pool).await?;

    sqlx::raw_sql(FIX_JSON_JSONB_UP).execute(pool).await?;

    Ok(())
}
