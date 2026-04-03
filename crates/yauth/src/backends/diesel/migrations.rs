use diesel::QueryableByName;
use diesel::sql_types::{BigInt, Text};
use diesel_async_crate::RunQueryDsl;

type Pool =
    diesel_async_crate::pooled_connection::deadpool::Pool<diesel_async_crate::AsyncPgConnection>;

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

async fn exec_sql(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    sql: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Split on semicolons and execute each statement individually.
    // (diesel::sql_query doesn't support multi-statement queries)
    for statement in sql.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        diesel::sql_query(trimmed)
            .execute(conn)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    }
    Ok(())
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

/// Returns the number of yauth columns that are still of type 'json' and need
/// converting to 'jsonb'. Used to make migration 016 idempotent without DO blocks
/// (which cannot be sent via PostgreSQL's extended/prepared-statement protocol).
async fn json_columns_remaining(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    schema: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let rows: Vec<CountRow> = diesel::sql_query(
        "SELECT COUNT(*)::bigint AS count \
         FROM information_schema.columns \
         WHERE table_schema = $1 \
           AND table_name IN (\
             'yauth_oauth2_clients','yauth_authorization_codes','yauth_consents',\
             'yauth_device_codes','yauth_webauthn_credentials','yauth_audit_log'\
           ) \
           AND data_type = 'json'",
    )
    .bind::<diesel::sql_types::Text, _>(schema)
    .load(conn)
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    Ok(rows.into_iter().next().map(|r| r.count).unwrap_or(0))
}

#[allow(dead_code)]
pub async fn run_migrations(pool: &Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_migrations_with_schema(pool, "public").await
}

pub async fn run_migrations_with_schema(
    pool: &Pool,
    schema: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Validate schema name to prevent SQL injection (format! interpolation below).
    // PostgreSQL unquoted identifiers: [a-z_][a-z0-9_]*, max 63 chars.
    if schema != "public" {
        let first_ok = !schema.is_empty()
            && (schema.as_bytes()[0].is_ascii_lowercase() || schema.as_bytes()[0] == b'_');
        let all_ok = schema.len() <= 63
            && schema
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !first_ok || !all_ok {
            return Err(format!("Invalid schema name '{schema}': must be 1-63 chars, start with a-z or _, contain only lowercase letters, digits, and underscores").into());
        }
    }

    let mut conn = pool.get().await?;

    // Create schema if non-default and set search_path
    if schema != "public" {
        exec_sql(&mut conn, &format!("CREATE SCHEMA IF NOT EXISTS {schema}")).await?;
        exec_sql(&mut conn, &format!("SET search_path TO {schema}, public")).await?;
    }

    // Core tables (always)
    exec_sql(&mut conn, CORE_UP).await?;

    #[cfg(feature = "email-password")]
    exec_sql(&mut conn, EMAIL_PASSWORD_UP).await?;

    #[cfg(feature = "passkey")]
    exec_sql(&mut conn, PASSKEY_UP).await?;

    #[cfg(feature = "mfa")]
    exec_sql(&mut conn, MFA_UP).await?;

    #[cfg(feature = "oauth")]
    exec_sql(&mut conn, OAUTH_UP).await?;

    #[cfg(feature = "bearer")]
    exec_sql(&mut conn, BEARER_UP).await?;

    #[cfg(feature = "api-key")]
    exec_sql(&mut conn, API_KEY_UP).await?;

    #[cfg(feature = "magic-link")]
    exec_sql(&mut conn, MAGIC_LINK_UP).await?;

    #[cfg(feature = "oauth")]
    exec_sql(&mut conn, OAUTH_TOKEN_REFRESH_UP).await?;

    #[cfg(feature = "oauth2-server")]
    exec_sql(&mut conn, OAUTH2_SERVER_UP).await?;

    #[cfg(feature = "oauth2-server")]
    exec_sql(&mut conn, DEVICE_AUTHORIZATION_UP).await?;

    #[cfg(feature = "account-lockout")]
    exec_sql(&mut conn, ACCOUNT_LOCKOUT_UP).await?;

    #[cfg(feature = "webhooks")]
    exec_sql(&mut conn, WEBHOOKS_UP).await?;

    #[cfg(feature = "oidc")]
    exec_sql(&mut conn, OIDC_UP).await?;

    // Fix json → jsonb for columns created by old SeaORM migrations.
    // Check first so the ALTER TABLE (which is not idempotent) only runs when needed.
    // DO $$ blocks cannot be used here because PostgreSQL rejects them via the
    // extended (prepared-statement) query protocol that diesel uses.
    if json_columns_remaining(&mut conn, schema).await? > 0 {
        exec_sql(&mut conn, FIX_JSON_JSONB_UP).await?;
    }

    Ok(())
}

#[derive(QueryableByName)]
#[allow(dead_code)]
struct TableName {
    #[diesel(sql_type = Text)]
    pub table_name: String,
}

#[allow(dead_code)]
pub async fn list_yauth_tables(
    pool: &Pool,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    list_yauth_tables_in_schema(pool, "public").await
}

#[allow(dead_code)]
pub async fn list_yauth_tables_in_schema(
    pool: &Pool,
    schema: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = pool.get().await?;
    let results: Vec<TableName> = diesel::sql_query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_name LIKE 'yauth_%' ORDER BY table_name",
    )
    .bind::<diesel::sql_types::Text, _>(schema)
    .load(&mut conn)
    .await?;
    Ok(results.into_iter().map(|r| r.table_name).collect())
}
