use std::sync::atomic::{AtomicBool, Ordering};

use super::{ChallengeStore, RateLimitResult, RateLimitStore};
use crate::state::DbPool;

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_rate_limits (
    key         TEXT PRIMARY KEY,
    count       INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
)
"#;

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_challenges (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

// ---------------------------------------------------------------------------
// SeaORM helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "seaorm")]
async fn ensure_table_seaorm(
    db: &sea_orm::DatabaseConnection,
    ddl: &str,
) -> Result<(), String> {
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    db.execute(Statement::from_string(DbBackend::Postgres, ddl.to_owned()))
        .await
        .map_err(|e| format!("failed to create table: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Diesel helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "diesel-async")]
async fn ensure_table_diesel(
    pool: &diesel_async_crate::pooled_connection::deadpool::Pool<
        diesel_async_crate::AsyncPgConnection,
    >,
    ddl: &str,
) -> Result<(), String> {
    use diesel_async_crate::RunQueryDsl;
    let mut conn = pool.get().await.map_err(|e| format!("pool error: {e}"))?;
    diesel::sql_query(ddl)
        .execute(&mut conn)
        .await
        .map_err(|e| format!("failed to create table: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PostgresChallengeStore
// ---------------------------------------------------------------------------

pub struct PostgresChallengeStore {
    db: DbPool,
    initialized: AtomicBool,
}

impl PostgresChallengeStore {
    pub fn new(db: DbPool) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            #[cfg(feature = "seaorm")]
            ensure_table_seaorm(&self.db, CREATE_CHALLENGES_TABLE).await?;
            #[cfg(feature = "diesel-async")]
            ensure_table_diesel(&self.db, CREATE_CHALLENGES_TABLE).await?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), String> {
        #[cfg(feature = "seaorm")]
        {
            use sea_orm::{ConnectionTrait, DbBackend, Statement};
            self.db
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    "DELETE FROM yauth_challenges WHERE expires_at < now()".to_owned(),
                ))
                .await
                .map_err(|e| format!("cleanup failed: {e}"))?;
        }
        #[cfg(feature = "diesel-async")]
        {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;
            diesel::sql_query("DELETE FROM yauth_challenges WHERE expires_at < now()")
                .execute(&mut conn)
                .await
                .map_err(|e| format!("cleanup failed: {e}"))?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ChallengeStore for PostgresChallengeStore {
    async fn set(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> Result<(), String> {
        self.ensure_init().await?;
        let _ = self.cleanup_expired().await;

        let sql = r#"
            INSERT INTO yauth_challenges (key, value, expires_at)
            VALUES ($1, $2, now() + make_interval(secs => $3))
            ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value,
                    expires_at = EXCLUDED.expires_at
        "#;

        #[cfg(feature = "seaorm")]
        {
            use sea_orm::{ConnectionTrait, DbBackend, Statement};
            self.db
                .execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    vec![key.into(), value.into(), (ttl_secs as f64).into()],
                ))
                .await
                .map_err(|e| format!("challenge set failed: {e}"))?;
        }
        #[cfg(feature = "diesel-async")]
        {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;
            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(key)
                .bind::<diesel::sql_types::Jsonb, _>(value)
                .bind::<diesel::sql_types::Float8, _>(ttl_secs as f64)
                .execute(&mut conn)
                .await
                .map_err(|e| format!("challenge set failed: {e}"))?;
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
        self.ensure_init().await?;

        let sql = r#"
            SELECT value FROM yauth_challenges
            WHERE key = $1 AND expires_at > now()
        "#;

        #[cfg(feature = "seaorm")]
        {
            use sea_orm::{ConnectionTrait, DbBackend, Statement};
            let row = self
                .db
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    vec![key.into()],
                ))
                .await
                .map_err(|e| format!("challenge get failed: {e}"))?;

            match row {
                Some(r) => {
                    let val: serde_json::Value = r
                        .try_get_by_index::<serde_json::Value>(0)
                        .map_err(|e| format!("deserialize challenge value: {e}"))?;
                    Ok(Some(val))
                }
                None => Ok(None),
            }
        }
        #[cfg(feature = "diesel-async")]
        {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            #[derive(diesel::QueryableByName)]
            struct ChallengeRow {
                #[diesel(sql_type = diesel::sql_types::Jsonb)]
                value: serde_json::Value,
            }

            let result: Option<ChallengeRow> = diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(key)
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(|e| format!("challenge get failed: {e}"))?;
            Ok(result.map(|r| r.value))
        }
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.ensure_init().await?;

        let sql = "DELETE FROM yauth_challenges WHERE key = $1";

        #[cfg(feature = "seaorm")]
        {
            use sea_orm::{ConnectionTrait, DbBackend, Statement};
            self.db
                .execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    vec![key.into()],
                ))
                .await
                .map_err(|e| format!("challenge delete failed: {e}"))?;
        }
        #[cfg(feature = "diesel-async")]
        {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;
            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(key)
                .execute(&mut conn)
                .await
                .map_err(|e| format!("challenge delete failed: {e}"))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PostgresRateLimitStore
// ---------------------------------------------------------------------------

pub struct PostgresRateLimitStore {
    db: DbPool,
    initialized: AtomicBool,
}

impl PostgresRateLimitStore {
    pub fn new(db: DbPool) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            #[cfg(feature = "seaorm")]
            ensure_table_seaorm(&self.db, CREATE_RATE_LIMITS_TABLE).await?;
            #[cfg(feature = "diesel-async")]
            ensure_table_diesel(&self.db, CREATE_RATE_LIMITS_TABLE).await?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl RateLimitStore for PostgresRateLimitStore {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> RateLimitResult {
        if let Err(e) = self.ensure_init().await {
            tracing::error!("rate limit store init failed: {e}");
            return RateLimitResult {
                allowed: true,
                remaining: limit.saturating_sub(1),
                retry_after: 0,
            };
        }

        let sql = r#"
            INSERT INTO yauth_rate_limits (key, count, window_start)
            VALUES ($1, 1, now())
            ON CONFLICT (key) DO UPDATE
                SET count = CASE
                        WHEN yauth_rate_limits.window_start + make_interval(secs => $2)
                             < now()
                        THEN 1
                        ELSE yauth_rate_limits.count + 1
                    END,
                    window_start = CASE
                        WHEN yauth_rate_limits.window_start + make_interval(secs => $2)
                             < now()
                        THEN now()
                        ELSE yauth_rate_limits.window_start
                    END
            RETURNING count, window_start
        "#;

        #[cfg(feature = "seaorm")]
        {
            use sea_orm::{ConnectionTrait, DbBackend, Statement};
            let result = self
                .db
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    vec![key.into(), (window_secs as f64).into()],
                ))
                .await;

            match result {
                Ok(Some(row)) => {
                    let count: i32 = row.try_get_by_index(0).unwrap_or(1);
                    let window_start: chrono::DateTime<chrono::Utc> = row
                        .try_get_by_index(1)
                        .unwrap_or_else(|_| chrono::Utc::now());
                    let count = count as u32;
                    rate_limit_result(count, limit, window_start, window_secs)
                }
                Ok(None) | Err(_) => {
                    if let Err(e) = &result {
                        tracing::error!("rate limit check failed: {e}");
                    }
                    RateLimitResult {
                        allowed: true,
                        remaining: limit.saturating_sub(1),
                        retry_after: 0,
                    }
                }
            }
        }
        #[cfg(feature = "diesel-async")]
        {
            use diesel_async_crate::RunQueryDsl;

            #[derive(diesel::QueryableByName)]
            struct RateLimitRow {
                #[diesel(sql_type = diesel::sql_types::Int4)]
                count: i32,
                #[diesel(sql_type = diesel::sql_types::Timestamptz)]
                window_start: chrono::NaiveDateTime,
            }

            let conn = self.db.get().await;
            match conn {
                Ok(mut conn) => {
                    let result: Result<RateLimitRow, _> = diesel::sql_query(sql)
                        .bind::<diesel::sql_types::Text, _>(key)
                        .bind::<diesel::sql_types::Float8, _>(window_secs as f64)
                        .get_result(&mut conn)
                        .await;

                    match result {
                        Ok(row) => {
                            let count = row.count as u32;
                            let window_start = row
                                .window_start
                                .and_utc();
                            rate_limit_result(count, limit, window_start, window_secs)
                        }
                        Err(e) => {
                            tracing::error!("rate limit check failed: {e}");
                            RateLimitResult {
                                allowed: true,
                                remaining: limit.saturating_sub(1),
                                retry_after: 0,
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("rate limit pool error: {e}");
                    RateLimitResult {
                        allowed: true,
                        remaining: limit.saturating_sub(1),
                        retry_after: 0,
                    }
                }
            }
        }
    }
}

fn rate_limit_result(
    count: u32,
    limit: u32,
    window_start: chrono::DateTime<chrono::Utc>,
    window_secs: u64,
) -> RateLimitResult {
    if count > limit {
        let window_end = window_start + chrono::Duration::seconds(window_secs as i64);
        let now = chrono::Utc::now();
        let retry_after = (window_end - now).num_seconds().max(0) as u64;
        RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after,
        }
    } else {
        RateLimitResult {
            allowed: true,
            remaining: limit - count,
            retry_after: 0,
        }
    }
}

#[cfg(feature = "diesel-async")]
use diesel::result::OptionalExtension;
