use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use std::sync::atomic::{AtomicBool, Ordering};

use super::{ChallengeStore, RateLimitResult, RateLimitStore};

// ---------------------------------------------------------------------------
// Shared helpers
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

async fn ensure_table(db: &DatabaseConnection, ddl: &str) -> Result<(), String> {
    db.execute(Statement::from_string(DbBackend::Postgres, ddl.to_owned()))
        .await
        .map_err(|e| format!("failed to create table: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PostgresChallengeStore
// ---------------------------------------------------------------------------

pub struct PostgresChallengeStore {
    db: DatabaseConnection,
    initialized: AtomicBool,
}

impl PostgresChallengeStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            ensure_table(&self.db, CREATE_CHALLENGES_TABLE).await?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Delete expired entries. Called opportunistically on `set` to keep the
    /// table from growing unbounded.
    async fn cleanup_expired(&self) -> Result<(), String> {
        self.db
            .execute(Statement::from_string(
                DbBackend::Postgres,
                "DELETE FROM yauth_challenges WHERE expires_at < now()".to_owned(),
            ))
            .await
            .map_err(|e| format!("cleanup failed: {e}"))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ChallengeStore for PostgresChallengeStore {
    async fn set(&self, key: &str, value: serde_json::Value, ttl_secs: u64) -> Result<(), String> {
        self.ensure_init().await?;

        // Opportunistic cleanup — fire-and-forget, don't fail the set
        let _ = self.cleanup_expired().await;

        // Upsert: insert or update on conflict
        let sql = r#"
            INSERT INTO yauth_challenges (key, value, expires_at)
            VALUES ($1, $2, now() + make_interval(secs => $3))
            ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value,
                    expires_at = EXCLUDED.expires_at
        "#;

        self.db
            .execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![
                    key.into(),
                    value.into(),
                    (ttl_secs as f64).into(),
                ],
            ))
            .await
            .map_err(|e| format!("challenge set failed: {e}"))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
        self.ensure_init().await?;

        let sql = r#"
            SELECT value FROM yauth_challenges
            WHERE key = $1 AND expires_at > now()
        "#;

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

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.ensure_init().await?;

        let sql = "DELETE FROM yauth_challenges WHERE key = $1";

        self.db
            .execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![key.into()],
            ))
            .await
            .map_err(|e| format!("challenge delete failed: {e}"))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PostgresRateLimitStore
// ---------------------------------------------------------------------------

pub struct PostgresRateLimitStore {
    db: DatabaseConnection,
    initialized: AtomicBool,
}

impl PostgresRateLimitStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            ensure_table(&self.db, CREATE_RATE_LIMITS_TABLE).await?;
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
            // Fail open — allow the request rather than blocking everyone
            return RateLimitResult {
                allowed: true,
                remaining: limit.saturating_sub(1),
                retry_after: 0,
            };
        }

        // Atomic upsert that either:
        //   - Inserts a new row with count=1 if the key doesn't exist
        //   - Resets the window and sets count=1 if the window has expired
        //   - Increments the count if within the current window
        // Returns the resulting count and window_start.
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

        let result = self
            .db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![
                    key.into(),
                    (window_secs as f64).into(),
                ],
            ))
            .await;

        match result {
            Ok(Some(row)) => {
                let count: i32 = row.try_get_by_index(0).unwrap_or(1);
                let window_start: chrono::DateTime<chrono::Utc> = row
                    .try_get_by_index(1)
                    .unwrap_or_else(|_| chrono::Utc::now());

                let count = count as u32;

                if count > limit {
                    // Over limit — compute retry_after
                    let window_end = window_start
                        + chrono::Duration::seconds(window_secs as i64);
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
            Ok(None) | Err(_) => {
                // Fail open on unexpected errors
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
}
