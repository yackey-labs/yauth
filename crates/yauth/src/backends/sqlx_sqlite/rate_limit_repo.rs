use chrono::NaiveDateTime;
use sqlx::SqlitePool;

use crate::backends::sqlx_common::{rate_limit_result, sqlx_err};
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS yauth_rate_limits (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 1,
    window_start TEXT NOT NULL DEFAULT (datetime('now'))
)
"#;

pub(crate) struct SqlxSqliteRateLimitRepo {
    pool: SqlitePool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxSqliteRateLimitRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                sqlx::raw_sql(CREATE_RATE_LIMITS_TABLE)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SqlxSqliteRateLimitRepo {}

impl RateLimitRepository for SqlxSqliteRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // SQLite: UPSERT with datetime arithmetic using strftime/datetime
            let sql = r#"
                INSERT INTO yauth_rate_limits (key, count, window_start)
                VALUES (?, 1, datetime('now'))
                ON CONFLICT (key) DO UPDATE
                    SET count = CASE
                            WHEN datetime(yauth_rate_limits.window_start, '+' || ? || ' seconds')
                                 < datetime('now')
                            THEN 1
                            ELSE yauth_rate_limits.count + 1
                        END,
                        window_start = CASE
                            WHEN datetime(yauth_rate_limits.window_start, '+' || ? || ' seconds')
                                 < datetime('now')
                            THEN datetime('now')
                            ELSE yauth_rate_limits.window_start
                        END
                RETURNING count, window_start
            "#;

            #[derive(sqlx::FromRow)]
            struct RateLimitRow {
                count: i32,
                window_start: NaiveDateTime,
            }

            match sqlx::query_as::<_, RateLimitRow>(sql)
                .bind(&key)
                .bind(window_secs as i64)
                .bind(window_secs as i64)
                .fetch_one(&self.pool)
                .await
            {
                Ok(row) => {
                    let count = row.count as u32;
                    let window_start = row.window_start.and_utc();
                    Ok(rate_limit_result(count, limit, window_start, window_secs))
                }
                Err(e) => {
                    crate::otel::record_error("rate_limit_check_failed", &e);
                    Ok(domain::RateLimitResult {
                        allowed: true,
                        remaining: limit.saturating_sub(1),
                        retry_after: 0,
                    })
                }
            }
        })
    }
}
