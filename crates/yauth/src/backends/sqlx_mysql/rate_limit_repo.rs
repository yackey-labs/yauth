use chrono::NaiveDateTime;
use sqlx::MySqlPool;

use crate::backends::sqlx_common::{rate_limit_result, sqlx_err};
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS yauth_rate_limits (
    `key`        VARCHAR(255) PRIMARY KEY,
    count        INT NOT NULL DEFAULT 1,
    window_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB
"#;

pub(crate) struct SqlxMysqlRateLimitRepo {
    pool: MySqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxMysqlRateLimitRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
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

impl sealed::Sealed for SqlxMysqlRateLimitRepo {}

impl RateLimitRepository for SqlxMysqlRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // MySQL: no RETURNING — INSERT/UPDATE then SELECT
            let upsert_sql = r#"
                INSERT INTO yauth_rate_limits (`key`, count, window_start)
                VALUES (?, 1, NOW())
                ON DUPLICATE KEY UPDATE
                    count = IF(window_start + INTERVAL ? SECOND < NOW(), 1, count + 1),
                    window_start = IF(window_start + INTERVAL ? SECOND < NOW(), NOW(), window_start)
            "#;

            match sqlx::query(upsert_sql)
                .bind(&key)
                .bind(window_secs as i64)
                .bind(window_secs as i64)
                .execute(&self.pool)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    crate::otel::record_error("rate_limit_upsert_failed", &e);
                    return Ok(domain::RateLimitResult {
                        allowed: true,
                        remaining: limit.saturating_sub(1),
                        retry_after: 0,
                    });
                }
            }

            #[derive(sqlx::FromRow)]
            struct RateLimitRow {
                count: i32,
                window_start: NaiveDateTime,
            }

            match sqlx::query_as::<_, RateLimitRow>(
                "SELECT count, window_start FROM yauth_rate_limits WHERE `key` = ?",
            )
            .bind(&key)
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
