use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::backends::sqlx_common::{rate_limit_result, sqlx_err};
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_rate_limits (
    key         TEXT PRIMARY KEY,
    count       INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
)
"#;

pub(crate) struct SqlxPgRateLimitRepo {
    pool: PgPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqlxPgRateLimitRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
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

impl sealed::Sealed for SqlxPgRateLimitRepo {}

impl RateLimitRepository for SqlxPgRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            #[derive(sqlx::FromRow)]
            struct RateLimitRow {
                count: i32,
                window_start: DateTime<Utc>,
            }

            let window = window_secs as f64;
            match sqlx::query_as!(
                RateLimitRow,
                r#"
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
                "#,
                key,
                window,
            )
            .fetch_one(&self.pool)
            .await
            {
                Ok(row) => {
                    let count = row.count as u32;
                    let window_start = row.window_start;
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
