use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};

use super::sea_err;
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_rate_limits (
    key         TEXT PRIMARY KEY,
    count       INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
)
"#;

pub(crate) struct SeaOrmRateLimitRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmRateLimitRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                self.db
                    .execute_unprepared(CREATE_RATE_LIMITS_TABLE)
                    .await
                    .map_err(sea_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl sealed::Sealed for SeaOrmRateLimitRepo {}

impl RateLimitRepository for SeaOrmRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            // Fail-open: ensure table exists
            self.ensure_init().await?;

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

            let stmt = Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                [key.into(), (window_secs as f64).into()],
            );

            match self.db.query_one_raw(stmt).await {
                Ok(Some(row)) => {
                    let count: i32 = row.try_get("", "count").map_err(sea_err)?;
                    let window_start: chrono::DateTime<chrono::Utc> =
                        row.try_get("", "window_start").map_err(sea_err)?;
                    let count = count as u32;
                    Ok(rate_limit_result(count, limit, window_start, window_secs))
                }
                Ok(None) => {
                    // Should not happen with RETURNING, but fail-open
                    Ok(domain::RateLimitResult {
                        allowed: true,
                        remaining: limit.saturating_sub(1),
                        retry_after: 0,
                    })
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

fn rate_limit_result(
    count: u32,
    limit: u32,
    window_start: chrono::DateTime<chrono::Utc>,
    window_secs: u64,
) -> domain::RateLimitResult {
    if count >= limit {
        let window_end = window_start + chrono::Duration::seconds(window_secs as i64);
        let now = chrono::Utc::now();
        let retry_after = (window_end - now).num_seconds().max(0) as u64;
        domain::RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after,
        }
    } else {
        domain::RateLimitResult {
            allowed: true,
            remaining: limit - count,
            retry_after: 0,
        }
    }
}
