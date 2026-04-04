use std::sync::atomic::{AtomicBool, Ordering};

use crate::backends::diesel_common::get_conn;
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};
use crate::state::DbPool;

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_rate_limits (
    key         TEXT PRIMARY KEY,
    count       INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
)
"#;

pub(crate) struct DieselRateLimitRepo {
    pool: DbPool,
    initialized: AtomicBool,
}

impl DieselRateLimitRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self {
            pool,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        if !self.initialized.load(Ordering::Relaxed) {
            use diesel_async_crate::RunQueryDsl;
            let mut conn = get_conn(&self.pool).await?;
            let _ = diesel::sql_query(CREATE_RATE_LIMITS_TABLE)
                .execute(&mut conn)
                .await;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl sealed::Sealed for DieselRateLimitRepo {}

impl RateLimitRepository for DieselRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            // Fail-open: if init or query fails, allow the request
            if let Err(e) = self.ensure_init().await {
                crate::otel::record_error("rate_limit_repo_init_failed", &e);
                return Ok(domain::RateLimitResult {
                    allowed: true,
                    remaining: limit.saturating_sub(1),
                    retry_after: 0,
                });
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

            use diesel_async_crate::RunQueryDsl;

            #[derive(diesel::QueryableByName)]
            struct RateLimitRow {
                #[diesel(sql_type = diesel::sql_types::Int4)]
                count: i32,
                #[diesel(sql_type = diesel::sql_types::Timestamptz)]
                window_start: chrono::NaiveDateTime,
            }

            let conn = get_conn(&self.pool).await;
            match conn {
                Ok(mut conn) => {
                    let result: Result<RateLimitRow, _> = diesel::sql_query(sql)
                        .bind::<diesel::sql_types::Text, _>(&key)
                        .bind::<diesel::sql_types::Float8, _>(window_secs as f64)
                        .get_result(&mut conn)
                        .await;

                    match result {
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
                }
                Err(e) => {
                    crate::otel::record_error("rate_limit_pool_error", &e);
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
    if count > limit {
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
