use super::SqlitePool;
use super::models::str_to_dt;
use crate::backends::diesel_common::{get_conn, lazy_init_table, rate_limit_result};
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

const CREATE_RATE_LIMITS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_rate_limits (\
    key TEXT PRIMARY KEY, \
    count INTEGER NOT NULL DEFAULT 1, \
    window_start TEXT NOT NULL DEFAULT (datetime('now'))\
)";

pub(crate) struct SqliteRateLimitRepo {
    pool: SqlitePool,
    initialized: tokio::sync::OnceCell<()>,
}

impl SqliteRateLimitRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        let pool = &self.pool;
        lazy_init_table(&self.initialized, || async {
            use diesel_async_crate::SimpleAsyncConnection;
            let mut conn = get_conn(pool).await?;
            (*conn)
                .batch_execute(CREATE_RATE_LIMITS_TABLE)
                .await
                .map_err(|e| {
                    RepoError::Internal(format!("rate_limit table init failed: {e}").into())
                })?;
            Ok(())
        })
        .await
    }
}

impl sealed::Sealed for SqliteRateLimitRepo {}

impl RateLimitRepository for SqliteRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            // Fail-open: ensure table exists (runs once)
            self.ensure_init().await?;

            // SQLite-compatible upsert with window reset logic.
            // We use two statements: upsert then select.
            let conn = get_conn(&self.pool).await;
            match conn {
                Ok(mut conn) => {
                    use diesel_async_crate::RunQueryDsl;

                    // Upsert: if window expired, reset; else increment
                    let upsert_sql = "\
                        INSERT INTO yauth_rate_limits (key, count, window_start) \
                        VALUES (?, 1, datetime('now')) \
                        ON CONFLICT (key) DO UPDATE SET \
                            count = CASE \
                                WHEN datetime(yauth_rate_limits.window_start, '+' || ? || ' seconds') < datetime('now') \
                                THEN 1 \
                                ELSE yauth_rate_limits.count + 1 \
                            END, \
                            window_start = CASE \
                                WHEN datetime(yauth_rate_limits.window_start, '+' || ? || ' seconds') < datetime('now') \
                                THEN datetime('now') \
                                ELSE yauth_rate_limits.window_start \
                            END";

                    let upsert_result = diesel::sql_query(upsert_sql)
                        .bind::<diesel::sql_types::Text, _>(&key)
                        .bind::<diesel::sql_types::BigInt, _>(window_secs as i64)
                        .bind::<diesel::sql_types::BigInt, _>(window_secs as i64)
                        .execute(&mut *conn)
                        .await;

                    if let Err(e) = upsert_result {
                        crate::otel::record_error("rate_limit_upsert_failed", &e);
                        return Ok(domain::RateLimitResult {
                            allowed: true,
                            remaining: limit.saturating_sub(1),
                            retry_after: 0,
                        });
                    }

                    // Select current values
                    #[derive(diesel::QueryableByName)]
                    struct RateLimitRow {
                        #[diesel(sql_type = diesel::sql_types::Integer)]
                        count: i32,
                        #[diesel(sql_type = diesel::sql_types::Text)]
                        window_start: String,
                    }

                    let select_result: Result<Vec<RateLimitRow>, _> = diesel::sql_query(
                        "SELECT count, window_start FROM yauth_rate_limits WHERE key = ?",
                    )
                    .bind::<diesel::sql_types::Text, _>(&key)
                    .load(&mut *conn)
                    .await;

                    match select_result {
                        Ok(rows) => {
                            if let Some(row) = rows.into_iter().next() {
                                let count = row.count as u32;
                                let window_start = str_to_dt(&row.window_start).and_utc();
                                Ok(rate_limit_result(count, limit, window_start, window_secs))
                            } else {
                                // Shouldn't happen after upsert, fail-open
                                Ok(domain::RateLimitResult {
                                    allowed: true,
                                    remaining: limit.saturating_sub(1),
                                    retry_after: 0,
                                })
                            }
                        }
                        Err(e) => {
                            crate::otel::record_error("rate_limit_select_failed", &e);
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
