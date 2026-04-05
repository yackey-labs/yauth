use diesel::result::OptionalExtension;

use super::MysqlPool;
use crate::backends::diesel_common::{get_conn, lazy_init_table, rate_limit_result};
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

const CREATE_RATE_LIMITS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS yauth_rate_limits (\
    `key` VARCHAR(255) PRIMARY KEY, \
    count INT NOT NULL DEFAULT 1, \
    window_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP\
) ENGINE=InnoDB";

pub(crate) struct MysqlRateLimitRepo {
    pool: MysqlPool,
    initialized: tokio::sync::OnceCell<()>,
}

impl MysqlRateLimitRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self {
            pool,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        let pool = &self.pool;
        lazy_init_table(&self.initialized, || async {
            use diesel_async_crate::AsyncMysqlConnection;
            use diesel_async_crate::SimpleAsyncConnection;
            let mut conn = get_conn(pool).await?;
            <AsyncMysqlConnection as SimpleAsyncConnection>::batch_execute(
                &mut *conn,
                CREATE_RATE_LIMITS_TABLE,
            )
            .await
            .map_err(|e| {
                RepoError::Internal(format!("rate_limit table init failed: {e}").into())
            })?;
            Ok(())
        })
        .await
    }
}

impl sealed::Sealed for MysqlRateLimitRepo {}

impl RateLimitRepository for MysqlRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let conn = get_conn(&self.pool).await;
            match conn {
                Ok(mut conn) => {
                    use diesel_async_crate::RunQueryDsl;

                    // MySQL upsert: ON DUPLICATE KEY UPDATE with window reset logic
                    let upsert_sql = "\
                        INSERT INTO yauth_rate_limits (`key`, count, window_start) \
                        VALUES (?, 1, NOW()) \
                        ON DUPLICATE KEY UPDATE \
                            count = CASE \
                                WHEN DATE_ADD(yauth_rate_limits.window_start, INTERVAL ? SECOND) < NOW() \
                                THEN 1 \
                                ELSE yauth_rate_limits.count + 1 \
                            END, \
                            window_start = CASE \
                                WHEN DATE_ADD(yauth_rate_limits.window_start, INTERVAL ? SECOND) < NOW() \
                                THEN NOW() \
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

                    // Select current values using native Datetime type
                    #[derive(diesel::QueryableByName)]
                    struct RateLimitRow {
                        #[diesel(sql_type = diesel::sql_types::Integer)]
                        count: i32,
                        #[diesel(sql_type = diesel::sql_types::Datetime)]
                        window_start: chrono::NaiveDateTime,
                    }

                    let select_result: Result<Option<RateLimitRow>, _> = diesel::sql_query(
                        "SELECT count, window_start FROM yauth_rate_limits WHERE `key` = ? LIMIT 1",
                    )
                    .bind::<diesel::sql_types::Text, _>(&key)
                    .get_result(&mut *conn)
                    .await
                    .optional();

                    match select_result {
                        Ok(opt_row) => {
                            if let Some(row) = opt_row {
                                let count = row.count as u32;
                                let window_start = row.window_start.and_utc();
                                Ok(rate_limit_result(count, limit, window_start, window_secs))
                            } else {
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
