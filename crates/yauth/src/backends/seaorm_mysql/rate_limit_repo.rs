use sea_orm::prelude::*;
use sea_orm::{ConnectionTrait, Schema, Statement};

use super::entities::rate_limits;
use super::sea_err;
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

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
                let schema = Schema::new(self.db.get_database_backend());
                let stmt = schema
                    .create_table_from_entity(rate_limits::Entity)
                    .if_not_exists()
                    .to_owned();
                let builder = self.db.get_database_backend();
                self.db
                    .execute_unprepared(&builder.build(&stmt).to_string())
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
            self.ensure_init().await?;

            let now = chrono::Utc::now();
            let now_naive = now.naive_utc();
            let backend = self.db.get_database_backend();

            // MySQL-compatible atomic upsert
            let upsert_sql = Statement::from_sql_and_values(
                backend,
                concat!(
                    "INSERT INTO yauth_rate_limits (`key`, count, window_start) ",
                    "VALUES (?, 1, ?) ",
                    "ON DUPLICATE KEY UPDATE ",
                    "count = IF(window_start + INTERVAL ? SECOND < ?, 1, count + 1), ",
                    "window_start = IF(window_start + INTERVAL ? SECOND < ?, ?, window_start)"
                ),
                [
                    sea_orm::Value::from(key.clone()),
                    sea_orm::Value::from(now_naive),
                    sea_orm::Value::from(window_secs as i64),
                    sea_orm::Value::from(now_naive),
                    sea_orm::Value::from(window_secs as i64),
                    sea_orm::Value::from(now_naive),
                    sea_orm::Value::from(now_naive),
                ],
            );
            let _ = self.db.execute_raw(upsert_sql).await;

            // Read back
            let select_sql = Statement::from_sql_and_values(
                backend,
                "SELECT count, window_start FROM yauth_rate_limits WHERE `key` = ?",
                [sea_orm::Value::from(key)],
            );
            match self.db.query_one_raw(select_sql).await {
                Ok(Some(row)) => {
                    let count: i32 = row.try_get("", "count").unwrap_or(1);
                    let ws: chrono::NaiveDateTime =
                        row.try_get("", "window_start").unwrap_or(now_naive);
                    let window_start = ws.and_utc();
                    Ok(rate_limit_result(
                        count as u32,
                        limit,
                        window_start,
                        window_secs,
                    ))
                }
                _ => {
                    // Fail-open on error
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
        let diff = (window_end - now).num_seconds();
        let retry_after = if diff > 0 { diff as u64 } else { 0 };
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
