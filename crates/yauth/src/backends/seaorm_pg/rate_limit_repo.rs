use sea_orm::prelude::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectionTrait, Schema, Set};

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
            let now_tz = now.fixed_offset();
            let window_start_cutoff = now - chrono::Duration::seconds(window_secs as i64);

            // Read current state
            let existing = rate_limits::Entity::find_by_id(&key)
                .one(&self.db)
                .await
                .map_err(sea_err)?;

            let (count, window_start) = match existing {
                Some(row) => {
                    let ws = row.window_start.with_timezone(&chrono::Utc);
                    if ws < window_start_cutoff {
                        // Window expired — reset
                        rate_limits::Entity::update_many()
                            .col_expr(rate_limits::Column::Count, Expr::value(1))
                            .col_expr(rate_limits::Column::WindowStart, Expr::value(now_tz))
                            .filter(rate_limits::Column::Key.eq(&key))
                            .exec(&self.db)
                            .await
                            .map_err(sea_err)?;
                        (1u32, now)
                    } else {
                        // Window active — increment
                        let new_count = row.count + 1;
                        rate_limits::Entity::update_many()
                            .col_expr(rate_limits::Column::Count, Expr::value(new_count))
                            .filter(rate_limits::Column::Key.eq(&key))
                            .exec(&self.db)
                            .await
                            .map_err(sea_err)?;
                        (new_count as u32, ws)
                    }
                }
                None => {
                    // New key — insert
                    let model = rate_limits::ActiveModel {
                        key: Set(key.clone()),
                        count: Set(1),
                        window_start: Set(now_tz),
                    };
                    let _ = rate_limits::Entity::insert(model)
                        .on_conflict(
                            OnConflict::column(rate_limits::Column::Key)
                                .do_nothing()
                                .to_owned(),
                        )
                        .exec(&self.db)
                        .await;
                    (1u32, now)
                }
            };

            Ok(rate_limit_result(count, limit, window_start, window_secs))
        })
    }
}

use sea_orm::sea_query::Expr;

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
