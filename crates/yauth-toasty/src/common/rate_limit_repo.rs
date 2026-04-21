use toasty::Db;

use crate::entities::YauthRateLimit;
use crate::helpers::toasty_err;
use yauth::repo::{RateLimitRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyRateLimitRepo {
    db: Db,
}

impl ToastyRateLimitRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyRateLimitRepo {}

impl RateLimitRepository for ToastyRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let now = jiff::Timestamp::now();
            let window_start_cutoff = now - jiff::SignedDuration::from_secs(window_secs as i64);

            // TODO: replace delete+insert with atomic upsert when Toasty adds ON CONFLICT
            let mut tx = db.transaction().await.map_err(toasty_err)?;
            let existing = YauthRateLimit::get_by_key(&mut tx, &key).await.ok();

            let (count, window_start) = match existing {
                Some(mut row) => {
                    if row.window_start < window_start_cutoff {
                        // Window expired — reset counter
                        row.delete().exec(&mut tx).await.map_err(toasty_err)?;
                        toasty::create!(YauthRateLimit {
                            key: key.clone(),
                            count: 1,
                            window_start: now,
                        })
                        .exec(&mut tx)
                        .await
                        .map_err(toasty_err)?;
                        (1u32, now)
                    } else {
                        // Within window — increment in-place
                        let new_count = row.count + 1;
                        let ws = row.window_start;
                        row.update()
                            .count(new_count)
                            .exec(&mut tx)
                            .await
                            .map_err(toasty_err)?;
                        (new_count as u32, ws)
                    }
                }
                None => {
                    toasty::create!(YauthRateLimit {
                        key: key.clone(),
                        count: 1,
                        window_start: now,
                    })
                    .exec(&mut tx)
                    .await
                    .map_err(toasty_err)?;
                    (1u32, now)
                }
            };
            tx.commit().await.map_err(toasty_err)?;

            Ok(rate_limit_result(count, limit, window_start, window_secs, now))
        })
    }
}

fn rate_limit_result(
    count: u32,
    limit: u32,
    window_start: jiff::Timestamp,
    window_secs: u64,
    now: jiff::Timestamp,
) -> domain::RateLimitResult {
    if count >= limit {
        let window_end = window_start + jiff::SignedDuration::from_secs(window_secs as i64);
        let diff = window_end.duration_since(now).as_secs();
        let retry_after = diff.max(0) as u64;
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
