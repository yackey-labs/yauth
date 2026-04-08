use chrono::Utc;
use toasty::Db;

use crate::entities::YauthRateLimit;
use crate::helpers::*;
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
            let now = Utc::now();
            let window_start_cutoff = now - chrono::Duration::seconds(window_secs as i64);

            let existing = YauthRateLimit::get_by_key(&mut db, &key).await.ok();

            let (count, window_start) = match existing {
                Some(row) => {
                    let ws = str_to_dt(&row.window_start);
                    let ws_utc = ws.and_utc();
                    if ws_utc < window_start_cutoff {
                        // Window expired -- reset by delete+insert
                        let _ = row.delete().exec(&mut db).await;
                        let _ = toasty::create!(YauthRateLimit {
                            key: key.clone(),
                            count: 1,
                            window_start: dt_to_str(now.naive_utc()),
                        })
                        .exec(&mut db)
                        .await;
                        (1u32, now)
                    } else {
                        let new_count = row.count + 1;
                        // Update by delete+insert (Toasty update may not work for non-PK fields easily)
                        let _ = row.delete().exec(&mut db).await;
                        let _ = toasty::create!(YauthRateLimit {
                            key: key.clone(),
                            count: new_count,
                            window_start: dt_to_str(ws),
                        })
                        .exec(&mut db)
                        .await;
                        (new_count as u32, ws_utc)
                    }
                }
                None => {
                    let _ = toasty::create!(YauthRateLimit {
                        key: key.clone(),
                        count: 1,
                        window_start: dt_to_str(now.naive_utc()),
                    })
                    .exec(&mut db)
                    .await;
                    (1u32, now)
                }
            };

            Ok(rate_limit_result(count, limit, window_start, window_secs))
        })
    }
}

fn rate_limit_result(
    count: u32,
    limit: u32,
    window_start: chrono::DateTime<Utc>,
    window_secs: u64,
) -> domain::RateLimitResult {
    if count >= limit {
        let window_end = window_start + chrono::Duration::seconds(window_secs as i64);
        let now = Utc::now();
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
