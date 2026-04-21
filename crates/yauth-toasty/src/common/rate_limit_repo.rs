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

            // TODO: replace delete+insert with atomic upsert when Toasty adds ON CONFLICT
            let mut tx = db.transaction().await.map_err(toasty_err)?;
            let existing = YauthRateLimit::get_by_key(&mut tx, &key).await.ok();

            let (count, window_start) = match existing {
                Some(row) => {
                    let ws = jiff_to_chrono(row.window_start);
                    let ws_utc = ws.and_utc();
                    if ws_utc < window_start_cutoff {
                        row.delete().exec(&mut tx).await.map_err(toasty_err)?;
                        toasty::create!(YauthRateLimit {
                            key: key.clone(),
                            count: 1,
                            window_start: chrono_to_jiff(now.naive_utc()),
                        })
                        .exec(&mut tx)
                        .await
                        .map_err(toasty_err)?;
                        (1u32, now)
                    } else {
                        let new_count = row.count + 1;
                        row.delete().exec(&mut tx).await.map_err(toasty_err)?;
                        toasty::create!(YauthRateLimit {
                            key: key.clone(),
                            count: new_count,
                            window_start: chrono_to_jiff(ws),
                        })
                        .exec(&mut tx)
                        .await
                        .map_err(toasty_err)?;
                        (new_count as u32, ws_utc)
                    }
                }
                None => {
                    toasty::create!(YauthRateLimit {
                        key: key.clone(),
                        count: 1,
                        window_start: chrono_to_jiff(now.naive_utc()),
                    })
                    .exec(&mut tx)
                    .await
                    .map_err(toasty_err)?;
                    (1u32, now)
                }
            };
            tx.commit().await.map_err(toasty_err)?;

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
