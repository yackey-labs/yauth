use toasty::Db;

use crate::entities::YauthChallenge;
use crate::helpers::toasty_err;
use yauth::repo::{ChallengeRepository, RepoFuture, sealed};

pub(crate) struct ToastyChallengeRepo {
    db: Db,
}

impl ToastyChallengeRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyChallengeRepo {}

impl ChallengeRepository for ToastyChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let expires_at =
                jiff::Timestamp::now() + jiff::SignedDuration::from_secs(ttl_secs as i64);

            // TODO: replace with atomic upsert when Toasty adds ON CONFLICT support
            let mut tx = db.transaction().await.map_err(toasty_err)?;
            if let Ok(existing) = YauthChallenge::get_by_key(&mut tx, &key).await {
                existing.delete().exec(&mut tx).await.map_err(toasty_err)?;
            }
            toasty::create!(YauthChallenge {
                key,
                value,
                expires_at,
            })
            .exec(&mut tx)
            .await
            .map_err(toasty_err)?;
            tx.commit().await.map_err(toasty_err)?;

            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthChallenge::get_by_key(&mut db, &key).await {
                Ok(row) => {
                    if row.expires_at < jiff::Timestamp::now() {
                        // Expired
                        let _ = row.delete().exec(&mut db).await;
                        Ok(None)
                    } else {
                        Ok(Some(row.value))
                    }
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(row) = YauthChallenge::get_by_key(&mut db, &key).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }
}
