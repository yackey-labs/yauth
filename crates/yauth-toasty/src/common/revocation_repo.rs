use chrono::Utc;
use toasty::Db;

use crate::entities::YauthRevocation;
use crate::helpers::*;
use yauth::repo::{RepoFuture, RevocationRepository, sealed};

pub(crate) struct ToastyRevocationRepo {
    db: Db,
}

impl ToastyRevocationRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyRevocationRepo {}

impl RevocationRepository for ToastyRevocationRepo {
    fn revoke_token(&self, jti: &str, ttl: std::time::Duration) -> RepoFuture<'_, ()> {
        let jti = jti.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let expires_at =
                Utc::now().naive_utc() + chrono::Duration::seconds(ttl.as_secs() as i64);

            // TODO: replace with atomic upsert when Toasty adds ON CONFLICT support
            let mut tx = db.transaction().await.map_err(toasty_err)?;
            if let Ok(row) = YauthRevocation::get_by_key(&mut tx, &jti).await {
                let _ = row.delete().exec(&mut tx).await;
            }
            toasty::create!(YauthRevocation {
                key: jti,
                expires_at: chrono_to_jiff(expires_at),
            })
            .exec(&mut tx)
            .await
            .map_err(toasty_err)?;
            tx.commit().await.map_err(toasty_err)?;

            Ok(())
        })
    }

    fn is_token_revoked(&self, jti: &str) -> RepoFuture<'_, bool> {
        let jti = jti.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthRevocation::get_by_key(&mut db, &jti).await {
                Ok(row) => {
                    let now = Utc::now().naive_utc();
                    if jiff_to_chrono(row.expires_at) > now {
                        Ok(true)
                    } else {
                        // Expired revocation -- clean up (best-effort)
                        let _ = row.delete().exec(&mut db).await;
                        Ok(false)
                    }
                }
                Err(e) => {
                    let msg = format!("{e}");
                    // "not found" means the token was never revoked
                    if msg.contains("not found") || msg.contains("no rows") {
                        Ok(false)
                    } else {
                        Err(toasty_err(e))
                    }
                }
            }
        })
    }
}
