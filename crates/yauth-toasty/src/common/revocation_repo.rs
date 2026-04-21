use toasty::Db;

use crate::entities::YauthRevocation;
use crate::helpers::{is_not_found, toasty_err};
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
                jiff::Timestamp::now() + jiff::SignedDuration::from_secs(ttl.as_secs() as i64);

            // TODO: replace with atomic upsert when Toasty adds ON CONFLICT support
            let mut tx = db.transaction().await.map_err(toasty_err)?;
            if let Ok(row) = YauthRevocation::get_by_key(&mut tx, &jti).await {
                row.delete().exec(&mut tx).await.map_err(toasty_err)?;
            }
            toasty::create!(YauthRevocation {
                key: jti,
                expires_at: expires_at,
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
                    if row.expires_at > jiff::Timestamp::now() {
                        Ok(true)
                    } else {
                        // Expired revocation -- clean up (best-effort)
                        let _ = row.delete().exec(&mut db).await;
                        Ok(false)
                    }
                }
                Err(e) if is_not_found(&e) => Ok(false),
                Err(e) => Err(toasty_err(e)),
            }
        })
    }
}
