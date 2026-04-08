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

            // Delete existing, then insert (no ON CONFLICT in Toasty)
            if let Ok(existing) = YauthRevocation::get_by_key(&mut db, &jti).await {
                let _ = existing.delete().exec(&mut db).await;
            }

            toasty::create!(YauthRevocation {
                key: jti,
                expires_at: dt_to_str(expires_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;

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
                    if str_to_dt(&row.expires_at) > now {
                        Ok(true)
                    } else {
                        // Expired revocation -- clean up
                        let _ = row.delete().exec(&mut db).await;
                        Ok(false)
                    }
                }
                Err(_) => Ok(false),
            }
        })
    }
}
