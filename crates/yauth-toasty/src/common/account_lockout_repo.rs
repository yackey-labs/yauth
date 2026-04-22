use chrono::NaiveDateTime;
use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthAccountLock, YauthUnlockToken};
use crate::helpers::{
    chrono_to_jiff, jiff_to_chrono, opt_chrono_to_jiff, opt_jiff_to_chrono, toasty_err,
};
use yauth::repo::{AccountLockRepository, RepoFuture, UnlockTokenRepository, sealed};
use yauth_entity as domain;

// -- AccountLockRepository --

pub(crate) struct ToastyAccountLockRepo {
    db: Db,
}

impl ToastyAccountLockRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyAccountLockRepo {}

impl AccountLockRepository for ToastyAccountLockRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::AccountLock>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthAccountLock> = YauthAccountLock::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows.into_iter().next().map(account_lock_to_domain))
        })
    }

    fn create(&self, input: domain::NewAccountLock) -> RepoFuture<'_, domain::AccountLock> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let row = toasty::create!(YauthAccountLock {
                id: input.id,
                user_id: input.user_id,
                failed_count: input.failed_count,
                locked_until: opt_chrono_to_jiff(input.locked_until),
                lock_count: input.lock_count,
                locked_reason: input.locked_reason,
                created_at: chrono_to_jiff(input.created_at),
                updated_at: chrono_to_jiff(input.updated_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(account_lock_to_domain(row))
        })
    }

    fn increment_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthAccountLock::get_by_id(&mut db, &id).await {
                let new_count = row.failed_count + 1;
                row.update()
                    .failed_count(new_count)
                    .updated_at(jiff::Timestamp::now())
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn set_locked(
        &self,
        id: Uuid,
        locked_until: Option<NaiveDateTime>,
        locked_reason: Option<&str>,
        lock_count: i32,
    ) -> RepoFuture<'_, ()> {
        let locked_reason = locked_reason.map(|s| s.to_string());
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthAccountLock::get_by_id(&mut db, &id).await {
                row.update()
                    .locked_until(opt_chrono_to_jiff(locked_until))
                    .locked_reason(locked_reason)
                    .lock_count(lock_count)
                    .updated_at(jiff::Timestamp::now())
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn reset_failed_count(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthAccountLock::get_by_id(&mut db, &id).await {
                row.update()
                    .failed_count(0)
                    .updated_at(jiff::Timestamp::now())
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn auto_unlock(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthAccountLock::get_by_id(&mut db, &id).await {
                row.update()
                    .locked_until(None::<jiff::Timestamp>)
                    .locked_reason(None::<String>)
                    .failed_count(0)
                    .updated_at(jiff::Timestamp::now())
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}

// -- UnlockTokenRepository --

pub(crate) struct ToastyUnlockTokenRepo {
    db: Db,
}

impl ToastyUnlockTokenRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyUnlockTokenRepo {}

impl UnlockTokenRepository for ToastyUnlockTokenRepo {
    fn find_by_token_hash(&self, token_hash: &str) -> RepoFuture<'_, Option<domain::UnlockToken>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthUnlockToken::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    if row.expires_at < jiff::Timestamp::now() {
                        Ok(None)
                    } else {
                        Ok(Some(unlock_token_to_domain(row)))
                    }
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewUnlockToken) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthUnlockToken {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                expires_at: chrono_to_jiff(input.expires_at),
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(row) = YauthUnlockToken::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            YauthUnlockToken::filter_by_user_id(user_id)
                .delete()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(())
        })
    }
}

fn account_lock_to_domain(m: YauthAccountLock) -> domain::AccountLock {
    domain::AccountLock {
        id: m.id,
        user_id: m.user_id,
        failed_count: m.failed_count,
        locked_until: opt_jiff_to_chrono(m.locked_until),
        lock_count: m.lock_count,
        locked_reason: m.locked_reason,
        created_at: jiff_to_chrono(m.created_at),
        updated_at: jiff_to_chrono(m.updated_at),
    }
}

fn unlock_token_to_domain(m: YauthUnlockToken) -> domain::UnlockToken {
    domain::UnlockToken {
        id: m.id,
        user_id: m.user_id,
        token_hash: m.token_hash,
        expires_at: jiff_to_chrono(m.expires_at),
        created_at: jiff_to_chrono(m.created_at),
    }
}
