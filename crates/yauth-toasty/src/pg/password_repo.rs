use chrono::Utc;
use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthEmailVerification, YauthPassword, YauthPasswordReset};
use crate::helpers::*;
use yauth::repo::{
    EmailVerificationRepository, PasswordRepository, PasswordResetRepository, RepoFuture, sealed,
};
use yauth_entity as domain;

// -- PasswordRepository --

pub(crate) struct ToastyPasswordRepo {
    db: Db,
}

impl ToastyPasswordRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyPasswordRepo {}

impl PasswordRepository for ToastyPasswordRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Option<domain::Password>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthPassword::get_by_user_id(&mut db, &user_id).await {
                Ok(row) => Ok(Some(domain::Password {
                    user_id: row.user_id,
                    password_hash: row.password_hash,
                })),
                Err(_) => Ok(None),
            }
        })
    }

    fn upsert(&self, input: domain::NewPassword) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Delete existing, then insert (no ON CONFLICT in Toasty)
            if let Ok(existing) = YauthPassword::get_by_user_id(&mut db, &input.user_id).await {
                let _ = existing.delete().exec(&mut db).await;
            }
            toasty::create!(YauthPassword {
                user_id: input.user_id,
                password_hash: input.password_hash,
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }
}

// -- EmailVerificationRepository --

pub(crate) struct ToastyEmailVerificationRepo {
    db: Db,
}

impl ToastyEmailVerificationRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyEmailVerificationRepo {}

impl EmailVerificationRepository for ToastyEmailVerificationRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::EmailVerification>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthEmailVerification::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    let now = Utc::now().naive_utc();
                    if str_to_dt(&row.expires_at) < now {
                        Ok(None)
                    } else {
                        Ok(Some(domain::EmailVerification {
                            id: row.id,
                            user_id: row.user_id,
                            token_hash: row.token_hash,
                            expires_at: str_to_dt(&row.expires_at),
                            created_at: str_to_dt(&row.created_at),
                        }))
                    }
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewEmailVerification) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthEmailVerification {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                expires_at: dt_to_str(input.expires_at),
                created_at: dt_to_str(input.created_at),
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
            if let Ok(row) = YauthEmailVerification::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthEmailVerification> =
                YauthEmailVerification::filter_by_user_id(user_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            for row in rows {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }
}

// -- PasswordResetRepository --

pub(crate) struct ToastyPasswordResetRepo {
    db: Db,
}

impl ToastyPasswordResetRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyPasswordResetRepo {}

impl PasswordResetRepository for ToastyPasswordResetRepo {
    fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> RepoFuture<'_, Option<domain::PasswordReset>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthPasswordReset::filter_by_token_hash(&token_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    let now = Utc::now().naive_utc();
                    if str_to_dt(&row.expires_at) < now || row.used_at.is_some() {
                        Ok(None)
                    } else {
                        Ok(Some(domain::PasswordReset {
                            id: row.id,
                            user_id: row.user_id,
                            token_hash: row.token_hash,
                            expires_at: str_to_dt(&row.expires_at),
                            used_at: opt_str_to_dt(row.used_at.as_deref()),
                            created_at: str_to_dt(&row.created_at),
                        }))
                    }
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewPasswordReset) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthPasswordReset {
                id: input.id,
                user_id: input.user_id,
                token_hash: input.token_hash,
                expires_at: dt_to_str(input.expires_at),
                used_at: Option::<String>::None,
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn delete_unused_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthPasswordReset> = YauthPasswordReset::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for row in rows {
                if row.used_at.is_none() {
                    let _ = row.delete().exec(&mut db).await;
                }
            }
            Ok(())
        })
    }
}
