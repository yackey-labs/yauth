use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthBackupCode, YauthTotpSecret};
use crate::helpers::*;
use yauth::repo::{BackupCodeRepository, RepoFuture, TotpRepository, sealed};
use yauth_entity as domain;

// -- TotpRepository --

pub(crate) struct ToastyTotpRepo {
    db: Db,
}

impl ToastyTotpRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyTotpRepo {}

impl TotpRepository for ToastyTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthTotpSecret> = YauthTotpSecret::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            let row = rows.into_iter().find(|r| match verified {
                Some(v) => r.verified == v,
                None => true,
            });
            Ok(row.map(|r| domain::TotpSecret {
                id: r.id,
                user_id: r.user_id,
                encrypted_secret: r.encrypted_secret,
                verified: r.verified,
                created_at: str_to_dt(&r.created_at),
            }))
        })
    }

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthTotpSecret {
                id: input.id,
                user_id: input.user_id,
                encrypted_secret: input.encrypted_secret,
                verified: input.verified,
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthTotpSecret> = YauthTotpSecret::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for row in rows {
                if verified_only.is_none_or(|v| row.verified == v) {
                    let _ = row.delete().exec(&mut db).await;
                }
            }
            Ok(())
        })
    }

    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthTotpSecret::get_by_id(&mut db, &id).await {
                row.update()
                    .verified(true)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}

// -- BackupCodeRepository --

pub(crate) struct ToastyBackupCodeRepo {
    db: Db,
}

impl ToastyBackupCodeRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyBackupCodeRepo {}

impl BackupCodeRepository for ToastyBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthBackupCode> = YauthBackupCode::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows
                .into_iter()
                .filter(|r| !r.used)
                .map(|r| domain::BackupCode {
                    id: r.id,
                    user_id: r.user_id,
                    code_hash: r.code_hash,
                    used: r.used,
                    created_at: str_to_dt(&r.created_at),
                })
                .collect())
        })
    }

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthBackupCode {
                id: input.id,
                user_id: input.user_id,
                code_hash: input.code_hash,
                used: input.used,
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthBackupCode> = YauthBackupCode::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            for row in rows {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthBackupCode::get_by_id(&mut db, &id).await {
                row.update()
                    .used(true)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}
