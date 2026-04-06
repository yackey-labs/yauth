use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{BackupCodeRepository, RepoFuture, TotpRepository, sealed};

#[derive(sqlx::FromRow)]
struct TotpRow {
    id: Uuid,
    user_id: Uuid,
    encrypted_secret: String,
    verified: bool,
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct BackupCodeRow {
    id: Uuid,
    user_id: Uuid,
    code_hash: String,
    used: bool,
    created_at: NaiveDateTime,
}

// ── TOTP ──

pub(crate) struct SqlxSqliteTotpRepo {
    pool: SqlitePool,
}
impl SqlxSqliteTotpRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteTotpRepo {}

impl TotpRepository for SqlxSqliteTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let row = match verified {
                Some(v) => sqlx::query_as::<_, TotpRow>(
                    "SELECT id, user_id, encrypted_secret, verified, created_at \
                         FROM yauth_totp_secrets WHERE user_id = ? AND verified = ?",
                )
                .bind(user_id)
                .bind(v)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?,
                None => sqlx::query_as::<_, TotpRow>(
                    "SELECT id, user_id, encrypted_secret, verified, created_at \
                         FROM yauth_totp_secrets WHERE user_id = ?",
                )
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?,
            };
            Ok(row.map(|r| domain::TotpSecret {
                id: r.id,
                user_id: r.user_id,
                encrypted_secret: r.encrypted_secret,
                verified: r.verified,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.encrypted_secret)
            .bind(input.verified)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            match verified_only {
                Some(v) => {
                    sqlx::query(
                        "DELETE FROM yauth_totp_secrets WHERE user_id = ? AND verified = ?",
                    )
                    .bind(user_id)
                    .bind(v)
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                }
                None => {
                    sqlx::query("DELETE FROM yauth_totp_secrets WHERE user_id = ?")
                        .bind(user_id)
                        .execute(&self.pool)
                        .await
                        .map_err(sqlx_err)?;
                }
            };
            Ok(())
        })
    }

    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_totp_secrets SET verified = true WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── Backup Codes ──

pub(crate) struct SqlxSqliteBackupCodeRepo {
    pool: SqlitePool,
}
impl SqlxSqliteBackupCodeRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxSqliteBackupCodeRepo {}

impl BackupCodeRepository for SqlxSqliteBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let rows: Vec<BackupCodeRow> = sqlx::query_as(
                "SELECT id, user_id, code_hash, used, created_at \
                 FROM yauth_backup_codes WHERE user_id = ? AND used = false",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::BackupCode {
                    id: r.id,
                    user_id: r.user_id,
                    code_hash: r.code_hash,
                    used: r.used,
                    created_at: r.created_at,
                })
                .collect())
        })
    }

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.code_hash)
            .bind(input.used)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_backup_codes WHERE user_id = ?")
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE yauth_backup_codes SET used = true WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
