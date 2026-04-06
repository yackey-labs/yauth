use chrono::NaiveDateTime;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_err, str_to_uuid};
use crate::domain;
use crate::repo::{BackupCodeRepository, RepoFuture, TotpRepository, sealed};

#[derive(sqlx::FromRow)]
struct TotpRow {
    id: String,
    user_id: Option<String>,
    encrypted_secret: String,
    verified: i8,
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct BackupCodeRow {
    id: String,
    user_id: Option<String>,
    code_hash: String,
    used: i8,
    created_at: NaiveDateTime,
}

// ── TOTP ──

pub(crate) struct SqlxMysqlTotpRepo {
    pool: MySqlPool,
}
impl SqlxMysqlTotpRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlTotpRepo {}

impl TotpRepository for SqlxMysqlTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let row = match verified {
                Some(v) => sqlx::query_as!(
                    TotpRow,
                    "SELECT id, user_id, encrypted_secret, verified, created_at \
                     FROM yauth_totp_secrets WHERE user_id = ? AND verified = ?",
                    user_id_str,
                    v
                )
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?,
                None => sqlx::query_as!(
                    TotpRow,
                    "SELECT id, user_id, encrypted_secret, verified, created_at \
                     FROM yauth_totp_secrets WHERE user_id = ?",
                    user_id_str
                )
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?,
            };
            Ok(row.map(|r| domain::TotpSecret {
                id: str_to_uuid(&r.id),
                user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                encrypted_secret: r.encrypted_secret,
                verified: r.verified != 0,
                created_at: r.created_at,
            }))
        })
    }

    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            sqlx::query!(
                "INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.encrypted_secret,
                input.verified,
                input.created_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            match verified_only {
                Some(v) => {
                    sqlx::query!(
                        "DELETE FROM yauth_totp_secrets WHERE user_id = ? AND verified = ?",
                        user_id_str,
                        v
                    )
                    .execute(&self.pool)
                    .await
                    .map_err(sqlx_err)?;
                }
                None => {
                    sqlx::query!(
                        "DELETE FROM yauth_totp_secrets WHERE user_id = ?",
                        user_id_str
                    )
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
            let id_str = id.to_string();
            sqlx::query!(
                "UPDATE yauth_totp_secrets SET verified = true WHERE id = ?",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}

// ── Backup Codes ──

pub(crate) struct SqlxMysqlBackupCodeRepo {
    pool: MySqlPool,
}
impl SqlxMysqlBackupCodeRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlxMysqlBackupCodeRepo {}

impl BackupCodeRepository for SqlxMysqlBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            let rows = sqlx::query_as!(
                BackupCodeRow,
                "SELECT id, user_id, code_hash, used, created_at \
                 FROM yauth_backup_codes WHERE user_id = ? AND used = false",
                user_id_str
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::BackupCode {
                    id: str_to_uuid(&r.id),
                    user_id: str_to_uuid(&r.user_id.unwrap_or_default()),
                    code_hash: r.code_hash,
                    used: r.used != 0,
                    created_at: r.created_at,
                })
                .collect())
        })
    }

    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            sqlx::query!(
                "INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.code_hash,
                input.used,
                input.created_at,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let user_id_str = user_id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_backup_codes WHERE user_id = ?",
                user_id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "UPDATE yauth_backup_codes SET used = true WHERE id = ?",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }
}
