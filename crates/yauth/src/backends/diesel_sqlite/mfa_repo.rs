use super::SqlitePool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{BackupCodeRepository, RepoFuture, TotpRepository, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_totp_secrets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteTotpSecret {
    pub id: String,
    pub user_id: String,
    pub encrypted_secret: String,
    pub verified: bool,
    pub created_at: String,
}
impl SqliteTotpSecret {
    fn into_domain(self) -> domain::TotpSecret {
        domain::TotpSecret {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            encrypted_secret: self.encrypted_secret,
            verified: self.verified,
            created_at: str_to_dt(&self.created_at),
        }
    }
}
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_backup_codes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteBackupCode {
    pub id: String,
    pub user_id: String,
    pub code_hash: String,
    pub used: bool,
    pub created_at: String,
}
impl SqliteBackupCode {
    fn into_domain(self) -> domain::BackupCode {
        domain::BackupCode {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            code_hash: self.code_hash,
            used: self.used,
            created_at: str_to_dt(&self.created_at),
        }
    }
}

pub(crate) struct SqliteTotpRepo {
    pool: SqlitePool,
}
impl SqliteTotpRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteTotpRepo {}
impl TotpRepository for SqliteTotpRepo {
    fn find_by_user_id(
        &self,
        user_id: Uuid,
        verified: Option<bool>,
    ) -> RepoFuture<'_, Option<domain::TotpSecret>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r = match verified {
                Some(v) => yauth_totp_secrets::table
                    .filter(
                        yauth_totp_secrets::user_id
                            .eq(&uid)
                            .and(yauth_totp_secrets::verified.eq(v)),
                    )
                    .select(SqliteTotpSecret::as_select())
                    .first(&mut *c)
                    .await
                    .optional()
                    .map_err(diesel_err)?,
                None => yauth_totp_secrets::table
                    .filter(yauth_totp_secrets::user_id.eq(&uid))
                    .select(SqliteTotpSecret::as_select())
                    .first(&mut *c)
                    .await
                    .optional()
                    .map_err(diesel_err)?,
            };
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewTotpSecret) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, es, v, ca) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.encrypted_secret,
                input.verified,
                dt_to_str(input.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at) VALUES (?, ?, ?, ?, ?)")
                .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&es).bind::<diesel::sql_types::Bool, _>(v).bind::<diesel::sql_types::Text, _>(&ca)
                .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete_for_user(&self, user_id: Uuid, verified_only: Option<bool>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            match verified_only {
                Some(v) => {
                    diesel::delete(
                        yauth_totp_secrets::table.filter(
                            yauth_totp_secrets::user_id
                                .eq(&uid)
                                .and(yauth_totp_secrets::verified.eq(v)),
                        ),
                    )
                    .execute(&mut *c)
                    .await
                    .map_err(diesel_err)?;
                }
                None => {
                    diesel::delete(
                        yauth_totp_secrets::table.filter(yauth_totp_secrets::user_id.eq(&uid)),
                    )
                    .execute(&mut *c)
                    .await
                    .map_err(diesel_err)?;
                }
            };
            Ok(())
        })
    }
    fn mark_verified(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_totp_secrets::table.find(&ids))
                .set(yauth_totp_secrets::verified.eq(true))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct SqliteBackupCodeRepo {
    pool: SqlitePool,
}
impl SqliteBackupCodeRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqliteBackupCodeRepo {}
impl BackupCodeRepository for SqliteBackupCodeRepo {
    fn find_unused_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::BackupCode>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r: Vec<SqliteBackupCode> = yauth_backup_codes::table
                .filter(
                    yauth_backup_codes::user_id
                        .eq(&uid)
                        .and(yauth_backup_codes::used.eq(false)),
                )
                .select(SqliteBackupCode::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn create(&self, input: domain::NewBackupCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, ch, u, ca) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.code_hash,
                input.used,
                dt_to_str(input.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, ?, ?)")
                .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&ch).bind::<diesel::sql_types::Bool, _>(u).bind::<diesel::sql_types::Text, _>(&ca)
                .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete_all_for_user(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            diesel::delete(yauth_backup_codes::table.filter(yauth_backup_codes::user_id.eq(&uid)))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_backup_codes::table.find(&ids))
                .set(yauth_backup_codes::used.eq(true))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
