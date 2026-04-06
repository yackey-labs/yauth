use super::SqlitePool;
use super::models::*;
use super::schema::*;
use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_webauthn_credentials)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub(crate) struct SqliteWebauthnCredential {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub aaguid: Option<String>,
    pub device_name: Option<String>,
    pub credential: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}
impl SqliteWebauthnCredential {
    fn into_domain(self) -> domain::WebauthnCredential {
        domain::WebauthnCredential {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            name: self.name,
            aaguid: self.aaguid,
            device_name: self.device_name,
            credential: str_to_json(&self.credential),
            created_at: str_to_dt(&self.created_at),
            last_used_at: opt_str_to_dt(self.last_used_at),
        }
    }
}

use crate::backends::diesel_common::{diesel_err, get_conn};

pub(crate) struct SqlitePasskeyRepo {
    pool: SqlitePool,
}
impl SqlitePasskeyRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for SqlitePasskeyRepo {}
impl PasskeyRepository for SqlitePasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r: Vec<SqliteWebauthnCredential> = yauth_webauthn_credentials::table
                .filter(yauth_webauthn_credentials::user_id.eq(&uid))
                .select(SqliteWebauthnCredential::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (ids, uid) = (uuid_to_str(id), uuid_to_str(user_id));
            let r = yauth_webauthn_credentials::table
                .filter(
                    yauth_webauthn_credentials::id
                        .eq(&ids)
                        .and(yauth_webauthn_credentials::user_id.eq(&uid)),
                )
                .select(SqliteWebauthnCredential::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, input: domain::NewWebauthnCredential) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let i = input;
            let (id, uid, nm, aa, dn, cr, ca) = (
                uuid_to_str(i.id),
                uuid_to_str(i.user_id),
                i.name,
                i.aaguid,
                i.device_name,
                json_to_str(i.credential),
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&nm)
                .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&aa).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&dn)
                .bind::<diesel::sql_types::Text, _>(&cr).bind::<diesel::sql_types::Text, _>(&ca)
                .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(
                yauth_webauthn_credentials::table
                    .filter(yauth_webauthn_credentials::user_id.eq(&uid)),
            )
            .set(yauth_webauthn_credentials::last_used_at.eq(&now))
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::delete(
                yauth_webauthn_credentials::table.filter(yauth_webauthn_credentials::id.eq(&ids)),
            )
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}
