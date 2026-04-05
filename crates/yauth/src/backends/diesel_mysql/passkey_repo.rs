use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{PasskeyRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlPasskeyRepo {
    pool: MysqlPool,
}
impl MysqlPasskeyRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlPasskeyRepo {}
impl PasskeyRepository for MysqlPasskeyRepo {
    fn find_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::WebauthnCredential>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r: Vec<MysqlWebauthnCredential> = yauth_webauthn_credentials::table
                .filter(yauth_webauthn_credentials::user_id.eq(&uid))
                .select(MysqlWebauthnCredential::as_select())
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
                .select(MysqlWebauthnCredential::as_select())
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
            let (id, uid, nm, aa, dn, cr, ca) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.name,
                input.aaguid,
                input.device_name,
                json_to_str(input.credential),
                input.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_webauthn_credentials \
                 (id, user_id, name, aaguid, device_name, credential, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&nm)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&aa)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&dn)
            .bind::<diesel::sql_types::Text, _>(&cr)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_last_used(&self, user_id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(
                yauth_webauthn_credentials::table
                    .filter(yauth_webauthn_credentials::user_id.eq(&uid)),
            )
            .set(yauth_webauthn_credentials::last_used_at.eq(now))
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
