use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{ApiKeyRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlApiKeyRepo {
    pool: MysqlPool,
}
impl MysqlApiKeyRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlApiKeyRepo {}
impl ApiKeyRepository for MysqlApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let p = prefix.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_api_keys::table
                .filter(yauth_api_keys::key_prefix.eq(&p))
                .select(MysqlApiKey::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (ids, uid) = (uuid_to_str(id), uuid_to_str(user_id));
            let r = yauth_api_keys::table
                .filter(
                    yauth_api_keys::id
                        .eq(&ids)
                        .and(yauth_api_keys::user_id.eq(&uid)),
                )
                .select(MysqlApiKey::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let uid = uuid_to_str(user_id);
            let r: Vec<MysqlApiKey> = yauth_api_keys::table
                .filter(yauth_api_keys::user_id.eq(&uid))
                .order(yauth_api_keys::created_at.desc())
                .select(MysqlApiKey::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, kp, kh, nm, sc, ea, ca) = (
                uuid_to_str(input.id),
                uuid_to_str(input.user_id),
                input.key_prefix,
                input.key_hash,
                input.name,
                input.scopes.map(json_to_str),
                input.expires_at,
                input.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_api_keys \
                 (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&kp)
            .bind::<diesel::sql_types::Text, _>(&kh)
            .bind::<diesel::sql_types::Text, _>(&nm)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Datetime>, _>(&ea)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
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
            diesel::delete(yauth_api_keys::table.filter(yauth_api_keys::id.eq(&ids)))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_api_keys::table.filter(yauth_api_keys::id.eq(&ids)))
                .set(yauth_api_keys::last_used_at.eq(now))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
