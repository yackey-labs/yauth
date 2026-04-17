use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlOauth2ClientRepo {
    pool: MysqlPool,
}
impl MysqlOauth2ClientRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlOauth2ClientRepo {}
impl Oauth2ClientRepository for MysqlOauth2ClientRepo {
    fn find_by_client_id(&self, cid: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let cid = cid.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_oauth2_clients::table
                .filter(yauth_oauth2_clients::client_id.eq(&cid))
                .select(MysqlOauth2Client::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, i: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, cid, csh, ru, cn, gt, sc, ip, ca, team, pkp, ju) = (
                uuid_to_str(i.id),
                i.client_id,
                i.client_secret_hash,
                json_to_str(i.redirect_uris),
                i.client_name,
                json_to_str(i.grant_types),
                i.scopes.map(json_to_str),
                i.is_public,
                i.created_at,
                i.token_endpoint_auth_method,
                i.public_key_pem,
                i.jwks_uri,
            );
            diesel::sql_query(
                "INSERT INTO yauth_oauth2_clients \
                 (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at, token_endpoint_auth_method, public_key_pem, jwks_uri) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&cid)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&csh)
            .bind::<diesel::sql_types::Text, _>(&ru)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&cn)
            .bind::<diesel::sql_types::Text, _>(&gt)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc)
            .bind::<diesel::sql_types::Bool, _>(ip)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&team)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&pkp)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ju)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn set_banned(
        &self,
        client_id: &str,
        banned: Option<(Option<String>, chrono::NaiveDateTime)>,
    ) -> RepoFuture<'_, bool> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (at, reason) = match banned {
                Some((r, a)) => (Some(a), r),
                None => (None, None),
            };
            let updated = diesel::update(
                yauth_oauth2_clients::table.filter(yauth_oauth2_clients::client_id.eq(&client_id)),
            )
            .set((
                yauth_oauth2_clients::banned_at.eq(at),
                yauth_oauth2_clients::banned_reason.eq(reason),
            ))
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(updated > 0)
        })
    }

    fn rotate_public_key(
        &self,
        client_id: &str,
        public_key_pem: Option<String>,
    ) -> RepoFuture<'_, bool> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let updated = diesel::update(
                yauth_oauth2_clients::table.filter(yauth_oauth2_clients::client_id.eq(&client_id)),
            )
            .set(yauth_oauth2_clients::public_key_pem.eq(public_key_pem))
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(updated > 0)
        })
    }

    fn list_banned(&self) -> RepoFuture<'_, Vec<domain::Oauth2Client>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let rows = yauth_oauth2_clients::table
                .filter(yauth_oauth2_clients::banned_at.is_not_null())
                .order(yauth_oauth2_clients::banned_at.desc())
                .select(MysqlOauth2Client::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(rows.into_iter().map(|r| r.into_domain()).collect())
        })
    }
}

pub(crate) struct MysqlAuthorizationCodeRepo {
    pool: MysqlPool,
}
impl MysqlAuthorizationCodeRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlAuthorizationCodeRepo {}
impl AuthorizationCodeRepository for MysqlAuthorizationCodeRepo {
    fn find_by_code_hash(&self, ch: &str) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let ch = ch.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = chrono::Utc::now().naive_utc();
            let r = yauth_authorization_codes::table
                .filter(
                    yauth_authorization_codes::code_hash
                        .eq(&ch)
                        .and(yauth_authorization_codes::used.eq(false))
                        .and(yauth_authorization_codes::expires_at.gt(now)),
                )
                .select(MysqlAuthorizationCode::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, i: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, ch, cid, uid, sc, ruri, cc, ccm, ea, u, n, ca) = (
                uuid_to_str(i.id),
                i.code_hash,
                i.client_id,
                uuid_to_str(i.user_id),
                i.scopes.map(json_to_str),
                i.redirect_uri,
                i.code_challenge,
                i.code_challenge_method,
                i.expires_at,
                i.used,
                i.nonce,
                i.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_authorization_codes \
                 (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, \
                  code_challenge_method, expires_at, used, nonce, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&ch)
            .bind::<diesel::sql_types::Text, _>(&cid)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc)
            .bind::<diesel::sql_types::Text, _>(&ruri)
            .bind::<diesel::sql_types::Text, _>(&cc)
            .bind::<diesel::sql_types::Text, _>(&ccm)
            .bind::<diesel::sql_types::Datetime, _>(&ea)
            .bind::<diesel::sql_types::Bool, _>(u)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&n)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
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
            diesel::update(yauth_authorization_codes::table.find(&ids))
                .set(yauth_authorization_codes::used.eq(true))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct MysqlConsentRepo {
    pool: MysqlPool,
}
impl MysqlConsentRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlConsentRepo {}
impl ConsentRepository for MysqlConsentRepo {
    fn find_by_user_and_client(
        &self,
        uid: Uuid,
        cid: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let cid = cid.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let u = uuid_to_str(uid);
            let r = yauth_consents::table
                .filter(
                    yauth_consents::user_id
                        .eq(&u)
                        .and(yauth_consents::client_id.eq(&cid)),
                )
                .select(MysqlConsent::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, i: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, cid, sc, ca) = (
                uuid_to_str(i.id),
                uuid_to_str(i.user_id),
                i.client_id,
                i.scopes.map(json_to_str),
                i.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_consents \
                 (id, user_id, client_id, scopes, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&cid)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_consents::table.find(&ids))
                .set(yauth_consents::scopes.eq(scopes.map(json_to_str)))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct MysqlDeviceCodeRepo {
    pool: MysqlPool,
}
impl MysqlDeviceCodeRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlDeviceCodeRepo {}
impl DeviceCodeRepository for MysqlDeviceCodeRepo {
    fn find_by_user_code_pending(&self, uc: &str) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let uc = uc.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = chrono::Utc::now().naive_utc();
            let r = yauth_device_codes::table
                .filter(
                    yauth_device_codes::user_code
                        .eq(&uc)
                        .and(yauth_device_codes::status.eq("pending"))
                        .and(yauth_device_codes::expires_at.gt(now)),
                )
                .select(MysqlDeviceCode::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn find_by_device_code_hash(&self, dch: &str) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let dch = dch.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_device_codes::table
                .filter(yauth_device_codes::device_code_hash.eq(&dch))
                .select(MysqlDeviceCode::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn create(&self, i: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, dch, uc, cid, sc, uid, st, iv, ea, ca) = (
                uuid_to_str(i.id),
                i.device_code_hash,
                i.user_code,
                i.client_id,
                i.scopes.map(json_to_str),
                i.user_id.map(uuid_to_str),
                i.status,
                i.interval,
                i.expires_at,
                i.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_device_codes \
                 (id, device_code_hash, user_code, client_id, scopes, user_id, status, `interval`, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&dch)
            .bind::<diesel::sql_types::Text, _>(&uc)
            .bind::<diesel::sql_types::Text, _>(&cid)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&uid)
            .bind::<diesel::sql_types::Text, _>(&st)
            .bind::<diesel::sql_types::Integer, _>(iv)
            .bind::<diesel::sql_types::Datetime, _>(&ea)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_status(&self, id: Uuid, status: &str, uid: Option<Uuid>) -> RepoFuture<'_, ()> {
        let st = status.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_device_codes::table.find(&ids))
                .set((
                    yauth_device_codes::status.eq(&st),
                    yauth_device_codes::user_id.eq(uid.map(uuid_to_str)),
                ))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let now = chrono::Utc::now().naive_utc();
            diesel::update(yauth_device_codes::table.find(&ids))
                .set(yauth_device_codes::last_polled_at.eq(now))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_device_codes::table.find(&ids))
                .set(yauth_device_codes::interval.eq(interval))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
