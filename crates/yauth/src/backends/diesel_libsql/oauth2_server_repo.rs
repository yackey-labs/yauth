use super::LibsqlPool;
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

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_oauth2_clients)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LC {
    pub id: String,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: String,
    pub client_name: Option<String>,
    pub grant_types: String,
    pub scopes: Option<String>,
    pub is_public: bool,
    pub created_at: String,
    pub token_endpoint_auth_method: Option<String>,
    pub public_key_pem: Option<String>,
    pub jwks_uri: Option<String>,
    pub banned_at: Option<String>,
    pub banned_reason: Option<String>,
}
impl LC {
    fn d(self) -> domain::Oauth2Client {
        domain::Oauth2Client {
            id: str_to_uuid(&self.id),
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            redirect_uris: str_to_json(&self.redirect_uris),
            client_name: self.client_name,
            grant_types: str_to_json(&self.grant_types),
            scopes: opt_str_to_json(self.scopes),
            is_public: self.is_public,
            created_at: str_to_dt(&self.created_at),
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            public_key_pem: self.public_key_pem,
            jwks_uri: self.jwks_uri,
            banned_at: opt_str_to_dt(self.banned_at),
            banned_reason: self.banned_reason,
        }
    }
}
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_authorization_codes)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct Lac {
    pub id: String,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Option<String>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: String,
    pub used: bool,
    pub nonce: Option<String>,
    pub created_at: String,
}
impl Lac {
    fn d(self) -> domain::AuthorizationCode {
        domain::AuthorizationCode {
            id: str_to_uuid(&self.id),
            code_hash: self.code_hash,
            client_id: self.client_id,
            user_id: str_to_uuid(&self.user_id),
            scopes: opt_str_to_json(self.scopes),
            redirect_uri: self.redirect_uri,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            expires_at: str_to_dt(&self.expires_at),
            used: self.used,
            nonce: self.nonce,
            created_at: str_to_dt(&self.created_at),
        }
    }
}
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_consents)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LCo {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub scopes: Option<String>,
    pub created_at: String,
}
impl LCo {
    fn d(self) -> domain::Consent {
        domain::Consent {
            id: str_to_uuid(&self.id),
            user_id: str_to_uuid(&self.user_id),
            client_id: self.client_id,
            scopes: opt_str_to_json(self.scopes),
            created_at: str_to_dt(&self.created_at),
        }
    }
}
#[derive(Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_device_codes)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct Ldc {
    pub id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scopes: Option<String>,
    pub user_id: Option<String>,
    pub status: String,
    pub interval: i32,
    pub expires_at: String,
    pub last_polled_at: Option<String>,
    pub created_at: String,
}
impl Ldc {
    fn d(self) -> domain::DeviceCode {
        domain::DeviceCode {
            id: str_to_uuid(&self.id),
            device_code_hash: self.device_code_hash,
            user_code: self.user_code,
            client_id: self.client_id,
            scopes: opt_str_to_json(self.scopes),
            user_id: opt_str_to_uuid(self.user_id),
            status: self.status,
            interval: self.interval,
            expires_at: str_to_dt(&self.expires_at),
            last_polled_at: opt_str_to_dt(self.last_polled_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

pub(crate) struct LibsqlOauth2ClientRepo {
    pool: LibsqlPool,
}
impl LibsqlOauth2ClientRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlOauth2ClientRepo {}
impl Oauth2ClientRepository for LibsqlOauth2ClientRepo {
    fn find_by_client_id(&self, cid: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let cid = cid.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_oauth2_clients::table
                .filter(yauth_oauth2_clients::client_id.eq(&cid))
                .select(LC::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.d()))
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
                opt_json_to_str(i.scopes),
                i.is_public,
                dt_to_str(i.created_at),
                i.token_endpoint_auth_method,
                i.public_key_pem,
                i.jwks_uri,
            );
            diesel::sql_query("INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at, token_endpoint_auth_method, public_key_pem, jwks_uri) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&cid).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&csh)
            .bind::<diesel::sql_types::Text, _>(&ru).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&cn).bind::<diesel::sql_types::Text, _>(&gt)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc).bind::<diesel::sql_types::Bool, _>(ip).bind::<diesel::sql_types::Text, _>(&ca)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&team)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&pkp)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&ju)
            .execute(&mut *c).await.map_err(diesel_err)?;
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
                Some((r, a)) => (Some(dt_to_str(a)), r),
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
                .select(LC::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(rows.into_iter().map(|r| r.d()).collect())
        })
    }
}

pub(crate) struct LibsqlAuthorizationCodeRepo {
    pool: LibsqlPool,
}
impl LibsqlAuthorizationCodeRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlAuthorizationCodeRepo {}
impl AuthorizationCodeRepository for LibsqlAuthorizationCodeRepo {
    fn find_by_code_hash(&self, ch: &str) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let ch = ch.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let r = yauth_authorization_codes::table
                .filter(
                    yauth_authorization_codes::code_hash
                        .eq(&ch)
                        .and(yauth_authorization_codes::used.eq(false))
                        .and(yauth_authorization_codes::expires_at.gt(&now)),
                )
                .select(Lac::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.d()))
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
                opt_json_to_str(i.scopes),
                i.redirect_uri,
                i.code_challenge,
                i.code_challenge_method,
                dt_to_str(i.expires_at),
                i.used,
                i.nonce,
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&ch).bind::<diesel::sql_types::Text, _>(&cid).bind::<diesel::sql_types::Text, _>(&uid)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc).bind::<diesel::sql_types::Text, _>(&ruri).bind::<diesel::sql_types::Text, _>(&cc).bind::<diesel::sql_types::Text, _>(&ccm)
            .bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Bool, _>(u).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&n).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
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

pub(crate) struct LibsqlConsentRepo {
    pool: LibsqlPool,
}
impl LibsqlConsentRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlConsentRepo {}
impl ConsentRepository for LibsqlConsentRepo {
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
                .select(LCo::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn create(&self, i: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, uid, cid, sc, ca) = (
                uuid_to_str(i.id),
                uuid_to_str(i.user_id),
                i.client_id,
                opt_json_to_str(i.scopes),
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&uid).bind::<diesel::sql_types::Text, _>(&cid).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_consents::table.find(&ids))
                .set(yauth_consents::scopes.eq(opt_json_to_str(scopes)))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct LibsqlDeviceCodeRepo {
    pool: LibsqlPool,
}
impl LibsqlDeviceCodeRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlDeviceCodeRepo {}
impl DeviceCodeRepository for LibsqlDeviceCodeRepo {
    fn find_by_user_code_pending(&self, uc: &str) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let uc = uc.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            let r = yauth_device_codes::table
                .filter(
                    yauth_device_codes::user_code
                        .eq(&uc)
                        .and(yauth_device_codes::status.eq("pending"))
                        .and(yauth_device_codes::expires_at.gt(&now)),
                )
                .select(Ldc::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn find_by_device_code_hash(&self, dch: &str) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let dch = dch.to_string();
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r = yauth_device_codes::table
                .filter(yauth_device_codes::device_code_hash.eq(&dch))
                .select(Ldc::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.d()))
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
                opt_json_to_str(i.scopes),
                opt_uuid_to_str(i.user_id),
                i.status,
                i.interval,
                dt_to_str(i.expires_at),
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&dch).bind::<diesel::sql_types::Text, _>(&uc).bind::<diesel::sql_types::Text, _>(&cid)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&sc).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&uid).bind::<diesel::sql_types::Text, _>(&st).bind::<diesel::sql_types::Integer, _>(iv)
            .bind::<diesel::sql_types::Text, _>(&ea).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
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
                    yauth_device_codes::user_id.eq(opt_uuid_to_str(uid)),
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
            let now = dt_to_str(chrono::Utc::now().naive_utc());
            diesel::update(yauth_device_codes::table.find(&ids))
                .set(yauth_device_codes::last_polled_at.eq(&now))
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
