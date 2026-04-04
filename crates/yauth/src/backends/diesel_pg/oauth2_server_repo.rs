use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};
use crate::state::DbPool;

// ── Oauth2Client ──

pub(crate) struct DieselOauth2ClientRepo {
    pool: DbPool,
}
impl DieselOauth2ClientRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselOauth2ClientRepo {}

impl Oauth2ClientRepository for DieselOauth2ClientRepo {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_oauth2_clients::table
                .filter(yauth_oauth2_clients::client_id.eq(&client_id))
                .select(DieselOauth2Client::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_oauth2_clients::table)
                .values(&DieselNewOauth2Client::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

// ── AuthorizationCode ──

pub(crate) struct DieselAuthorizationCodeRepo {
    pool: DbPool,
}
impl DieselAuthorizationCodeRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselAuthorizationCodeRepo {}

impl AuthorizationCodeRepository for DieselAuthorizationCodeRepo {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let code_hash = code_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_authorization_codes::table
                .filter(
                    yauth_authorization_codes::code_hash
                        .eq(&code_hash)
                        .and(yauth_authorization_codes::used.eq(false))
                        .and(
                            yauth_authorization_codes::expires_at
                                .gt(chrono::Utc::now().naive_utc()),
                        ),
                )
                .select(DieselAuthorizationCode::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_authorization_codes::table)
                .values(&DieselNewAuthorizationCode::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_authorization_codes::table.find(id))
                .set(yauth_authorization_codes::used.eq(true))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

// ── Consent ──

pub(crate) struct DieselConsentRepo {
    pool: DbPool,
}
impl DieselConsentRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselConsentRepo {}

impl ConsentRepository for DieselConsentRepo {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_consents::table
                .filter(
                    yauth_consents::user_id
                        .eq(user_id)
                        .and(yauth_consents::client_id.eq(&client_id)),
                )
                .select(DieselConsent::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_consents::table)
                .values(&DieselNewConsent::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_consents::table.find(id))
                .set(yauth_consents::scopes.eq(scopes))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

// ── DeviceCode ──

pub(crate) struct DieselDeviceCodeRepo {
    pool: DbPool,
}
impl DieselDeviceCodeRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselDeviceCodeRepo {}

impl DeviceCodeRepository for DieselDeviceCodeRepo {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let user_code = user_code.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_device_codes::table
                .filter(
                    yauth_device_codes::user_code
                        .eq(&user_code)
                        .and(yauth_device_codes::status.eq("pending"))
                        .and(yauth_device_codes::expires_at.gt(chrono::Utc::now().naive_utc())),
                )
                .select(DieselDeviceCode::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let device_code_hash = device_code_hash.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_device_codes::table
                .filter(yauth_device_codes::device_code_hash.eq(&device_code_hash))
                .select(DieselDeviceCode::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_device_codes::table)
                .values(&DieselNewDeviceCode::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()> {
        let status = status.to_string();
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_device_codes::table.find(id))
                .set((
                    yauth_device_codes::status.eq(&status),
                    yauth_device_codes::user_id.eq(user_id),
                ))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_device_codes::table.find(id))
                .set(yauth_device_codes::last_polled_at.eq(chrono::Utc::now().naive_utc()))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::update(yauth_device_codes::table.find(id))
                .set(yauth_device_codes::interval.eq(interval))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
