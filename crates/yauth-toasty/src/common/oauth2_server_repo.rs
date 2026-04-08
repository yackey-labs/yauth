use chrono::Utc;
use toasty::Db;
use uuid::Uuid;

use crate::entities::{YauthAuthorizationCode, YauthConsent, YauthDeviceCode, YauthOauth2Client};
use crate::helpers::*;
use yauth::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};
use yauth_entity as domain;

// -- Oauth2ClientRepository --

pub(crate) struct ToastyOauth2ClientRepo {
    db: Db,
}

impl ToastyOauth2ClientRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyOauth2ClientRepo {}

impl Oauth2ClientRepository for ToastyOauth2ClientRepo {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthOauth2Client::filter_by_client_id(&client_id)
                .get(&mut db)
                .await
            {
                Ok(row) => Ok(Some(oauth2_client_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthOauth2Client {
                id: input.id,
                client_id: input.client_id,
                client_secret_hash: input.client_secret_hash,
                redirect_uris: json_to_str(&input.redirect_uris),
                client_name: input.client_name,
                grant_types: json_to_str(&input.grant_types),
                scopes: opt_json_to_str(input.scopes.as_ref()),
                is_public: input.is_public,
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }
}

// -- AuthorizationCodeRepository --

pub(crate) struct ToastyAuthorizationCodeRepo {
    db: Db,
}

impl ToastyAuthorizationCodeRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyAuthorizationCodeRepo {}

impl AuthorizationCodeRepository for ToastyAuthorizationCodeRepo {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let code_hash = code_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthAuthorizationCode::filter_by_code_hash(&code_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    let now = Utc::now().naive_utc();
                    if str_to_dt(&row.expires_at) < now || row.used {
                        Ok(None)
                    } else {
                        Ok(Some(auth_code_to_domain(row)))
                    }
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthAuthorizationCode {
                id: input.id,
                code_hash: input.code_hash,
                client_id: input.client_id,
                user_id: input.user_id,
                scopes: opt_json_to_str(input.scopes.as_ref()),
                redirect_uri: input.redirect_uri,
                code_challenge: input.code_challenge,
                code_challenge_method: input.code_challenge_method,
                expires_at: dt_to_str(input.expires_at),
                used: input.used,
                nonce: input.nonce,
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthAuthorizationCode::get_by_id(&mut db, &id).await {
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

// -- ConsentRepository --

pub(crate) struct ToastyConsentRepo {
    db: Db,
}

impl ToastyConsentRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyConsentRepo {}

impl ConsentRepository for ToastyConsentRepo {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthConsent> = YauthConsent::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows
                .into_iter()
                .find(|r| r.client_id == client_id)
                .map(consent_to_domain))
        })
    }

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthConsent {
                id: input.id,
                user_id: input.user_id,
                client_id: input.client_id,
                scopes: opt_json_to_str(input.scopes.as_ref()),
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthConsent::get_by_id(&mut db, &id).await {
                row.update()
                    .scopes(opt_json_to_str(scopes.as_ref()))
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}

// -- DeviceCodeRepository --

pub(crate) struct ToastyDeviceCodeRepo {
    db: Db,
}

impl ToastyDeviceCodeRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyDeviceCodeRepo {}

impl DeviceCodeRepository for ToastyDeviceCodeRepo {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let user_code = user_code.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthDeviceCode::filter_by_user_code(&user_code)
                .get(&mut db)
                .await
            {
                Ok(row) if row.status == "pending" => Ok(Some(device_code_to_domain(row))),
                _ => Ok(None),
            }
        })
    }

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let device_code_hash = device_code_hash.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthDeviceCode::filter_by_device_code_hash(&device_code_hash)
                .get(&mut db)
                .await
            {
                Ok(row) => Ok(Some(device_code_to_domain(row))),
                Err(_) => Ok(None),
            }
        })
    }

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthDeviceCode {
                id: input.id,
                device_code_hash: input.device_code_hash,
                user_code: input.user_code,
                client_id: input.client_id,
                scopes: opt_json_to_str(input.scopes.as_ref()),
                user_id: input.user_id,
                status: input.status,
                interval: input.interval,
                expires_at: dt_to_str(input.expires_at),
                last_polled_at: Option::<String>::None,
                created_at: dt_to_str(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()> {
        let status = status.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthDeviceCode::get_by_id(&mut db, &id).await {
                row.update()
                    .status(status)
                    .user_id(user_id)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthDeviceCode::get_by_id(&mut db, &id).await {
                row.update()
                    .last_polled_at(Some(dt_to_str(Utc::now().naive_utc())))
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthDeviceCode::get_by_id(&mut db, &id).await {
                row.update()
                    .interval(interval)
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}

// -- Domain conversions --

fn oauth2_client_to_domain(m: YauthOauth2Client) -> domain::Oauth2Client {
    domain::Oauth2Client {
        id: m.id,
        client_id: m.client_id,
        client_secret_hash: m.client_secret_hash,
        redirect_uris: str_to_json(&m.redirect_uris),
        client_name: m.client_name,
        grant_types: str_to_json(&m.grant_types),
        scopes: opt_str_to_json(m.scopes.as_deref()),
        is_public: m.is_public,
        created_at: str_to_dt(&m.created_at),
    }
}

fn auth_code_to_domain(m: YauthAuthorizationCode) -> domain::AuthorizationCode {
    domain::AuthorizationCode {
        id: m.id,
        code_hash: m.code_hash,
        client_id: m.client_id,
        user_id: m.user_id,
        scopes: opt_str_to_json(m.scopes.as_deref()),
        redirect_uri: m.redirect_uri,
        code_challenge: m.code_challenge,
        code_challenge_method: m.code_challenge_method,
        expires_at: str_to_dt(&m.expires_at),
        used: m.used,
        nonce: m.nonce,
        created_at: str_to_dt(&m.created_at),
    }
}

fn consent_to_domain(m: YauthConsent) -> domain::Consent {
    domain::Consent {
        id: m.id,
        user_id: m.user_id,
        client_id: m.client_id,
        scopes: opt_str_to_json(m.scopes.as_deref()),
        created_at: str_to_dt(&m.created_at),
    }
}

fn device_code_to_domain(m: YauthDeviceCode) -> domain::DeviceCode {
    domain::DeviceCode {
        id: m.id,
        device_code_hash: m.device_code_hash,
        user_code: m.user_code,
        client_id: m.client_id,
        scopes: opt_str_to_json(m.scopes.as_deref()),
        user_id: m.user_id,
        status: m.status,
        interval: m.interval,
        expires_at: str_to_dt(&m.expires_at),
        last_polled_at: opt_str_to_dt(m.last_polled_at.as_deref()),
        created_at: str_to_dt(&m.created_at),
    }
}
