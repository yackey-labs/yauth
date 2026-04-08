use chrono::Utc;
use sea_orm::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::entities::{authorization_codes, consents, device_codes, oauth2_clients};
use super::sea_err;
use crate::domain;
use crate::repo::{
    AuthorizationCodeRepository, ConsentRepository, DeviceCodeRepository, Oauth2ClientRepository,
    RepoFuture, sealed,
};

// -- Oauth2ClientRepository --

pub(crate) struct SeaOrmOauth2ClientRepo {
    db: DatabaseConnection,
}

impl SeaOrmOauth2ClientRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmOauth2ClientRepo {}

impl Oauth2ClientRepository for SeaOrmOauth2ClientRepo {
    fn find_by_client_id(&self, client_id: &str) -> RepoFuture<'_, Option<domain::Oauth2Client>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let row = oauth2_clients::Entity::find()
                .filter(oauth2_clients::Column::ClientId.eq(&client_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewOauth2Client) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = oauth2_clients::ActiveModel {
                id: Set(input.id.to_string()),
                client_id: Set(input.client_id),
                client_secret_hash: Set(input.client_secret_hash),
                redirect_uris: Set(input.redirect_uris),
                client_name: Set(input.client_name),
                grant_types: Set(input.grant_types),
                scopes: Set(input.scopes),
                is_public: Set(input.is_public),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }
}

// -- AuthorizationCodeRepository --

pub(crate) struct SeaOrmAuthorizationCodeRepo {
    db: DatabaseConnection,
}

impl SeaOrmAuthorizationCodeRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmAuthorizationCodeRepo {}

impl AuthorizationCodeRepository for SeaOrmAuthorizationCodeRepo {
    fn find_by_code_hash(
        &self,
        code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::AuthorizationCode>> {
        let code_hash = code_hash.to_string();
        Box::pin(async move {
            let now = Utc::now().fixed_offset();
            let row = authorization_codes::Entity::find()
                .filter(authorization_codes::Column::CodeHash.eq(&code_hash))
                .filter(authorization_codes::Column::ExpiresAt.gt(now))
                .filter(authorization_codes::Column::Used.eq(false))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewAuthorizationCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = authorization_codes::ActiveModel {
                id: Set(input.id.to_string()),
                code_hash: Set(input.code_hash),
                client_id: Set(input.client_id),
                user_id: Set(input.user_id.to_string()),
                scopes: Set(input.scopes),
                redirect_uri: Set(input.redirect_uri),
                code_challenge: Set(input.code_challenge),
                code_challenge_method: Set(input.code_challenge_method),
                expires_at: Set(super::to_tz(input.expires_at)),
                used: Set(input.used),
                nonce: Set(input.nonce),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn mark_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            authorization_codes::Entity::update_many()
                .col_expr(authorization_codes::Column::Used, Expr::value(true))
                .filter(authorization_codes::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// -- ConsentRepository --

pub(crate) struct SeaOrmConsentRepo {
    db: DatabaseConnection,
}

impl SeaOrmConsentRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmConsentRepo {}

impl ConsentRepository for SeaOrmConsentRepo {
    fn find_by_user_and_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> RepoFuture<'_, Option<domain::Consent>> {
        let client_id = client_id.to_string();
        Box::pin(async move {
            let row = consents::Entity::find()
                .filter(consents::Column::UserId.eq(user_id.to_string()))
                .filter(consents::Column::ClientId.eq(&client_id))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewConsent) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = consents::ActiveModel {
                id: Set(input.id.to_string()),
                user_id: Set(input.user_id.to_string()),
                client_id: Set(input.client_id),
                scopes: Set(input.scopes),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn update_scopes(&self, id: Uuid, scopes: Option<serde_json::Value>) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            consents::Entity::update_many()
                .col_expr(consents::Column::Scopes, Expr::value(scopes))
                .filter(consents::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}

// -- DeviceCodeRepository --

pub(crate) struct SeaOrmDeviceCodeRepo {
    db: DatabaseConnection,
}

impl SeaOrmDeviceCodeRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmDeviceCodeRepo {}

impl DeviceCodeRepository for SeaOrmDeviceCodeRepo {
    fn find_by_user_code_pending(
        &self,
        user_code: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let user_code = user_code.to_string();
        Box::pin(async move {
            let row = device_codes::Entity::find()
                .filter(device_codes::Column::UserCode.eq(&user_code))
                .filter(device_codes::Column::Status.eq("pending"))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> RepoFuture<'_, Option<domain::DeviceCode>> {
        let device_code_hash = device_code_hash.to_string();
        Box::pin(async move {
            let row = device_codes::Entity::find()
                .filter(device_codes::Column::DeviceCodeHash.eq(&device_code_hash))
                .one(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(row.map(|m| m.into_domain()))
        })
    }

    fn create(&self, input: domain::NewDeviceCode) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = device_codes::ActiveModel {
                id: Set(input.id.to_string()),
                device_code_hash: Set(input.device_code_hash),
                user_code: Set(input.user_code),
                client_id: Set(input.client_id),
                scopes: Set(input.scopes),
                user_id: Set(input.user_id.map(|u| u.to_string())),
                status: Set(input.status),
                interval: Set(input.interval),
                expires_at: Set(super::to_tz(input.expires_at)),
                last_polled_at: Set(None),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
            Ok(())
        })
    }

    fn update_status(&self, id: Uuid, status: &str, user_id: Option<Uuid>) -> RepoFuture<'_, ()> {
        let status = status.to_string();
        Box::pin(async move {
            device_codes::Entity::update_many()
                .col_expr(device_codes::Column::Status, Expr::value(status))
                .col_expr(
                    device_codes::Column::UserId,
                    Expr::value(user_id.map(|u| u.to_string())),
                )
                .filter(device_codes::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn update_last_polled(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            device_codes::Entity::update_many()
                .col_expr(
                    device_codes::Column::LastPolledAt,
                    Expr::value(chrono::Utc::now().fixed_offset()),
                )
                .filter(device_codes::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }

    fn update_interval(&self, id: Uuid, interval: i32) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            device_codes::Entity::update_many()
                .col_expr(device_codes::Column::Interval, Expr::value(interval))
                .filter(device_codes::Column::Id.eq(id.to_string()))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(())
        })
    }
}
