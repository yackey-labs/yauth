use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};
use crate::state::DbPool;

pub(crate) struct DieselWebhookRepo {
    pool: DbPool,
}
impl DieselWebhookRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselWebhookRepo {}

impl WebhookRepository for DieselWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = yauth_webhooks::table
                .find(id)
                .select(DieselWebhook::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(result.map(|r| r.into_domain()))
        })
    }

    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let results: Vec<DieselWebhook> = yauth_webhooks::table
                .filter(yauth_webhooks::active.eq(true))
                .select(DieselWebhook::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let results: Vec<DieselWebhook> = yauth_webhooks::table
                .select(DieselWebhook::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_webhooks::table)
                .values(&DieselNewWebhook::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let result = diesel::update(yauth_webhooks::table.find(id))
                .set(&DieselUpdateWebhook::from_domain(changes))
                .returning(DieselWebhook::as_returning())
                .get_result(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(result.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::delete(yauth_webhooks::table.find(id))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct DieselWebhookDeliveryRepo {
    pool: DbPool,
}
impl DieselWebhookDeliveryRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for DieselWebhookDeliveryRepo {}

impl WebhookDeliveryRepository for DieselWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let results: Vec<DieselWebhookDelivery> = yauth_webhook_deliveries::table
                .filter(yauth_webhook_deliveries::webhook_id.eq(webhook_id))
                .order(yauth_webhook_deliveries::created_at.desc())
                .limit(limit)
                .select(DieselWebhookDelivery::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(results.into_iter().map(|r| r.into_domain()).collect())
        })
    }

    fn create(&self, input: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            diesel::insert_into(yauth_webhook_deliveries::table)
                .values(&DieselNewWebhookDelivery::from_domain(input))
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}
