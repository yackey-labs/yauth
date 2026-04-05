use super::MysqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

pub(crate) struct MysqlWebhookRepo {
    pool: MysqlPool,
}
impl MysqlWebhookRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlWebhookRepo {}
impl WebhookRepository for MysqlWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let r = yauth_webhooks::table
                .find(&ids)
                .select(MysqlWebhook::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.into_domain()))
        })
    }
    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r: Vec<MysqlWebhook> = yauth_webhooks::table
                .filter(yauth_webhooks::active.eq(true))
                .select(MysqlWebhook::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r: Vec<MysqlWebhook> = yauth_webhooks::table
                .select(MysqlWebhook::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn create(&self, i: domain::NewWebhook) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, url, sec, ev, act, ca, ua) = (
                uuid_to_str(i.id),
                i.url,
                i.secret,
                json_to_str(i.events),
                i.active,
                i.created_at,
                i.updated_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_webhooks \
                 (id, url, secret, events, active, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&url)
            .bind::<diesel::sql_types::Text, _>(&sec)
            .bind::<diesel::sql_types::Text, _>(&ev)
            .bind::<diesel::sql_types::Bool, _>(act)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .bind::<diesel::sql_types::Datetime, _>(&ua)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::update(yauth_webhooks::table.find(&ids))
                .set(&MysqlUpdateWebhook::from_domain(changes))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            let r = yauth_webhooks::table
                .find(&ids)
                .select(MysqlWebhook::as_select())
                .first(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_domain())
        })
    }
    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            diesel::delete(yauth_webhooks::table.find(&ids))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(())
        })
    }
}

pub(crate) struct MysqlWebhookDeliveryRepo {
    pool: MysqlPool,
}
impl MysqlWebhookDeliveryRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlWebhookDeliveryRepo {}
impl WebhookDeliveryRepository for MysqlWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        wid: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let w = uuid_to_str(wid);
            let r: Vec<MysqlWebhookDelivery> = yauth_webhook_deliveries::table
                .filter(yauth_webhook_deliveries::webhook_id.eq(&w))
                .order(yauth_webhook_deliveries::created_at.desc())
                .limit(limit)
                .select(MysqlWebhookDelivery::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.into_domain()).collect())
        })
    }
    fn create(&self, i: domain::NewWebhookDelivery) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let (id, wid, et, pl, sc, rb, su, at, ca) = (
                uuid_to_str(i.id),
                uuid_to_str(i.webhook_id),
                i.event_type,
                json_to_str(i.payload),
                i.status_code,
                i.response_body,
                i.success,
                i.attempt,
                i.created_at,
            );
            diesel::sql_query(
                "INSERT INTO yauth_webhook_deliveries \
                 (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<diesel::sql_types::Text, _>(&id)
            .bind::<diesel::sql_types::Text, _>(&wid)
            .bind::<diesel::sql_types::Text, _>(&et)
            .bind::<diesel::sql_types::Text, _>(&pl)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::SmallInt>, _>(sc)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&rb)
            .bind::<diesel::sql_types::Bool, _>(su)
            .bind::<diesel::sql_types::Integer, _>(at)
            .bind::<diesel::sql_types::Datetime, _>(&ca)
            .execute(&mut *c)
            .await
            .map_err(diesel_err)?;
            Ok(())
        })
    }
}
