use super::LibsqlPool;
use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{RepoFuture, WebhookDeliveryRepository, WebhookRepository, sealed};
use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

#[derive(Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_webhooks)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct LW {
    pub id: String,
    pub url: String,
    pub secret: String,
    pub events: String,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}
impl LW {
    fn d(self) -> domain::Webhook {
        domain::Webhook {
            id: str_to_uuid(&self.id),
            url: self.url,
            secret: self.secret,
            events: str_to_json(&self.events),
            active: self.active,
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}
#[derive(Clone, AsChangeset)]
#[diesel(table_name = yauth_webhooks)]
pub(crate) struct Lwu {
    pub url: Option<String>,
    pub secret: Option<String>,
    pub events: Option<String>,
    pub active: Option<bool>,
    pub updated_at: Option<String>,
}
impl Lwu {
    fn from_domain(i: domain::UpdateWebhook) -> Self {
        Self {
            url: i.url,
            secret: i.secret,
            events: i.events.map(json_to_str),
            active: i.active,
            updated_at: i.updated_at.map(dt_to_str),
        }
    }
}
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = yauth_webhook_deliveries)]
#[diesel(check_for_backend(diesel_libsql::LibSql))]
pub(crate) struct Lwd {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub payload: String,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempt: i32,
    pub created_at: String,
}
impl Lwd {
    fn d(self) -> domain::WebhookDelivery {
        domain::WebhookDelivery {
            id: str_to_uuid(&self.id),
            webhook_id: str_to_uuid(&self.webhook_id),
            event_type: self.event_type,
            payload: str_to_json(&self.payload),
            status_code: self.status_code,
            response_body: self.response_body,
            success: self.success,
            attempt: self.attempt,
            created_at: str_to_dt(&self.created_at),
        }
    }
}

pub(crate) struct LibsqlWebhookRepo {
    pool: LibsqlPool,
}
impl LibsqlWebhookRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlWebhookRepo {}
impl WebhookRepository for LibsqlWebhookRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Webhook>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            let r = yauth_webhooks::table
                .find(&ids)
                .select(LW::as_select())
                .first(&mut *c)
                .await
                .optional()
                .map_err(diesel_err)?;
            Ok(r.map(|r| r.d()))
        })
    }
    fn find_active(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r: Vec<LW> = yauth_webhooks::table
                .filter(yauth_webhooks::active.eq(true))
                .select(LW::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.d()).collect())
        })
    }
    fn find_all(&self) -> RepoFuture<'_, Vec<domain::Webhook>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let r: Vec<LW> = yauth_webhooks::table
                .select(LW::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.d()).collect())
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
                dt_to_str(i.created_at),
                dt_to_str(i.updated_at),
            );
            diesel::sql_query("INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&url).bind::<diesel::sql_types::Text, _>(&sec).bind::<diesel::sql_types::Text, _>(&ev).bind::<diesel::sql_types::Bool, _>(act).bind::<diesel::sql_types::Text, _>(&ca).bind::<diesel::sql_types::Text, _>(&ua)
            .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
    fn update(&self, id: Uuid, changes: domain::UpdateWebhook) -> RepoFuture<'_, domain::Webhook> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let ids = uuid_to_str(id);
            // Update + re-select (AsChangeset works fine, but returning doesn't with AsChangeset)
            diesel::update(yauth_webhooks::table.find(&ids))
                .set(&Lwu::from_domain(changes))
                .execute(&mut *c)
                .await
                .map_err(diesel_err)?;
            let r = yauth_webhooks::table
                .find(&ids)
                .select(LW::as_select())
                .first(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.d())
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

pub(crate) struct LibsqlWebhookDeliveryRepo {
    pool: LibsqlPool,
}
impl LibsqlWebhookDeliveryRepo {
    pub(crate) fn new(pool: LibsqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for LibsqlWebhookDeliveryRepo {}
impl WebhookDeliveryRepository for LibsqlWebhookDeliveryRepo {
    fn find_by_webhook_id(
        &self,
        wid: Uuid,
        limit: i64,
    ) -> RepoFuture<'_, Vec<domain::WebhookDelivery>> {
        Box::pin(async move {
            let mut c = get_conn(&self.pool).await?;
            let w = uuid_to_str(wid);
            let r: Vec<Lwd> = yauth_webhook_deliveries::table
                .filter(yauth_webhook_deliveries::webhook_id.eq(&w))
                .order(yauth_webhook_deliveries::created_at.desc())
                .limit(limit)
                .select(Lwd::as_select())
                .load(&mut *c)
                .await
                .map_err(diesel_err)?;
            Ok(r.into_iter().map(|r| r.d()).collect())
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
                dt_to_str(i.created_at),
            );
            diesel::sql_query("INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind::<diesel::sql_types::Text, _>(&id).bind::<diesel::sql_types::Text, _>(&wid).bind::<diesel::sql_types::Text, _>(&et).bind::<diesel::sql_types::Text, _>(&pl)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::SmallInt>, _>(sc).bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&rb).bind::<diesel::sql_types::Bool, _>(su).bind::<diesel::sql_types::Integer, _>(at).bind::<diesel::sql_types::Text, _>(&ca)
            .execute(&mut *c).await.map_err(diesel_err)?;
            Ok(())
        })
    }
}
