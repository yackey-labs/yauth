use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use uuid::Uuid;

use super::{
    ChallengeStore, RateLimitResult, RateLimitStore, RevocationStore, SessionStore, StoredSession,
};
use crate::backends::diesel::schema::{yauth_challenges, yauth_sessions};
use crate::backends::diesel::store_types::{Challenge, NewSession, Session};
use crate::state::DbPool;

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const CREATE_RATE_LIMITS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_rate_limits (
    key         TEXT PRIMARY KEY,
    count       INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
)
"#;

const CREATE_CHALLENGES_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_challenges (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

const CREATE_REVOCATIONS_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS yauth_revocations (
    key         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
)
"#;

// ---------------------------------------------------------------------------
// Diesel helpers
// ---------------------------------------------------------------------------

async fn ensure_table_diesel(
    pool: &diesel_async_crate::pooled_connection::deadpool::Pool<
        diesel_async_crate::AsyncPgConnection,
    >,
    ddl: &str,
) -> Result<(), String> {
    use diesel_async_crate::RunQueryDsl;
    let mut conn = pool.get().await.map_err(|e| format!("pool error: {e}"))?;
    diesel::sql_query(ddl)
        .execute(&mut conn)
        .await
        .map_err(|e| format!("failed to create table: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PostgresChallengeStore
// ---------------------------------------------------------------------------

pub struct PostgresChallengeStore {
    db: DbPool,
    initialized: AtomicBool,
}

impl PostgresChallengeStore {
    pub fn new(db: DbPool) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            ensure_table_diesel(&self.db, CREATE_CHALLENGES_TABLE).await?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), String> {
        use diesel::prelude::*;
        use diesel_async_crate::RunQueryDsl;
        let mut conn = self
            .db
            .get()
            .await
            .map_err(|e| format!("pool error: {e}"))?;
        diesel::delete(
            yauth_challenges::table.filter(yauth_challenges::expires_at.lt(diesel::dsl::now)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| format!("cleanup failed: {e}"))?;
        Ok(())
    }
}

impl ChallengeStore for PostgresChallengeStore {
    fn set(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;
            let _ = self.cleanup_expired().await;

            // Use raw SQL for INSERT ON CONFLICT with make_interval() —
            // diesel doesn't support make_interval natively.
            let sql = r#"
                INSERT INTO yauth_challenges (key, value, expires_at)
                VALUES ($1, $2, now() + make_interval(secs => $3))
                ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value,
                        expires_at = EXCLUDED.expires_at
            "#;

            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;
            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&key)
                .bind::<diesel::sql_types::Jsonb, _>(value)
                .bind::<diesel::sql_types::Float8, _>(ttl_secs as f64)
                .execute(&mut conn)
                .await
                .map_err(|e| format!("challenge set failed: {e}"))?;
            Ok(())
        })
    }

    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, String>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            use diesel::prelude::*;
            use diesel::result::OptionalExtension;
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            let result: Option<Challenge> = yauth_challenges::table
                .filter(yauth_challenges::key.eq(&key))
                .filter(yauth_challenges::expires_at.gt(diesel::dsl::now))
                .select(Challenge::as_select())
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(|e| format!("challenge get failed: {e}"))?;
            Ok(result.map(|r| r.value))
        })
    }

    fn delete(&self, key: &str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            use diesel::prelude::*;
            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;
            diesel::delete(yauth_challenges::table.filter(yauth_challenges::key.eq(&key)))
                .execute(&mut conn)
                .await
                .map_err(|e| format!("challenge delete failed: {e}"))?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// PostgresRateLimitStore
// ---------------------------------------------------------------------------

pub struct PostgresRateLimitStore {
    db: DbPool,
    initialized: AtomicBool,
}

impl PostgresRateLimitStore {
    pub fn new(db: DbPool) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            ensure_table_diesel(&self.db, CREATE_RATE_LIMITS_TABLE).await?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl RateLimitStore for PostgresRateLimitStore {
    fn check(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Pin<Box<dyn Future<Output = RateLimitResult> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            if let Err(e) = self.ensure_init().await {
                crate::otel::record_error("rate_limit_store_init_failed", &e);
                return RateLimitResult {
                    allowed: true,
                    remaining: limit.saturating_sub(1),
                    retry_after: 0,
                };
            }

            // Keep as raw SQL — CASE+RETURNING is too complex for the query builder
            let sql = r#"
                INSERT INTO yauth_rate_limits (key, count, window_start)
                VALUES ($1, 1, now())
                ON CONFLICT (key) DO UPDATE
                    SET count = CASE
                            WHEN yauth_rate_limits.window_start + make_interval(secs => $2)
                                 < now()
                            THEN 1
                            ELSE yauth_rate_limits.count + 1
                        END,
                        window_start = CASE
                            WHEN yauth_rate_limits.window_start + make_interval(secs => $2)
                                 < now()
                            THEN now()
                            ELSE yauth_rate_limits.window_start
                        END
                RETURNING count, window_start
            "#;

            use diesel_async_crate::RunQueryDsl;

            #[derive(diesel::QueryableByName)]
            struct RateLimitRow {
                #[diesel(sql_type = diesel::sql_types::Int4)]
                count: i32,
                #[diesel(sql_type = diesel::sql_types::Timestamptz)]
                window_start: chrono::NaiveDateTime,
            }

            let conn = self.db.get().await;
            match conn {
                Ok(mut conn) => {
                    let result: Result<RateLimitRow, _> = diesel::sql_query(sql)
                        .bind::<diesel::sql_types::Text, _>(&key)
                        .bind::<diesel::sql_types::Float8, _>(window_secs as f64)
                        .get_result(&mut conn)
                        .await;

                    match result {
                        Ok(row) => {
                            let count = row.count as u32;
                            let window_start = row.window_start.and_utc();
                            rate_limit_result(count, limit, window_start, window_secs)
                        }
                        Err(e) => {
                            crate::otel::record_error("rate_limit_check_failed", &e);
                            RateLimitResult {
                                allowed: true,
                                remaining: limit.saturating_sub(1),
                                retry_after: 0,
                            }
                        }
                    }
                }
                Err(e) => {
                    crate::otel::record_error("rate_limit_pool_error", &e);
                    RateLimitResult {
                        allowed: true,
                        remaining: limit.saturating_sub(1),
                        retry_after: 0,
                    }
                }
            }
        })
    }
}

fn rate_limit_result(
    count: u32,
    limit: u32,
    window_start: chrono::DateTime<chrono::Utc>,
    window_secs: u64,
) -> RateLimitResult {
    if count > limit {
        let window_end = window_start + chrono::Duration::seconds(window_secs as i64);
        let now = chrono::Utc::now();
        let retry_after = (window_end - now).num_seconds().max(0) as u64;
        RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after,
        }
    } else {
        RateLimitResult {
            allowed: true,
            remaining: limit - count,
            retry_after: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PostgresSessionStore
// ---------------------------------------------------------------------------

pub struct PostgresSessionStore {
    db: DbPool,
}

impl PostgresSessionStore {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

impl SessionStore for PostgresSessionStore {
    fn create(
        &self,
        user_id: Uuid,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Uuid, String>> + Send + '_>> {
        Box::pin(async move {
            use diesel_async_crate::RunQueryDsl;

            let session_id = Uuid::new_v4();
            let now = Utc::now();
            let expires_at =
                now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(7));

            let new_session = NewSession {
                id: session_id,
                user_id,
                token_hash,
                ip_address,
                user_agent,
                expires_at: expires_at.naive_utc(),
                created_at: now.naive_utc(),
            };

            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            diesel::insert_into(yauth_sessions::table)
                .values(&new_session)
                .execute(&mut conn)
                .await
                .map_err(|e| format!("session create failed: {e}"))?;

            Ok(session_id)
        })
    }

    fn validate(
        &self,
        token_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StoredSession>, String>> + Send + '_>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            use diesel::prelude::*;
            use diesel::result::OptionalExtension;
            use diesel_async_crate::RunQueryDsl;

            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            let session: Option<Session> = yauth_sessions::table
                .filter(yauth_sessions::token_hash.eq(&token_hash))
                .select(Session::as_select())
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(|e| format!("session validate failed: {e}"))?;

            match session {
                Some(s) => {
                    let now = Utc::now().naive_utc();
                    if s.expires_at < now {
                        // Expired — clean up the row
                        diesel::delete(yauth_sessions::table.filter(yauth_sessions::id.eq(s.id)))
                            .execute(&mut conn)
                            .await
                            .map_err(|e| format!("session cleanup failed: {e}"))?;
                        return Ok(None);
                    }

                    Ok(Some(StoredSession {
                        id: s.id,
                        user_id: s.user_id,
                        ip_address: s.ip_address,
                        user_agent: s.user_agent,
                        expires_at: s.expires_at,
                        created_at: s.created_at,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    fn delete(
        &self,
        token_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>> {
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            use diesel::prelude::*;
            use diesel_async_crate::RunQueryDsl;

            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            let rows = diesel::delete(
                yauth_sessions::table.filter(yauth_sessions::token_hash.eq(&token_hash)),
            )
            .execute(&mut conn)
            .await
            .map_err(|e| format!("session delete failed: {e}"))?;

            Ok(rows > 0)
        })
    }

    fn delete_all_for_user(
        &self,
        user_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>> {
        Box::pin(async move {
            use diesel::prelude::*;
            use diesel_async_crate::RunQueryDsl;

            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            let rows =
                diesel::delete(yauth_sessions::table.filter(yauth_sessions::user_id.eq(user_id)))
                    .execute(&mut conn)
                    .await
                    .map_err(|e| format!("session delete_all_for_user failed: {e}"))?;

            Ok(rows as u64)
        })
    }

    fn delete_others_for_user(
        &self,
        user_id: Uuid,
        keep_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>> {
        let keep_hash = keep_hash.to_string();
        Box::pin(async move {
            use diesel::prelude::*;
            use diesel_async_crate::RunQueryDsl;

            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            let rows = diesel::delete(
                yauth_sessions::table
                    .filter(yauth_sessions::user_id.eq(user_id))
                    .filter(yauth_sessions::token_hash.ne(&keep_hash)),
            )
            .execute(&mut conn)
            .await
            .map_err(|e| format!("session delete_others_for_user failed: {e}"))?;

            Ok(rows as u64)
        })
    }
}

// ---------------------------------------------------------------------------
// PostgresRevocationStore
// ---------------------------------------------------------------------------

pub struct PostgresRevocationStore {
    db: DbPool,
    initialized: AtomicBool,
}

impl PostgresRevocationStore {
    pub fn new(db: DbPool) -> Self {
        Self {
            db,
            initialized: AtomicBool::new(false),
        }
    }

    async fn ensure_init(&self) -> Result<(), String> {
        if !self.initialized.load(Ordering::Relaxed) {
            ensure_table_diesel(&self.db, CREATE_REVOCATIONS_TABLE).await?;
            self.initialized.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl RevocationStore for PostgresRevocationStore {
    fn revoke(
        &self,
        jti: &str,
        ttl: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let sql = r#"
                INSERT INTO yauth_revocations (key, expires_at)
                VALUES ($1, now() + make_interval(secs => $2))
                ON CONFLICT (key) DO UPDATE
                    SET expires_at = EXCLUDED.expires_at
            "#;

            use diesel_async_crate::RunQueryDsl;
            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&jti)
                .bind::<diesel::sql_types::Float8, _>(ttl.as_secs_f64())
                .execute(&mut conn)
                .await
                .map_err(|e| format!("revocation insert failed: {e}"))?;

            Ok(())
        })
    }

    fn is_revoked(
        &self,
        jti: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>> {
        let jti = jti.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let sql = r#"
                SELECT 1 AS found
                FROM yauth_revocations
                WHERE key = $1 AND expires_at > now()
            "#;

            use diesel::result::OptionalExtension;
            use diesel_async_crate::RunQueryDsl;

            #[derive(diesel::QueryableByName)]
            struct Found {
                #[diesel(sql_type = diesel::sql_types::Int4)]
                #[allow(dead_code)]
                found: i32,
            }

            let mut conn = self
                .db
                .get()
                .await
                .map_err(|e| format!("pool error: {e}"))?;

            let result: Option<Found> = diesel::sql_query(sql)
                .bind::<diesel::sql_types::Text, _>(&jti)
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(|e| format!("revocation check failed: {e}"))?;

            Ok(result.is_some())
        })
    }
}
