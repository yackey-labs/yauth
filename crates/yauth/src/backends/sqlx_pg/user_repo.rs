use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::backends::sqlx_common::{sqlx_conflict, sqlx_err};
use crate::domain;
use crate::repo::{RepoFuture, SessionRepository, UserRepository, sealed};

// ── Row types for sqlx ──

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    display_name: Option<String>,
    email_verified: bool,
    role: String,
    banned: bool,
    banned_reason: Option<String>,
    banned_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    fn into_domain(self) -> domain::User {
        domain::User {
            id: self.id,
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified,
            role: self.role,
            banned: self.banned,
            banned_reason: self.banned_reason,
            banned_until: self.banned_until.map(|dt| dt.naive_utc()),
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl SessionRow {
    fn into_domain(self) -> domain::Session {
        domain::Session {
            id: self.id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: self.expires_at.naive_utc(),
            created_at: self.created_at.naive_utc(),
        }
    }
}

// ── UserRepository ──

pub(crate) struct SqlxPgUserRepo {
    pool: PgPool,
}

impl SqlxPgUserRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgUserRepo {}

impl UserRepository for SqlxPgUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, UserRow>(
                "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                 FROM yauth_users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email = email.to_string();
        Box::pin(async move {
            let row = sqlx::query_as::<_, UserRow>(
                "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                 FROM yauth_users WHERE email ILIKE $1",
            )
            .bind(&email)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, UserRow>(
                "INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at",
            )
            .bind(input.id)
            .bind(&input.email)
            .bind(&input.display_name)
            .bind(input.email_verified)
            .bind(&input.role)
            .bind(input.banned)
            .bind(&input.banned_reason)
            .bind(input.banned_until)
            .bind(input.created_at)
            .bind(input.updated_at)
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_conflict)?;
            Ok(row.into_domain())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            // Build dynamic SET clause
            let mut sets = Vec::new();
            let mut param_idx = 1u32;

            macro_rules! push_set {
                ($field:expr, $col:expr) => {
                    if $field.is_some() {
                        param_idx += 1;
                        sets.push(format!("{} = ${}", $col, param_idx));
                    }
                };
            }

            push_set!(changes.email, "email");
            push_set!(changes.display_name, "display_name");
            push_set!(changes.email_verified, "email_verified");
            push_set!(changes.role, "role");
            push_set!(changes.banned, "banned");
            push_set!(changes.banned_reason, "banned_reason");
            push_set!(changes.banned_until, "banned_until");
            push_set!(changes.updated_at, "updated_at");

            if sets.is_empty() {
                // Nothing to update — just fetch current
                return self
                    .find_by_id(id)
                    .await?
                    .ok_or(crate::repo::RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_users SET {} WHERE id = $1 \
                 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at",
                sets.join(", ")
            );

            // Build query dynamically with binds
            let mut query = sqlx::query_as::<_, UserRow>(&sql).bind(id);

            if let Some(ref email) = changes.email {
                query = query.bind(email.clone());
            }
            if let Some(ref display_name) = changes.display_name {
                query = query.bind(display_name.clone());
            }
            if let Some(email_verified) = changes.email_verified {
                query = query.bind(email_verified);
            }
            if let Some(ref role) = changes.role {
                query = query.bind(role.clone());
            }
            if let Some(banned) = changes.banned {
                query = query.bind(banned);
            }
            if let Some(ref banned_reason) = changes.banned_reason {
                query = query.bind(banned_reason.clone());
            }
            if let Some(ref banned_until) = changes.banned_until {
                query = query.bind(*banned_until);
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(updated_at);
            }

            let row = query.fetch_one(&self.pool).await.map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_users WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM yauth_users LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(row.is_some())
        })
    }

    fn list(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, (Vec<domain::User>, i64)> {
        let search = search.map(|s| s.to_string());
        Box::pin(async move {
            let (total, users) = if let Some(ref s) = search {
                let pattern = format!("%{}%", s.to_lowercase());
                let total: (i64,) =
                    sqlx::query_as("SELECT COUNT(*) FROM yauth_users WHERE email ILIKE $1")
                        .bind(&pattern)
                        .fetch_one(&self.pool)
                        .await
                        .map_err(sqlx_err)?;

                let rows: Vec<UserRow> = sqlx::query_as(
                    "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                     FROM yauth_users WHERE email ILIKE $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(&pattern)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;

                (total.0, rows)
            } else {
                let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM yauth_users")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(sqlx_err)?;

                let rows: Vec<UserRow> = sqlx::query_as(
                    "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                     FROM yauth_users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;

                (total.0, rows)
            };

            Ok((users.into_iter().map(|u| u.into_domain()).collect(), total))
        })
    }
}

// ── SessionRepository ──

pub(crate) struct SqlxPgSessionRepo {
    pool: PgPool,
}

impl SqlxPgSessionRepo {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxPgSessionRepo {}

impl SessionRepository for SqlxPgSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, SessionRow>(
                "SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at \
                 FROM yauth_sessions WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(input.id)
            .bind(input.user_id)
            .bind(&input.token_hash)
            .bind(&input.ip_address)
            .bind(&input.user_agent)
            .bind(input.expires_at)
            .bind(input.created_at)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            sqlx::query("DELETE FROM yauth_sessions WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)> {
        Box::pin(async move {
            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM yauth_sessions")
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;

            let rows: Vec<SessionRow> = sqlx::query_as(
                "SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at \
                 FROM yauth_sessions ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;

            Ok((rows.into_iter().map(|s| s.into_domain()).collect(), total.0))
        })
    }
}
