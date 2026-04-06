use sqlx::SqlitePool;
use uuid::Uuid;

use crate::backends::sqlx_common::{
    dt_to_str, opt_dt_to_str, opt_str_to_dt, sqlx_conflict, sqlx_err, str_to_dt, str_to_uuid,
};
use crate::domain;
use crate::repo::{RepoFuture, SessionRepository, UserRepository, sealed};

// ── Row types ──
// SQLite stores UUIDs as TEXT and datetimes as TEXT (ISO 8601).
// query_as!() macro infers these as String, so row types use String
// and into_domain() parses them.

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Option<String>,
    email: String,
    display_name: Option<String>,
    email_verified: i64,
    role: String,
    banned: i64,
    banned_reason: Option<String>,
    banned_until: Option<String>,
    created_at: String,
    updated_at: String,
}

impl UserRow {
    fn into_domain(self) -> domain::User {
        domain::User {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            email: self.email,
            display_name: self.display_name,
            email_verified: self.email_verified != 0,
            role: self.role,
            banned: self.banned != 0,
            banned_reason: self.banned_reason,
            banned_until: opt_str_to_dt(self.banned_until),
            created_at: str_to_dt(&self.created_at),
            updated_at: str_to_dt(&self.updated_at),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Option<String>,
    user_id: String,
    token_hash: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: String,
    created_at: String,
}

impl SessionRow {
    fn into_domain(self) -> domain::Session {
        domain::Session {
            id: str_to_uuid(&self.id.unwrap_or_default()),
            user_id: str_to_uuid(&self.user_id),
            token_hash: self.token_hash,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: str_to_dt(&self.expires_at),
            created_at: str_to_dt(&self.created_at),
        }
    }
}

// ── UserRepository ──

pub(crate) struct SqlxSqliteUserRepo {
    pool: SqlitePool,
}

impl SqlxSqliteUserRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteUserRepo {}

impl UserRepository for SqlxSqliteUserRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::User>> {
        Box::pin(async move {
            let id_str = id.to_string();
            let row = sqlx::query_as!(
                UserRow,
                "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                 FROM yauth_users WHERE id = ? /* sqlite */",
                id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn find_by_email(&self, email: &str) -> RepoFuture<'_, Option<domain::User>> {
        let email = email.to_string();
        Box::pin(async move {
            let row = sqlx::query_as!(
                UserRow,
                "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                 FROM yauth_users WHERE email LIKE ? /* sqlite */",
                email
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewUser) -> RepoFuture<'_, domain::User> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let created_str = dt_to_str(input.created_at);
            let updated_str = dt_to_str(input.updated_at);
            let banned_until_str = opt_dt_to_str(input.banned_until);
            let row = sqlx::query_as!(
                UserRow,
                "INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at /* sqlite */",
                id_str,
                input.email,
                input.display_name,
                input.email_verified,
                input.role,
                input.banned,
                input.banned_reason,
                banned_until_str,
                created_str,
                updated_str,
            )
            .fetch_one(&self.pool)
            .await
            .map_err(sqlx_conflict)?;
            Ok(row.into_domain())
        })
    }

    fn update(&self, id: Uuid, changes: domain::UpdateUser) -> RepoFuture<'_, domain::User> {
        // Dynamic SET clause — must stay as runtime query()
        Box::pin(async move {
            let mut sets = Vec::new();

            macro_rules! push_set {
                ($field:expr, $col:expr) => {
                    if $field.is_some() {
                        sets.push(format!("{} = ?", $col));
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
                return self
                    .find_by_id(id)
                    .await?
                    .ok_or(crate::repo::RepoError::NotFound);
            }

            let sql = format!(
                "UPDATE yauth_users SET {} WHERE id = ? \
                 RETURNING id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at",
                sets.join(", ")
            );

            let mut query = sqlx::query_as::<_, UserRow>(&sql);

            if let Some(ref email) = changes.email {
                query = query.bind(email.clone());
            }
            if let Some(ref display_name) = changes.display_name {
                query = query.bind(display_name.clone());
            }
            if let Some(email_verified) = changes.email_verified {
                query = query.bind(email_verified as i64);
            }
            if let Some(ref role) = changes.role {
                query = query.bind(role.clone());
            }
            if let Some(banned) = changes.banned {
                query = query.bind(banned as i64);
            }
            if let Some(ref banned_reason) = changes.banned_reason {
                query = query.bind(banned_reason.clone());
            }
            if let Some(ref banned_until) = changes.banned_until {
                query = query.bind(opt_dt_to_str(*banned_until));
            }
            if let Some(updated_at) = changes.updated_at {
                query = query.bind(dt_to_str(updated_at));
            }

            let row = query
                .bind(id.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(row.into_domain())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!("DELETE FROM yauth_users WHERE id = ? /* sqlite */", id_str)
                .execute(&self.pool)
                .await
                .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn any_exists(&self) -> RepoFuture<'_, bool> {
        Box::pin(async move {
            let row = sqlx::query!("SELECT id FROM yauth_users LIMIT 1 /* sqlite */")
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
                let total = sqlx::query!(
                    "SELECT COUNT(*) as count FROM yauth_users WHERE email LIKE ? /* sqlite */",
                    pattern
                )
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;

                let rows = sqlx::query_as!(
                    UserRow,
                    "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                     FROM yauth_users WHERE email LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ? /* sqlite */",
                    pattern,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;

                (total.count, rows)
            } else {
                let total = sqlx::query!("SELECT COUNT(*) as count FROM yauth_users /* sqlite */")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(sqlx_err)?;

                let rows = sqlx::query_as!(
                    UserRow,
                    "SELECT id, email, display_name, email_verified, role, banned, banned_reason, banned_until, created_at, updated_at \
                     FROM yauth_users ORDER BY created_at DESC LIMIT ? OFFSET ? /* sqlite */",
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(sqlx_err)?;

                (total.count, rows)
            };

            Ok((users.into_iter().map(|u| u.into_domain()).collect(), total))
        })
    }
}

// ── SessionRepository ──

pub(crate) struct SqlxSqliteSessionRepo {
    pool: SqlitePool,
}

impl SqlxSqliteSessionRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteSessionRepo {}

impl SessionRepository for SqlxSqliteSessionRepo {
    fn find_by_id(&self, id: Uuid) -> RepoFuture<'_, Option<domain::Session>> {
        Box::pin(async move {
            let id_str = id.to_string();
            let row = sqlx::query_as!(
                SessionRow,
                "SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at \
                 FROM yauth_sessions WHERE id = ? /* sqlite */",
                id_str
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(row.map(|r| r.into_domain()))
        })
    }

    fn create(&self, input: domain::NewSession) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.to_string();
            let expires_str = dt_to_str(input.expires_at);
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.token_hash,
                input.ip_address,
                input.user_agent,
                expires_str,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = id.to_string();
            sqlx::query!(
                "DELETE FROM yauth_sessions WHERE id = ? /* sqlite */",
                id_str
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(())
        })
    }

    fn list(&self, limit: i64, offset: i64) -> RepoFuture<'_, (Vec<domain::Session>, i64)> {
        Box::pin(async move {
            let total = sqlx::query!("SELECT COUNT(*) as count FROM yauth_sessions /* sqlite */")
                .fetch_one(&self.pool)
                .await
                .map_err(sqlx_err)?;

            let rows = sqlx::query_as!(
                SessionRow,
                "SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at \
                 FROM yauth_sessions ORDER BY created_at DESC LIMIT ? OFFSET ? /* sqlite */",
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;

            Ok((
                rows.into_iter().map(|s| s.into_domain()).collect(),
                total.count,
            ))
        })
    }
}
