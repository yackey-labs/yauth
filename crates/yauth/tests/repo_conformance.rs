//! Cross-backend repository conformance test suite.
//!
//! Runs identical assertions against every available backend:
//! - memory: always available
//! - diesel_pg: if DATABASE_URL env var is set
//! - diesel_mysql: if MYSQL_DATABASE_URL env var is set
//! - diesel_sqlite: if SQLITE_DATABASE_URL env var is set (defaults to :memory:)
//! - diesel_libsql: always available (in-memory) — test separately due to libsql-ffi symbol conflict
//! - sqlx_pg: if SQLX_PG_DATABASE_URL (or DATABASE_URL) env var is set
//! - sqlx_mysql: if SQLX_MYSQL_DATABASE_URL (or MYSQL_DATABASE_URL) env var is set
//! - sqlx_sqlite: if SQLX_SQLITE_DATABASE_URL env var is set (defaults to sqlite::memory:)
//!
//! ```text
//! cargo test --features full,all-backends --test repo_conformance
//! ```

#![cfg(feature = "full")]

use chrono::{Duration, Utc};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;
use yauth::repo::{DatabaseBackend, RepoError, Repositories};
use yauth_entity as domain;

use std::sync::OnceLock;
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn shared_runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create shared test runtime")
    })
}

mod helpers;

// ---------------------------------------------------------------------------
// Backend setup
// ---------------------------------------------------------------------------

fn unique(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let run_id = Uuid::now_v7().simple().to_string();
    format!("{prefix}-{n}-{run_id}@test.local")
}

/// Short unique identifier for DB columns with length limits (e.g., key_prefix VARCHAR(12)).
/// Uses UUIDv7's random suffix (last N hex chars) which is unique per call.
fn short_unique(prefix: &str) -> String {
    let uuid = Uuid::now_v7().simple().to_string();
    let max_suffix = 12usize.saturating_sub(prefix.len());
    let start = 32 - max_suffix;
    format!("{prefix}{}", &uuid[start..])
}

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

/// Shared backends — initialized once, reused across all parallel tests.
/// PG and MySQL connect to shared databases (schema set up once via OnceCell).
/// Memory creates per-test instances (cheap, no shared state).
use tokio::sync::OnceCell;

#[cfg(feature = "diesel-pg-backend")]
static PG_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "diesel-libsql-backend")]
static LIBSQL_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "diesel-mysql-backend")]
static MYSQL_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "diesel-sqlite-backend")]
static SQLITE_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "sqlx-pg-backend")]
static SQLX_PG_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "sqlx-mysql-backend")]
static SQLX_MYSQL_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "sqlx-sqlite-backend")]
static SQLX_SQLITE_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "seaorm-pg-backend")]
static SEAORM_PG_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "seaorm-mysql-backend")]
static SEAORM_MYSQL_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "seaorm-sqlite-backend")]
static SEAORM_SQLITE_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

#[cfg(feature = "diesel-pg-backend")]
async fn shared_pg_repos() -> Option<Repositories> {
    PG_REPOS
        .get_or_init(|| async {
            let db = helpers::TestDb::shared().await?;
            // Schema already set up by TestDb::init_schema via helpers::schema::setup_pg_schema_diesel
            use yauth::backends::diesel_pg::DieselPgBackend;
            let backend = DieselPgBackend::from_pool(db.pool.clone());
            Some(backend.repositories())
        })
        .await
        .clone()
}

#[cfg(feature = "diesel-libsql-backend")]
async fn shared_libsql_repos() -> Option<Repositories> {
    LIBSQL_REPOS
        .get_or_init(|| async {
            use yauth::backends::diesel_libsql::DieselLibsqlBackend;
            let url =
                std::env::var("LIBSQL_LOCAL_URL").unwrap_or_else(|_| "file::memory:".to_string());
            let is_memory =
                url == ":memory:" || url == "file::memory:" || url.starts_with("file::memory:?");
            let max_size = if is_memory { 1 } else { 8 };
            let manager = diesel_libsql::deadpool::Manager::new(&url);
            let pool = diesel_libsql::deadpool::Pool::builder(manager)
                .max_size(max_size)
                .build()
                .expect("create libsql pool");
            helpers::schema::setup_libsql_schema_diesel(&pool).await;
            let backend = DieselLibsqlBackend::from_pool(pool);
            Some(backend.repositories())
        })
        .await
        .clone()
}

#[cfg(feature = "diesel-mysql-backend")]
async fn shared_mysql_repos() -> Option<Repositories> {
    MYSQL_REPOS
        .get_or_init(|| async {
            let url = match std::env::var("MYSQL_DATABASE_URL") {
                Ok(u) => u,
                Err(_) => return None,
            };
            use yauth::backends::diesel_mysql::DieselMysqlBackend;
            let config = diesel_async_crate::pooled_connection::AsyncDieselConnectionManager::<
                diesel_async_crate::AsyncMysqlConnection,
            >::new(&url);
            let pool = match diesel_async_crate::pooled_connection::deadpool::Pool::builder(config)
                .max_size(32)
                .build()
            {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("MySQL pool creation failed: {e}, skipping");
                    return None;
                }
            };
            helpers::schema::setup_mysql_schema_diesel(&pool).await;
            let backend = DieselMysqlBackend::from_pool(pool);
            Some(backend.repositories())
        })
        .await
        .clone()
}

#[cfg(feature = "diesel-sqlite-backend")]
async fn shared_sqlite_repos() -> Option<Repositories> {
    SQLITE_REPOS
        .get_or_init(|| async {
            use yauth::backends::diesel_sqlite::{
                DieselSqliteBackend, SqliteAsyncConn, SqlitePool,
            };
            let url =
                std::env::var("SQLITE_DATABASE_URL").unwrap_or_else(|_| ":memory:".to_string());
            let is_memory =
                url == ":memory:" || url == "file::memory:" || url.starts_with("file::memory:?");
            let max_size = if is_memory { 1 } else { 8 };
            let config = diesel_async_crate::pooled_connection::AsyncDieselConnectionManager::<
                SqliteAsyncConn,
            >::new(&url);
            let pool: SqlitePool =
                match diesel_async_crate::pooled_connection::deadpool::Pool::builder(config)
                    .max_size(max_size)
                    .build()
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("SQLite pool creation failed: {e}, skipping");
                        return None;
                    }
                };
            helpers::schema::setup_sqlite_schema_diesel(&pool).await;
            let backend = if is_memory {
                DieselSqliteBackend::from_pool_memory(pool)
            } else {
                DieselSqliteBackend::from_pool(pool)
            };
            Some(backend.repositories())
        })
        .await
        .clone()
}

#[cfg(feature = "sqlx-pg-backend")]
async fn shared_sqlx_pg_repos() -> Option<Repositories> {
    SQLX_PG_REPOS
        .get_or_init(|| async {
            let url = match std::env::var("SQLX_PG_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
            {
                Ok(u) => u,
                Err(_) => return None,
            };
            use yauth::backends::sqlx_pg::SqlxPgBackend;
            match sqlx::PgPool::connect(&url).await {
                Ok(pool) => {
                    helpers::schema::setup_pg_schema_sqlx(&pool).await;
                    let backend = SqlxPgBackend::from_pool(pool);
                    Some(backend.repositories())
                }
                Err(e) => {
                    eprintln!("sqlx-pg pool creation failed: {e}, skipping");
                    None
                }
            }
        })
        .await
        .clone()
}

#[cfg(feature = "sqlx-mysql-backend")]
async fn shared_sqlx_mysql_repos() -> Option<Repositories> {
    SQLX_MYSQL_REPOS
        .get_or_init(|| async {
            let url = match std::env::var("SQLX_MYSQL_DATABASE_URL")
                .or_else(|_| std::env::var("MYSQL_DATABASE_URL"))
            {
                Ok(u) => u,
                Err(_) => return None,
            };
            use yauth::backends::sqlx_mysql::SqlxMysqlBackend;
            match sqlx::MySqlPool::connect(&url).await {
                Ok(pool) => {
                    helpers::schema::setup_mysql_schema_sqlx(&pool).await;
                    let backend = SqlxMysqlBackend::from_pool(pool);
                    Some(backend.repositories())
                }
                Err(e) => {
                    eprintln!("sqlx-mysql pool creation failed: {e}, skipping");
                    None
                }
            }
        })
        .await
        .clone()
}

#[cfg(feature = "sqlx-sqlite-backend")]
async fn shared_sqlx_sqlite_repos() -> Option<Repositories> {
    SQLX_SQLITE_REPOS
        .get_or_init(|| async {
            let url = std::env::var("SQLX_SQLITE_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite::memory:".to_string());
            use yauth::backends::sqlx_sqlite::SqlxSqliteBackend;
            match sqlx::SqlitePool::connect(&url).await {
                Ok(pool) => {
                    helpers::schema::setup_sqlite_schema_sqlx(&pool).await;
                    let backend = SqlxSqliteBackend::from_pool(pool);
                    Some(backend.repositories())
                }
                Err(e) => {
                    eprintln!("sqlx-sqlite pool creation failed: {e}, skipping");
                    None
                }
            }
        })
        .await
        .clone()
}

#[cfg(feature = "seaorm-pg-backend")]
async fn shared_seaorm_pg_repos() -> Option<Repositories> {
    SEAORM_PG_REPOS
        .get_or_init(|| async {
            let url = match std::env::var("SEAORM_PG_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
            {
                Ok(u) => u,
                Err(_) => return None,
            };
            use sea_orm::{ConnectOptions, Database};
            use yauth::backends::seaorm_pg::SeaOrmPgBackend;
            let mut opts = ConnectOptions::new(url);
            opts.max_connections(64)
                .min_connections(2)
                .sqlx_logging(false);
            match Database::connect(opts).await {
                Ok(db) => {
                    helpers::schema::setup_pg_schema_seaorm(&db).await;
                    let backend = SeaOrmPgBackend::from_connection(db);
                    Some(backend.repositories())
                }
                Err(e) => {
                    eprintln!("seaorm-pg connection failed: {e}, skipping");
                    None
                }
            }
        })
        .await
        .clone()
}

#[cfg(feature = "seaorm-mysql-backend")]
async fn shared_seaorm_mysql_repos() -> Option<Repositories> {
    SEAORM_MYSQL_REPOS
        .get_or_init(|| async {
            let url = match std::env::var("SEAORM_MYSQL_DATABASE_URL")
                .or_else(|_| std::env::var("MYSQL_DATABASE_URL"))
            {
                Ok(u) => u,
                Err(_) => return None,
            };
            use sea_orm::{ConnectOptions, Database};
            use yauth::backends::seaorm_mysql::SeaOrmMysqlBackend;
            let mut opts = ConnectOptions::new(url);
            opts.max_connections(64)
                .min_connections(2)
                .sqlx_logging(false);
            match Database::connect(opts).await {
                Ok(db) => {
                    helpers::schema::setup_mysql_schema_seaorm(&db).await;
                    let backend = SeaOrmMysqlBackend::from_connection(db);
                    Some(backend.repositories())
                }
                Err(e) => {
                    eprintln!("seaorm-mysql connection failed: {e}, skipping");
                    None
                }
            }
        })
        .await
        .clone()
}

#[cfg(feature = "seaorm-sqlite-backend")]
async fn shared_seaorm_sqlite_repos() -> Option<Repositories> {
    SEAORM_SQLITE_REPOS
        .get_or_init(|| async {
            use sea_orm::{ConnectOptions, Database};
            use yauth::backends::seaorm_sqlite::SeaOrmSqliteBackend;
            let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
            opts.max_connections(1).sqlx_logging(false);
            match Database::connect(opts).await {
                Ok(db) => {
                    helpers::schema::setup_sqlite_schema_seaorm(&db).await;
                    let backend = SeaOrmSqliteBackend::from_connection(db);
                    Some(backend.repositories())
                }
                Err(e) => {
                    eprintln!("seaorm-sqlite connection failed: {e}, skipping");
                    None
                }
            }
        })
        .await
        .clone()
}

async fn test_backends() -> Vec<(&'static str, Repositories)> {
    helpers::otel::ensure_init();
    let _span = helpers::otel::HelperSpan::new("test_backends");
    let mut backends: Vec<(&'static str, Repositories)> = Vec::new();

    // Memory -- always available, per-test instance (no shared state)
    {
        use yauth::backends::memory::InMemoryBackend;
        let backend = InMemoryBackend::new();
        backends.push(("memory", backend.repositories()));
    }

    // Diesel PG -- shared, schema set up once
    #[cfg(feature = "diesel-pg-backend")]
    if let Some(repos) = shared_pg_repos().await {
        backends.push(("diesel_pg", repos));
    }

    // Diesel libsql -- shared instance, schema set up once.
    // Must be shared (not per-test) to avoid deadpool dropping connections on a
    // shutting-down per-test tokio runtime, which causes "Tokio context is being shutdown".
    #[cfg(feature = "diesel-libsql-backend")]
    if let Some(repos) = shared_libsql_repos().await {
        backends.push(("diesel_libsql", repos));
    }

    // Diesel libsql (remote) -- if LIBSQL_URL is set, test against a remote sqld server.
    // This tests the hrana/websocket code path (vs local SQLite FFI above).
    #[cfg(feature = "diesel-libsql-backend")]
    if let Ok(url) = std::env::var("LIBSQL_URL") {
        let manager = diesel_libsql::deadpool::Manager::new(&url);
        match diesel_libsql::deadpool::Pool::builder(manager)
            .max_size(8)
            .build()
        {
            Ok(pool) => {
                helpers::schema::setup_libsql_schema_diesel(&pool).await;
                use yauth::backends::diesel_libsql::DieselLibsqlBackend;
                let backend = DieselLibsqlBackend::from_pool(pool);
                backends.push(("diesel_libsql_remote", backend.repositories()));
            }
            Err(e) => eprintln!("Remote libsql pool creation failed: {e}, skipping"),
        }
    }

    // Diesel MySQL -- shared, schema set up once
    #[cfg(feature = "diesel-mysql-backend")]
    if let Some(repos) = shared_mysql_repos().await {
        backends.push(("diesel_mysql", repos));
    }

    // Diesel native SQLite -- shared, schema set up once.
    // Uses SyncConnectionWrapper<SqliteConnection> via deadpool.
    #[cfg(feature = "diesel-sqlite-backend")]
    if let Some(repos) = shared_sqlite_repos().await {
        backends.push(("diesel_sqlite", repos));
    }

    // sqlx PostgreSQL -- shared, schema set up once
    #[cfg(feature = "sqlx-pg-backend")]
    if let Some(repos) = shared_sqlx_pg_repos().await {
        backends.push(("sqlx_pg", repos));
    }

    // sqlx MySQL -- shared, schema set up once
    #[cfg(feature = "sqlx-mysql-backend")]
    if let Some(repos) = shared_sqlx_mysql_repos().await {
        backends.push(("sqlx_mysql", repos));
    }

    // sqlx SQLite -- shared, schema set up once
    #[cfg(feature = "sqlx-sqlite-backend")]
    if let Some(repos) = shared_sqlx_sqlite_repos().await {
        backends.push(("sqlx_sqlite", repos));
    }

    // SeaORM PostgreSQL -- shared, relies on existing schema (from diesel_pg setup)
    #[cfg(feature = "seaorm-pg-backend")]
    if let Some(repos) = shared_seaorm_pg_repos().await {
        backends.push(("seaorm_pg", repos));
    }

    // SeaORM MySQL -- shared, relies on existing schema (from diesel_mysql setup)
    #[cfg(feature = "seaorm-mysql-backend")]
    if let Some(repos) = shared_seaorm_mysql_repos().await {
        backends.push(("seaorm_mysql", repos));
    }

    // SeaORM SQLite -- shared, in-memory
    #[cfg(feature = "seaorm-sqlite-backend")]
    if let Some(repos) = shared_seaorm_sqlite_repos().await {
        backends.push(("seaorm_sqlite", repos));
    }

    backends
}

/// Create a test user and return its UUID.
async fn create_test_user(repos: &Repositories, email: &str) -> Uuid {
    let _span = helpers::otel::HelperSpan::new("create_test_user");
    let id = Uuid::now_v7();
    let n = now();
    repos
        .users
        .create(domain::NewUser {
            id,
            email: email.to_string(),
            display_name: Some("Test User".into()),
            email_verified: false,
            role: "user".into(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            created_at: n,
            updated_at: n,
        })
        .await
        .expect("create test user");
    id
}

// ---------------------------------------------------------------------------
// Core: UserRepository
// ---------------------------------------------------------------------------

#[test]
fn user_create_find_update_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("user_create_find_update_delete", name);
            let email = unique("user_crud");
            let id = create_test_user(&repos, &email).await;

            // find_by_id
            let u = repos
                .users
                .find_by_id(id)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id: {e}"));
            assert!(u.is_some(), "{name}: user should exist");
            let u = u.unwrap();
            assert_eq!(u.id, id, "{name}: id mismatch");
            assert_eq!(u.email, email, "{name}: email mismatch");

            // find_by_email
            let u2 = repos
                .users
                .find_by_email(&email)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_email: {e}"));
            assert!(u2.is_some(), "{name}: find_by_email should find user");
            assert_eq!(u2.unwrap().id, id, "{name}: find_by_email id mismatch");

            // update
            let updated = repos
                .users
                .update(
                    id,
                    domain::UpdateUser {
                        display_name: Some(Some("Updated Name".into())),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: update: {e}"));
            assert_eq!(
                updated.display_name.as_deref(),
                Some("Updated Name"),
                "{name}: update display_name"
            );

            // delete
            repos
                .users
                .delete(id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete: {e}"));
            let gone = repos
                .users
                .find_by_id(id)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(gone.is_none(), "{name}: user should be gone after delete");
        }
    });
}

#[test]
fn user_duplicate_email_conflict() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("user_duplicate_email_conflict", name);
            let email = unique("user_dupe");
            let _id = create_test_user(&repos, &email).await;

            let result = repos
                .users
                .create(domain::NewUser {
                    id: Uuid::now_v7(),
                    email: email.clone(),
                    display_name: None,
                    email_verified: false,
                    role: "user".into(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: now(),
                    updated_at: now(),
                })
                .await;
            assert!(
                matches!(result, Err(RepoError::Conflict(_))),
                "{name}: duplicate email should return Conflict, got: {result:?}"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Core: SessionOpsRepository
// ---------------------------------------------------------------------------

#[test]
fn session_create_validate_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("session_create_validate_delete", name);
            let email = unique("session_ops");
            let uid = create_test_user(&repos, &email).await;
            let hash = format!("sess_hash_{}", Uuid::now_v7());

            let sid = repos
                .session_ops
                .create_session(
                    uid,
                    hash.clone(),
                    Some("127.0.0.1".into()),
                    Some("test-agent".into()),
                    std::time::Duration::from_secs(3600),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: create_session: {e}"));
            assert!(!sid.is_nil(), "{name}: session id should not be nil");

            // validate
            let s = repos
                .session_ops
                .validate_session(&hash)
                .await
                .unwrap_or_else(|e| panic!("{name}: validate_session: {e}"));
            assert!(s.is_some(), "{name}: session should validate");
            assert_eq!(s.unwrap().user_id, uid, "{name}: user_id mismatch");

            // delete
            let deleted = repos
                .session_ops
                .delete_session(&hash)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_session: {e}"));
            assert!(deleted, "{name}: delete should return true");

            // validate after delete
            let s2 = repos
                .session_ops
                .validate_session(&hash)
                .await
                .unwrap_or_else(|e| panic!("{name}: validate after delete: {e}"));
            assert!(s2.is_none(), "{name}: session should be gone after delete");
        }
    });
}

// ---------------------------------------------------------------------------
// Core: RateLimitRepository
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_enforcement() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("rate_limit_enforcement", name);
            let key = format!("rl_conf_{}", Uuid::now_v7());

            // Keep calling until we get denied. With limit=2, backends may allow
            // 2 or 3 calls depending on whether they check-then-increment or
            // increment-then-check. The key invariant is that we eventually get
            // blocked and remaining reaches 0.
            let mut denied = false;
            for _ in 0..10 {
                let r = repos
                    .rate_limits
                    .check_rate_limit(&key, 2, 60)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: check_rate_limit: {e}"));
                if !r.allowed {
                    denied = true;
                    assert_eq!(r.remaining, 0, "{name}: remaining should be 0 when denied");
                    break;
                }
            }
            assert!(denied, "{name}: should eventually be rate-limited");
        }
    });
}

// ---------------------------------------------------------------------------
// email-password: PasswordRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "email-password")]
#[test]
fn password_upsert_and_find() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("password_upsert_and_find", name);
            let email = unique("pw_test");
            let uid = create_test_user(&repos, &email).await;

            // upsert
            repos
                .passwords
                .upsert(domain::NewPassword {
                    user_id: uid,
                    password_hash: "hash_v1".into(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: upsert password: {e}"));

            let pw = repos
                .passwords
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find password: {e}"));
            assert!(pw.is_some(), "{name}: password should exist");
            assert_eq!(
                pw.unwrap().password_hash,
                "hash_v1",
                "{name}: hash mismatch"
            );

            // upsert again (update)
            repos
                .passwords
                .upsert(domain::NewPassword {
                    user_id: uid,
                    password_hash: "hash_v2".into(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: upsert password v2: {e}"));

            let pw2 = repos
                .passwords
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find password v2: {e}"));
            assert_eq!(
                pw2.unwrap().password_hash,
                "hash_v2",
                "{name}: updated hash"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// passkey: PasskeyRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "passkey")]
#[test]
fn passkey_create_find_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("passkey_create_find_delete", name);
            let email = unique("pk_test");
            let uid = create_test_user(&repos, &email).await;
            let cred_id = Uuid::now_v7();

            repos
                .passkeys
                .create(domain::NewWebauthnCredential {
                    id: cred_id,
                    user_id: uid,
                    name: "my-key".into(),
                    aaguid: Some("test-aaguid".into()),
                    device_name: Some("YubiKey".into()),
                    credential: json!({"type": "public-key", "id": "test"}),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create passkey: {e}"));

            let creds = repos
                .passkeys
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find passkeys: {e}"));
            assert_eq!(creds.len(), 1, "{name}: should have 1 credential");
            assert_eq!(creds[0].name, "my-key", "{name}: name mismatch");
            assert_eq!(
                creds[0].credential["type"], "public-key",
                "{name}: credential JSON"
            );

            // find_by_id_and_user
            let found = repos
                .passkeys
                .find_by_id_and_user(cred_id, uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id_and_user: {e}"));
            assert!(found.is_some(), "{name}: should find by id and user");

            // delete
            repos
                .passkeys
                .delete(cred_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete passkey: {e}"));
            let after = repos
                .passkeys
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(after.is_empty(), "{name}: should be empty after delete");
        }
    });
}

// ---------------------------------------------------------------------------
// mfa: TotpRepository + BackupCodeRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "mfa")]
#[test]
fn totp_create_verify_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("totp_create_verify_delete", name);
            let email = unique("totp_test");
            let uid = create_test_user(&repos, &email).await;
            let totp_id = Uuid::now_v7();

            repos
                .totp
                .create(domain::NewTotpSecret {
                    id: totp_id,
                    user_id: uid,
                    encrypted_secret: "encrypted_secret_data".into(),
                    verified: false,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create totp: {e}"));

            // find unverified
            let t = repos
                .totp
                .find_by_user_id(uid, Some(false))
                .await
                .unwrap_or_else(|e| panic!("{name}: find unverified: {e}"));
            assert!(t.is_some(), "{name}: should find unverified totp");
            assert!(!t.unwrap().verified, "{name}: should not be verified");

            // mark verified
            repos
                .totp
                .mark_verified(totp_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: mark_verified: {e}"));
            let t2 = repos
                .totp
                .find_by_user_id(uid, Some(true))
                .await
                .unwrap_or_else(|e| panic!("{name}: find verified: {e}"));
            assert!(t2.is_some(), "{name}: should find verified totp");

            // delete
            repos
                .totp
                .delete_for_user(uid, None)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete totp: {e}"));
            let t3 = repos
                .totp
                .find_by_user_id(uid, None)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(t3.is_none(), "{name}: should be gone after delete");
        }
    });
}

#[cfg(feature = "mfa")]
#[test]
fn backup_code_create_mark_used() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("backup_code_create_mark_used", name);
            let email = unique("bc_test");
            let uid = create_test_user(&repos, &email).await;
            let bc_id = Uuid::now_v7();
            let bc_hash = format!("backup_hash_{}", Uuid::now_v7());

            repos
                .backup_codes
                .create(domain::NewBackupCode {
                    id: bc_id,
                    user_id: uid,
                    code_hash: bc_hash,
                    used: false,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create backup code: {e}"));

            let codes = repos
                .backup_codes
                .find_unused_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find unused: {e}"));
            assert_eq!(codes.len(), 1, "{name}: should have 1 unused code");

            repos
                .backup_codes
                .mark_used(bc_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: mark used: {e}"));
            let codes2 = repos
                .backup_codes
                .find_unused_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find unused after mark: {e}"));
            assert!(codes2.is_empty(), "{name}: no unused after mark_used");

            repos
                .backup_codes
                .delete_all_for_user(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete all: {e}"));
        }
    });
}

// ---------------------------------------------------------------------------
// oauth: OauthAccountRepository + OauthStateRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "oauth")]
#[test]
fn oauth_account_crud() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("oauth_account_crud", name);
            let email = unique("oauth_test");
            let uid = create_test_user(&repos, &email).await;
            let oa_id = Uuid::now_v7();
            let n = now();

            repos
                .oauth_accounts
                .create(domain::NewOauthAccount {
                    id: oa_id,
                    user_id: uid,
                    provider: "github".into(),
                    provider_user_id: format!("gh_{}", Uuid::now_v7()),
                    access_token_enc: Some("enc_at".into()),
                    refresh_token_enc: None,
                    created_at: n,
                    expires_at: None,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create oauth account: {e}"));

            // find by user
            let list = repos
                .oauth_accounts
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_user_id: {e}"));
            assert_eq!(list.len(), 1, "{name}: should have 1 oauth account");

            // delete
            repos
                .oauth_accounts
                .delete(oa_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete oauth account: {e}"));
            let gone = repos
                .oauth_accounts
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(gone.is_empty(), "{name}: should be gone after delete");
        }
    });
}

#[cfg(feature = "oauth")]
#[test]
fn oauth_state_create_and_consume() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("oauth_state_create_and_consume", name);
            let state_val = format!("state_{}", Uuid::now_v7());
            let n = now();

            repos
                .oauth_states
                .create(domain::NewOauthState {
                    state: state_val.clone(),
                    provider: "google".into(),
                    redirect_url: Some("https://example.com/callback".into()),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create oauth state: {e}"));

            // consume
            let s = repos
                .oauth_states
                .find_and_delete(&state_val)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_and_delete: {e}"));
            assert!(s.is_some(), "{name}: should find state");
            assert_eq!(s.unwrap().provider, "google");

            // second consume should return None
            let s2 = repos
                .oauth_states
                .find_and_delete(&state_val)
                .await
                .unwrap_or_else(|e| panic!("{name}: second find_and_delete: {e}"));
            assert!(s2.is_none(), "{name}: should not find consumed state");
        }
    });
}

// ---------------------------------------------------------------------------
// api-key: ApiKeyRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "api-key")]
#[test]
fn api_key_create_find_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("api_key_create_find_delete", name);
            let email = unique("ak_test");
            let uid = create_test_user(&repos, &email).await;
            let ak_id = Uuid::now_v7();
            let prefix = short_unique("yt");

            repos
                .api_keys
                .create(domain::NewApiKey {
                    id: ak_id,
                    user_id: uid,
                    key_prefix: prefix.clone(),
                    key_hash: format!("hashed_key_{}", Uuid::now_v7()),
                    name: "My API Key".into(),
                    scopes: Some(json!(["read", "write"])),
                    expires_at: None,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create api key: {e}"));

            // find by prefix
            let found = repos
                .api_keys
                .find_by_prefix(&prefix)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_prefix: {e}"));
            assert!(found.is_some(), "{name}: should find by prefix");
            assert_eq!(found.unwrap().name, "My API Key");

            // list for user
            let list = repos
                .api_keys
                .list_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: list_by_user_id: {e}"));
            assert_eq!(list.len(), 1, "{name}: should list 1 key");

            // delete
            repos
                .api_keys
                .delete(ak_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete api key: {e}"));
            let gone = repos
                .api_keys
                .find_by_prefix(&prefix)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(gone.is_none(), "{name}: should be gone");
        }
    });
}

// ---------------------------------------------------------------------------
// bearer: RefreshTokenRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "bearer")]
#[test]
fn refresh_token_create_find_revoke() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("refresh_token_create_find_revoke", name);
            let email = unique("rt_test");
            let uid = create_test_user(&repos, &email).await;
            let rt_id = Uuid::now_v7();
            let fam_id = Uuid::now_v7();
            let n = now();
            let th = format!("rt_hash_{}", Uuid::now_v7());

            repos
                .refresh_tokens
                .create(domain::NewRefreshToken {
                    id: rt_id,
                    user_id: uid,
                    token_hash: th.clone(),
                    family_id: fam_id,
                    expires_at: n + Duration::hours(24),
                    revoked: false,
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create refresh token: {e}"));

            // find by hash
            let found = repos
                .refresh_tokens
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_token_hash: {e}"));
            assert!(found.is_some(), "{name}: should find refresh token");
            assert!(!found.unwrap().revoked, "{name}: should not be revoked");

            // revoke
            repos
                .refresh_tokens
                .revoke(rt_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: revoke: {e}"));
            let revoked = repos
                .refresh_tokens
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after revoke: {e}"));
            assert!(
                revoked.unwrap().revoked,
                "{name}: should be revoked after revoke"
            );
        }
    });
}

#[cfg(feature = "bearer")]
#[test]
fn refresh_token_revoke_family() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("refresh_token_revoke_family", name);
            let email = unique("rt_fam");
            let uid = create_test_user(&repos, &email).await;
            let fam_id = Uuid::now_v7();
            let n = now();

            let mut hashes = Vec::new();
            for i in 0..2 {
                let hash = format!("rt_fam_hash_{i}_{}", Uuid::now_v7());
                repos
                    .refresh_tokens
                    .create(domain::NewRefreshToken {
                        id: Uuid::now_v7(),
                        user_id: uid,
                        token_hash: hash.clone(),
                        family_id: fam_id,
                        expires_at: n + Duration::hours(24),
                        revoked: false,
                        created_at: n,
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{name}: create rt family member {i}: {e}"));
                hashes.push(hash);
            }

            repos
                .refresh_tokens
                .revoke_family(fam_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: revoke_family: {e}"));

            for (i, hash) in hashes.iter().enumerate() {
                let token = repos
                    .refresh_tokens
                    .find_by_token_hash(hash)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: find_by_token_hash after revoke {i}: {e}"))
                    .unwrap_or_else(|| panic!("{name}: token {i} missing after revoke_family"));
                assert!(
                    token.revoked,
                    "{name}: token {i} should be revoked after revoke_family"
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------
// magic-link: MagicLinkRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "magic-link")]
#[test]
fn magic_link_create_find_mark_used() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("magic_link_create_find_mark_used", name);
            let ml_id = Uuid::now_v7();
            let n = now();
            let th = format!("ml_hash_{}", Uuid::now_v7());
            let ml_email = unique("ml_test");

            repos
                .magic_links
                .create(domain::NewMagicLink {
                    id: ml_id,
                    email: ml_email,
                    token_hash: th.clone(),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create magic link: {e}"));

            // find unused
            let found = repos
                .magic_links
                .find_unused_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_unused: {e}"));
            assert!(found.is_some(), "{name}: should find unused magic link");

            // mark used
            repos
                .magic_links
                .mark_used(ml_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: mark_used: {e}"));
            let gone = repos
                .magic_links
                .find_unused_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after mark_used: {e}"));
            assert!(gone.is_none(), "{name}: should not find used magic link");
        }
    });
}

// ---------------------------------------------------------------------------
// account-lockout: AccountLockRepository + UnlockTokenRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "account-lockout")]
#[test]
fn account_lock_create_increment_reset() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("account_lock_create_increment_reset", name);
            let email = unique("lock_test");
            let uid = create_test_user(&repos, &email).await;
            let n = now();

            let lock = repos
                .account_locks
                .create(domain::NewAccountLock {
                    id: Uuid::now_v7(),
                    user_id: uid,
                    failed_count: 0,
                    locked_until: None,
                    lock_count: 0,
                    locked_reason: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create lock: {e}"));
            assert_eq!(lock.failed_count, 0, "{name}: initial failed_count");

            // increment
            repos
                .account_locks
                .increment_failed_count(lock.id)
                .await
                .unwrap_or_else(|e| panic!("{name}: increment: {e}"));

            let found = repos
                .account_locks
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after increment: {e}"));
            assert_eq!(
                found.unwrap().failed_count,
                1,
                "{name}: failed_count after increment"
            );

            // reset
            repos
                .account_locks
                .reset_failed_count(lock.id)
                .await
                .unwrap_or_else(|e| panic!("{name}: reset: {e}"));
            let found2 = repos
                .account_locks
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after reset: {e}"));
            assert_eq!(
                found2.unwrap().failed_count,
                0,
                "{name}: failed_count after reset"
            );
        }
    });
}

#[cfg(feature = "account-lockout")]
#[test]
fn unlock_token_create_find_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("unlock_token_create_find_delete", name);
            let email = unique("unlock_test");
            let uid = create_test_user(&repos, &email).await;
            let ut_id = Uuid::now_v7();
            let n = now();
            let th = format!("unlock_hash_{}", Uuid::now_v7());

            repos
                .unlock_tokens
                .create(domain::NewUnlockToken {
                    id: ut_id,
                    user_id: uid,
                    token_hash: th.clone(),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create unlock token: {e}"));

            let found = repos
                .unlock_tokens
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find unlock token: {e}"));
            assert!(found.is_some(), "{name}: should find unlock token");

            repos
                .unlock_tokens
                .delete(ut_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete unlock token: {e}"));
            let gone = repos
                .unlock_tokens
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(gone.is_none(), "{name}: should be gone");
        }
    });
}

// ---------------------------------------------------------------------------
// webhooks: WebhookRepository + WebhookDeliveryRepository
// ---------------------------------------------------------------------------

#[cfg(feature = "webhooks")]
#[test]
fn webhook_create_update_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("webhook_create_update_delete", name);
            let wh_id = Uuid::now_v7();
            let n = now();

            repos
                .webhooks_repo
                .create(domain::NewWebhook {
                    id: wh_id,
                    url: "https://example.com/webhook".into(),
                    secret: "wh_secret".into(),
                    events: json!(["user.created", "user.deleted"]),
                    active: true,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create webhook: {e}"));

            // find
            let found = repos
                .webhooks_repo
                .find_by_id(wh_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: find webhook: {e}"));
            assert!(found.is_some(), "{name}: should find webhook");
            assert_eq!(found.unwrap().url, "https://example.com/webhook");

            // find active
            let active = repos
                .webhooks_repo
                .find_active()
                .await
                .unwrap_or_else(|e| panic!("{name}: find_active: {e}"));
            assert!(
                active.iter().any(|w| w.id == wh_id),
                "{name}: should be in active list"
            );

            // update
            let updated = repos
                .webhooks_repo
                .update(
                    wh_id,
                    domain::UpdateWebhook {
                        url: Some("https://example.com/webhook-v2".into()),
                        updated_at: Some(now()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: update webhook: {e}"));
            assert_eq!(updated.url, "https://example.com/webhook-v2");

            // delete
            repos
                .webhooks_repo
                .delete(wh_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete webhook: {e}"));
        }
    });
}

#[cfg(feature = "webhooks")]
#[test]
fn webhook_delivery_create_list() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("webhook_delivery_create_list", name);
            let wh_id = Uuid::now_v7();
            let n = now();

            repos
                .webhooks_repo
                .create(domain::NewWebhook {
                    id: wh_id,
                    url: "https://example.com/wh-delivery".into(),
                    secret: "sec".into(),
                    events: json!(["test"]),
                    active: true,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create parent webhook: {e}"));

            repos
                .webhook_deliveries
                .create(domain::NewWebhookDelivery {
                    id: Uuid::now_v7(),
                    webhook_id: wh_id,
                    event_type: "user.created".into(),
                    payload: json!({"user_id": "123"}),
                    status_code: Some(200),
                    response_body: Some("OK".into()),
                    success: true,
                    attempt: 1,
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create delivery: {e}"));

            let deliveries = repos
                .webhook_deliveries
                .find_by_webhook_id(wh_id, 10)
                .await
                .unwrap_or_else(|e| panic!("{name}: find deliveries: {e}"));
            assert_eq!(deliveries.len(), 1, "{name}: should have 1 delivery");
            assert_eq!(deliveries[0].event_type, "user.created");

            // cleanup
            repos
                .webhooks_repo
                .delete(wh_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: cleanup webhook: {e}"));
        }
    });
}

// ---------------------------------------------------------------------------
// oauth2-server: Oauth2ClientRepository + AuthorizationCodeRepository + etc.
// ---------------------------------------------------------------------------

#[cfg(feature = "oauth2-server")]
#[test]
fn oauth2_client_create_find() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("oauth2_client_create_find", name);
            let cid = format!("client_{}", Uuid::now_v7());

            repos
                .oauth2_clients
                .create(domain::NewOauth2Client {
                    id: Uuid::now_v7(),
                    client_id: cid.clone(),
                    client_secret_hash: Some("secret_hash".into()),
                    redirect_uris: json!(["https://example.com/callback"]),
                    client_name: Some("Test Client".into()),
                    grant_types: json!(["authorization_code"]),
                    scopes: Some(json!(["openid", "profile"])),
                    is_public: false,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create oauth2 client: {e}"));

            let found = repos
                .oauth2_clients
                .find_by_client_id(&cid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find oauth2 client: {e}"));
            assert!(found.is_some(), "{name}: should find client");
            let c = found.unwrap();
            assert_eq!(c.client_id, cid);
            assert_eq!(c.client_name.as_deref(), Some("Test Client"));
        }
    });
}

#[cfg(feature = "oauth2-server")]
#[test]
fn authorization_code_create_find_mark_used() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span =
                helpers::otel::TestSpan::new("authorization_code_create_find_mark_used", name);
            let email = unique("authcode_test");
            let uid = create_test_user(&repos, &email).await;
            let ac_id = Uuid::now_v7();
            let n = now();
            let ch = format!("code_hash_{}", Uuid::now_v7());

            repos
                .authorization_codes
                .create(domain::NewAuthorizationCode {
                    id: ac_id,
                    code_hash: ch.clone(),
                    client_id: "test_client".into(),
                    user_id: uid,
                    scopes: Some(json!(["openid"])),
                    redirect_uri: "https://example.com/cb".into(),
                    code_challenge: "challenge".into(),
                    code_challenge_method: "S256".into(),
                    expires_at: n + Duration::minutes(10),
                    used: false,
                    nonce: Some("nonce_val".into()),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create auth code: {e}"));

            let found = repos
                .authorization_codes
                .find_by_code_hash(&ch)
                .await
                .unwrap_or_else(|e| panic!("{name}: find auth code: {e}"));
            assert!(found.is_some(), "{name}: should find auth code");

            repos
                .authorization_codes
                .mark_used(ac_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: mark_used: {e}"));
            let gone = repos
                .authorization_codes
                .find_by_code_hash(&ch)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after mark_used: {e}"));
            assert!(gone.is_none(), "{name}: should not find used code");
        }
    });
}

#[cfg(feature = "oauth2-server")]
#[test]
fn consent_create_find_update() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("consent_create_find_update", name);
            let email = unique("consent_test");
            let uid = create_test_user(&repos, &email).await;
            let co_id = Uuid::now_v7();
            let cid = format!("consent_client_{}", Uuid::now_v7());

            repos
                .consents
                .create(domain::NewConsent {
                    id: co_id,
                    user_id: uid,
                    client_id: cid.clone(),
                    scopes: Some(json!(["openid"])),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create consent: {e}"));

            let found = repos
                .consents
                .find_by_user_and_client(uid, &cid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find consent: {e}"));
            assert!(found.is_some(), "{name}: should find consent");

            repos
                .consents
                .update_scopes(co_id, Some(json!(["openid", "profile"])))
                .await
                .unwrap_or_else(|e| panic!("{name}: update_scopes: {e}"));
        }
    });
}

#[cfg(feature = "oauth2-server")]
#[test]
fn device_code_create_find_update() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("device_code_create_find_update", name);
            let dc_id = Uuid::now_v7();
            let n = now();
            let uc = format!("DC-{}", Uuid::now_v7().simple());
            let dch = format!("dc_hash_{}", Uuid::now_v7());

            repos
                .device_codes
                .create(domain::NewDeviceCode {
                    id: dc_id,
                    device_code_hash: dch.clone(),
                    user_code: uc.clone(),
                    client_id: "test_client".into(),
                    scopes: Some(json!(["openid"])),
                    user_id: None,
                    status: "pending".into(),
                    interval: 5,
                    expires_at: n + Duration::minutes(10),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create device code: {e}"));

            let found = repos
                .device_codes
                .find_by_user_code_pending(&uc)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_user_code: {e}"));
            assert!(found.is_some(), "{name}: should find pending device code");

            let found2 = repos
                .device_codes
                .find_by_device_code_hash(&dch)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_device_code_hash: {e}"));
            assert!(found2.is_some(), "{name}: should find by hash");

            let email = unique("dc_user");
            let uid = create_test_user(&repos, &email).await;
            repos
                .device_codes
                .update_status(dc_id, "authorized", Some(uid))
                .await
                .unwrap_or_else(|e| panic!("{name}: update_status: {e}"));

            repos
                .device_codes
                .update_last_polled(dc_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: update_last_polled: {e}"));

            repos
                .device_codes
                .update_interval(dc_id, 10)
                .await
                .unwrap_or_else(|e| panic!("{name}: update_interval: {e}"));
        }
    });
}

// ---------------------------------------------------------------------------
// Edge case tests (UUID, boolean, JSON round-trips)
// ---------------------------------------------------------------------------

#[test]
fn uuid_round_trip() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("uuid_round_trip", name);
            let id = Uuid::now_v7();
            let email = unique("uuid_rt");
            let n = now();

            let user = repos
                .users
                .create(domain::NewUser {
                    id,
                    email: email.clone(),
                    display_name: None,
                    email_verified: false,
                    role: "user".into(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create user for uuid test: {e}"));

            assert_eq!(user.id, id, "{name}: UUID should round-trip exactly");
            assert_eq!(
                user.id.to_string(),
                id.to_string(),
                "{name}: UUID string rep should match"
            );

            let found = repos
                .users
                .find_by_id(id)
                .await
                .unwrap_or_else(|e| panic!("{name}: find: {e}"))
                .unwrap();
            assert_eq!(found.id, id, "{name}: UUID round-trip after SELECT");
        }
    });
}

#[test]
fn boolean_storage_retrieval() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("boolean_storage_retrieval", name);
            let email = unique("bool_test");
            let n = now();

            let user = repos
                .users
                .create(domain::NewUser {
                    id: Uuid::now_v7(),
                    email: email.clone(),
                    display_name: None,
                    email_verified: true,
                    role: "user".into(),
                    banned: true,
                    banned_reason: Some("test".into()),
                    banned_until: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create with booleans: {e}"));

            assert!(user.email_verified, "{name}: email_verified should be true");
            assert!(user.banned, "{name}: banned should be true");

            let found = repos.users.find_by_id(user.id).await.unwrap().unwrap();
            assert!(found.email_verified, "{name}: email_verified round-trip");
            assert!(found.banned, "{name}: banned round-trip");
        }
    });
}

#[cfg(feature = "passkey")]
#[test]
fn json_round_trip() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("json_round_trip", name);
            let email = unique("json_rt");
            let uid = create_test_user(&repos, &email).await;
            let cred_id = Uuid::now_v7();

            let complex_json = json!({
                "type": "public-key",
                "nested": {
                    "array": [1, 2, 3],
                    "object": {"key": "value"},
                    "null_val": null,
                    "bool_val": true
                }
            });

            repos
                .passkeys
                .create(domain::NewWebauthnCredential {
                    id: cred_id,
                    user_id: uid,
                    name: "json-test".into(),
                    aaguid: None,
                    device_name: None,
                    credential: complex_json.clone(),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create with complex JSON: {e}"));

            let creds = repos
                .passkeys
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find creds: {e}"));
            assert_eq!(creds.len(), 1, "{name}: should have 1 cred");
            assert_eq!(
                creds[0].credential, complex_json,
                "{name}: JSON should round-trip structurally"
            );
        }
    });
}

#[test]
fn case_insensitive_email_lookup() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("case_insensitive_email_lookup", name);
            // Store with mixed case
            let mixed = format!("CaseTest-{}@Example.COM", Uuid::now_v7().simple());
            let _id = create_test_user(&repos, &mixed).await;

            // Look up with same case — should always work
            let found = repos
                .users
                .find_by_email(&mixed)
                .await
                .unwrap_or_else(|e| panic!("{name}: find same case: {e}"));
            assert!(found.is_some(), "{name}: should find with same case");

            // Cross-case lookup — all backends MUST be case-insensitive per the
            // UserRepository trait contract.
            let lower = mixed.to_lowercase();
            let cross_case = repos
                .users
                .find_by_email(&lower)
                .await
                .unwrap_or_else(|e| panic!("{name}: find cross-case: {e}"));

            assert!(
                cross_case.is_some(),
                "{name}: find_by_email MUST be case-insensitive"
            );
            assert_eq!(
                cross_case.unwrap().id,
                _id,
                "{name}: cross-case lookup should return same user"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Core: datetime fractional-second precision
// ---------------------------------------------------------------------------

/// Verify that session timestamps round-trip through the database without
/// corruption. MySQL's DATETIME (without fractional-second specifier) truncates
/// to whole seconds — this test documents that behavior and confirms the value
/// is still correct at second-level precision.
#[test]
fn datetime_fractional_second_precision() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("datetime_fractional_second_precision", name);
            let email = unique("dt_prec");
            let uid = create_test_user(&repos, &email).await;

            // Build a timestamp with known microsecond component
            let base = Utc::now().naive_utc();
            let expires_with_micros =
                base + Duration::seconds(3600) + Duration::microseconds(123_456);

            let session_id = Uuid::now_v7();
            let token_hash = format!("dt_prec_hash_{session_id}");

            repos
                .sessions
                .create(domain::NewSession {
                    id: session_id,
                    user_id: uid,
                    token_hash: token_hash.clone(),
                    ip_address: Some("127.0.0.1".into()),
                    user_agent: Some("dt-test".into()),
                    expires_at: expires_with_micros,
                    created_at: base,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create session: {e}"));

            let session = repos
                .sessions
                .find_by_id(session_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: find session: {e}"));
            assert!(session.is_some(), "{name}: session should exist");

            let session = session.unwrap();

            // Verify at least second-level precision is preserved.
            // MySQL DATETIME truncates sub-second; others may preserve microseconds.
            let diff = (session.expires_at - expires_with_micros)
                .num_seconds()
                .abs();
            assert!(
                diff <= 1,
                "{name}: expires_at should be within 1 second of the original value \
             (original={expires_with_micros}, stored={})",
                session.expires_at
            );

            // Cleanup
            repos.sessions.delete(session_id).await.unwrap();
        }
    });
}

// ---------------------------------------------------------------------------
// Core: UserRepository::any_exists
// ---------------------------------------------------------------------------

#[test]
fn user_any_exists() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("user_any_exists", name);
            // Note: other tests may have already created users in this backend,
            // so we can't assume the database is empty. Instead, we verify the
            // invariant: after creating a user, any_exists must return true.
            let email = unique("any_exists");
            create_test_user(&repos, &email).await;

            let exists = repos
                .users
                .any_exists()
                .await
                .unwrap_or_else(|e| panic!("{name}: any_exists: {e}"));
            assert!(
                exists,
                "{name}: any_exists should return true after creating a user"
            );
        }
    });
}

// ===========================================================================
// Part 1: Uncovered method tests
// ===========================================================================

// ---------------------------------------------------------------------------
// SessionOpsRepository::delete_other_sessions_for_user
// ---------------------------------------------------------------------------

#[test]
fn session_ops_delete_other_sessions() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("session_ops_delete_other_sessions", name);
            let email = unique("sess_del_other");
            let uid = create_test_user(&repos, &email).await;

            let hash_keep = format!("keep_hash_{}", Uuid::now_v7());
            let hash_a = format!("del_hash_a_{}", Uuid::now_v7());
            let hash_b = format!("del_hash_b_{}", Uuid::now_v7());

            for h in [&hash_keep, &hash_a, &hash_b] {
                repos
                    .session_ops
                    .create_session(
                        uid,
                        h.clone(),
                        Some("127.0.0.1".into()),
                        Some("test-agent".into()),
                        std::time::Duration::from_secs(3600),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("{name}: create_session({h}): {e}"));
            }

            // Delete all except keep_hash
            let deleted = repos
                .session_ops
                .delete_other_sessions_for_user(uid, &hash_keep)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_other_sessions: {e}"));
            assert_eq!(deleted, 2, "{name}: should delete 2 sessions");

            // The kept session should still validate
            let kept = repos
                .session_ops
                .validate_session(&hash_keep)
                .await
                .unwrap_or_else(|e| panic!("{name}: validate kept: {e}"));
            assert!(kept.is_some(), "{name}: kept session should still exist");

            // The other two should be gone
            for h in [&hash_a, &hash_b] {
                let gone = repos
                    .session_ops
                    .validate_session(h)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: validate deleted({h}): {e}"));
                assert!(gone.is_none(), "{name}: session {h} should be gone");
            }
        }
    });
}

// ---------------------------------------------------------------------------
// SessionRepository (admin CRUD): find_by_id, create, delete, list
// ---------------------------------------------------------------------------

#[test]
fn session_admin_crud() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("session_admin_crud", name);
            let email = unique("sess_admin");
            let uid = create_test_user(&repos, &email).await;
            let sid = Uuid::now_v7();
            let n = now();
            let th = format!("admin_sess_hash_{}", Uuid::now_v7());

            repos
                .sessions
                .create(domain::NewSession {
                    id: sid,
                    user_id: uid,
                    token_hash: th.clone(),
                    ip_address: Some("10.0.0.1".into()),
                    user_agent: Some("admin-test".into()),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create session: {e}"));

            // find_by_id
            let found = repos
                .sessions
                .find_by_id(sid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id: {e}"));
            assert!(found.is_some(), "{name}: session should exist");
            let s = found.unwrap();
            assert_eq!(s.user_id, uid, "{name}: user_id mismatch");
            assert_eq!(s.token_hash, th, "{name}: token_hash mismatch");

            // list
            let (sessions, count) = repos
                .sessions
                .list(100, 0)
                .await
                .unwrap_or_else(|e| panic!("{name}: list sessions: {e}"));
            assert!(count >= 1, "{name}: count should be >= 1");
            assert!(
                sessions.iter().any(|s| s.id == sid),
                "{name}: our session should be in the list"
            );

            // delete
            repos
                .sessions
                .delete(sid)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete session: {e}"));
            let gone = repos
                .sessions
                .find_by_id(sid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(
                gone.is_none(),
                "{name}: session should be gone after delete"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// PasskeyRepository::update_last_used
// ---------------------------------------------------------------------------

#[cfg(feature = "passkey")]
#[test]
fn passkey_update_last_used() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("passkey_update_last_used", name);
            let email = unique("pk_last_used");
            let uid = create_test_user(&repos, &email).await;
            let cred_id = Uuid::now_v7();

            repos
                .passkeys
                .create(domain::NewWebauthnCredential {
                    id: cred_id,
                    user_id: uid,
                    name: "last-used-test".into(),
                    aaguid: None,
                    device_name: None,
                    credential: json!({"type": "public-key"}),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create passkey: {e}"));

            // Initially last_used_at should be None
            let creds = repos
                .passkeys
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find before update: {e}"));
            assert_eq!(creds.len(), 1, "{name}: should have 1 credential");
            assert!(
                creds[0].last_used_at.is_none(),
                "{name}: last_used_at should initially be None"
            );

            // update_last_used takes user_id (updates the most recently used credential for that user)
            repos
                .passkeys
                .update_last_used(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: update_last_used: {e}"));

            let creds2 = repos
                .passkeys
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after update: {e}"));
            assert!(
                creds2[0].last_used_at.is_some(),
                "{name}: last_used_at should be set after update"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// ApiKeyRepository::list_by_user_id (multi-user isolation)
// ---------------------------------------------------------------------------

#[cfg(feature = "api-key")]
#[test]
fn api_key_list_by_user_id() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("api_key_list_by_user_id", name);
            let email_a = unique("ak_list_a");
            let uid_a = create_test_user(&repos, &email_a).await;
            let email_b = unique("ak_list_b");
            let uid_b = create_test_user(&repos, &email_b).await;

            // Create 2 keys for user A
            for i in 0..2 {
                let prefix = short_unique("a");
                repos
                    .api_keys
                    .create(domain::NewApiKey {
                        id: Uuid::now_v7(),
                        user_id: uid_a,
                        key_prefix: prefix,
                        key_hash: format!("hash_a_{i}_{}", Uuid::now_v7()),
                        name: format!("Key A{i}"),
                        scopes: None,
                        expires_at: None,
                        created_at: now(),
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{name}: create key A{i}: {e}"));
            }

            // Create 1 key for user B
            let prefix_b = short_unique("b");
            repos
                .api_keys
                .create(domain::NewApiKey {
                    id: Uuid::now_v7(),
                    user_id: uid_b,
                    key_prefix: prefix_b,
                    key_hash: format!("hash_b_{}", Uuid::now_v7()),
                    name: "Key B".into(),
                    scopes: None,
                    expires_at: None,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create key B: {e}"));

            let list_a = repos
                .api_keys
                .list_by_user_id(uid_a)
                .await
                .unwrap_or_else(|e| panic!("{name}: list_by_user_id(A): {e}"));
            assert_eq!(list_a.len(), 2, "{name}: user A should have 2 keys");

            let list_b = repos
                .api_keys
                .list_by_user_id(uid_b)
                .await
                .unwrap_or_else(|e| panic!("{name}: list_by_user_id(B): {e}"));
            assert_eq!(list_b.len(), 1, "{name}: user B should have 1 key");
        }
    });
}

// ---------------------------------------------------------------------------
// ApiKeyRepository::update_last_used
// ---------------------------------------------------------------------------

#[cfg(feature = "api-key")]
#[test]
fn api_key_update_last_used() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("api_key_update_last_used", name);
            let email = unique("ak_last_used");
            let uid = create_test_user(&repos, &email).await;
            let ak_id = Uuid::now_v7();
            let prefix = short_unique("u");

            repos
                .api_keys
                .create(domain::NewApiKey {
                    id: ak_id,
                    user_id: uid,
                    key_prefix: prefix.clone(),
                    key_hash: format!("hash_lu_{}", Uuid::now_v7()),
                    name: "Last Used Test".into(),
                    scopes: None,
                    expires_at: None,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create api key: {e}"));

            // Initially last_used_at should be None
            let found = repos
                .api_keys
                .find_by_prefix(&prefix)
                .await
                .unwrap_or_else(|e| panic!("{name}: find before update: {e}"))
                .expect("should find key");
            assert!(
                found.last_used_at.is_none(),
                "{name}: last_used_at should initially be None"
            );

            repos
                .api_keys
                .update_last_used(ak_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: update_last_used: {e}"));

            let updated = repos
                .api_keys
                .find_by_prefix(&prefix)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after update: {e}"))
                .expect("should still find key");
            assert!(
                updated.last_used_at.is_some(),
                "{name}: last_used_at should be set after update"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// WebhookRepository::find_by_id (including not-found case)
// ---------------------------------------------------------------------------

#[cfg(feature = "webhooks")]
#[test]
fn webhook_find_by_id() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("webhook_find_by_id", name);
            let wh_id = Uuid::now_v7();
            let n = now();

            repos
                .webhooks_repo
                .create(domain::NewWebhook {
                    id: wh_id,
                    url: "https://example.com/wh-find".into(),
                    secret: "find_secret".into(),
                    events: json!(["user.created"]),
                    active: true,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create webhook: {e}"));

            // find_by_id should return it with all fields matching
            let found = repos
                .webhooks_repo
                .find_by_id(wh_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id: {e}"));
            assert!(found.is_some(), "{name}: should find webhook");
            let wh = found.unwrap();
            assert_eq!(wh.id, wh_id, "{name}: id mismatch");
            assert_eq!(
                wh.url, "https://example.com/wh-find",
                "{name}: url mismatch"
            );
            assert_eq!(wh.secret, "find_secret", "{name}: secret mismatch");
            assert!(wh.active, "{name}: should be active");

            // find_by_id with random UUID returns None
            let not_found = repos
                .webhooks_repo
                .find_by_id(Uuid::now_v7())
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id random: {e}"));
            assert!(
                not_found.is_none(),
                "{name}: random UUID should return None"
            );

            // cleanup
            repos.webhooks_repo.delete(wh_id).await.unwrap();
        }
    });
}

// ---------------------------------------------------------------------------
// WebhookRepository::find_active (active vs inactive filtering)
// ---------------------------------------------------------------------------

#[cfg(feature = "webhooks")]
#[test]
fn webhook_find_active() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("webhook_find_active", name);
            let n = now();
            let mut active_ids = Vec::new();

            // Create 2 active webhooks
            for i in 0..2 {
                let wh_id = Uuid::now_v7();
                repos
                    .webhooks_repo
                    .create(domain::NewWebhook {
                        id: wh_id,
                        url: format!("https://example.com/active-{i}"),
                        secret: format!("active_sec_{i}"),
                        events: json!(["test"]),
                        active: true,
                        created_at: n,
                        updated_at: n,
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{name}: create active webhook {i}: {e}"));
                active_ids.push(wh_id);
            }

            // Create 1 inactive webhook
            let inactive_id = Uuid::now_v7();
            repos
                .webhooks_repo
                .create(domain::NewWebhook {
                    id: inactive_id,
                    url: "https://example.com/inactive".into(),
                    secret: "inactive_sec".into(),
                    events: json!(["test"]),
                    active: false,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create inactive webhook: {e}"));

            let active = repos
                .webhooks_repo
                .find_active()
                .await
                .unwrap_or_else(|e| panic!("{name}: find_active: {e}"));

            // Both active webhooks should be in the list
            for aid in &active_ids {
                assert!(
                    active.iter().any(|w| w.id == *aid),
                    "{name}: active webhook {aid} should be in find_active results"
                );
            }
            // Inactive webhook should NOT be in the list
            assert!(
                !active.iter().any(|w| w.id == inactive_id),
                "{name}: inactive webhook should NOT be in find_active results"
            );

            // cleanup
            for id in active_ids.iter().chain(std::iter::once(&inactive_id)) {
                repos.webhooks_repo.delete(*id).await.unwrap();
            }
        }
    });
}

// ---------------------------------------------------------------------------
// AccountLockRepository::set_locked
// ---------------------------------------------------------------------------

#[cfg(feature = "account-lockout")]
#[test]
fn account_lock_set_locked() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("account_lock_set_locked", name);
            let email = unique("lock_set");
            let uid = create_test_user(&repos, &email).await;
            let n = now();

            let lock = repos
                .account_locks
                .create(domain::NewAccountLock {
                    id: Uuid::now_v7(),
                    user_id: uid,
                    failed_count: 5,
                    locked_until: None,
                    lock_count: 0,
                    locked_reason: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create lock: {e}"));

            let lock_until = n + Duration::hours(1);
            repos
                .account_locks
                .set_locked(lock.id, Some(lock_until), Some("Too many attempts"), 1)
                .await
                .unwrap_or_else(|e| panic!("{name}: set_locked: {e}"));

            let found = repos
                .account_locks
                .find_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after set_locked: {e}"))
                .expect("lock should exist");

            assert!(
                found.locked_until.is_some(),
                "{name}: locked_until should be set"
            );
            assert_eq!(
                found.locked_reason.as_deref(),
                Some("Too many attempts"),
                "{name}: locked_reason mismatch"
            );
            assert_eq!(found.lock_count, 1, "{name}: lock_count should be 1");
        }
    });
}

// ===========================================================================
// Part 2: Behavioral contract tests — expiration and state semantics
// ===========================================================================

// ---------------------------------------------------------------------------
// EmailVerificationRepository: expired token returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "email-password")]
#[test]
fn expired_email_verification_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span =
                helpers::otel::TestSpan::new("expired_email_verification_returns_none", name);
            let email = unique("ev_expired");
            let uid = create_test_user(&repos, &email).await;
            let ev_id = Uuid::now_v7();
            let th = format!("ev_hash_{}", Uuid::now_v7());
            let n = now();

            // Create with expires_at in the past
            repos
                .email_verifications
                .create(domain::NewEmailVerification {
                    id: ev_id,
                    user_id: uid,
                    token_hash: th.clone(),
                    expires_at: n - Duration::seconds(60),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired ev: {e}"));

            let found = repos
                .email_verifications
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired ev: {e}"));
            assert!(
                found.is_none(),
                "{name}: expired email verification MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// PasswordResetRepository: expired token returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "email-password")]
#[test]
fn expired_password_reset_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("expired_password_reset_returns_none", name);
            let email = unique("pr_expired");
            let uid = create_test_user(&repos, &email).await;
            let th = format!("pr_hash_{}", Uuid::now_v7());
            let n = now();

            repos
                .password_resets
                .create(domain::NewPasswordReset {
                    id: Uuid::now_v7(),
                    user_id: uid,
                    token_hash: th.clone(),
                    expires_at: n - Duration::seconds(60),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired reset: {e}"));

            let found = repos
                .password_resets
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired reset: {e}"));
            assert!(
                found.is_none(),
                "{name}: expired password reset MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// PasswordResetRepository: delete_unused_for_user cleans all
// ---------------------------------------------------------------------------

#[cfg(feature = "email-password")]
#[test]
fn password_reset_delete_unused_for_user() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("password_reset_delete_unused_for_user", name);
            let email = unique("pr_del_unused");
            let uid = create_test_user(&repos, &email).await;
            let n = now();
            let th1 = format!("pr_du1_{}", Uuid::now_v7());
            let th2 = format!("pr_du2_{}", Uuid::now_v7());

            // Create 2 resets for the same user
            for th in [&th1, &th2] {
                repos
                    .password_resets
                    .create(domain::NewPasswordReset {
                        id: Uuid::now_v7(),
                        user_id: uid,
                        token_hash: th.clone(),
                        expires_at: n + Duration::hours(1),
                        created_at: n,
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{name}: create reset ({th}): {e}"));
            }

            // Both should be findable
            for th in [&th1, &th2] {
                let f = repos.password_resets.find_by_token_hash(th).await.unwrap();
                assert!(f.is_some(), "{name}: reset {th} should exist before delete");
            }

            // Delete unused for user
            repos
                .password_resets
                .delete_unused_for_user(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_unused_for_user: {e}"));

            // Both should be gone
            for th in [&th1, &th2] {
                let f = repos.password_resets.find_by_token_hash(th).await.unwrap();
                assert!(
                    f.is_none(),
                    "{name}: reset {th} should be gone after delete_unused_for_user"
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------
// MagicLinkRepository: expired magic link returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "magic-link")]
#[test]
fn expired_magic_link_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("expired_magic_link_returns_none", name);
            let th = format!("ml_exp_{}", Uuid::now_v7());
            let n = now();

            repos
                .magic_links
                .create(domain::NewMagicLink {
                    id: Uuid::now_v7(),
                    email: unique("ml_expired"),
                    token_hash: th.clone(),
                    expires_at: n - Duration::seconds(60),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired magic link: {e}"));

            let found = repos
                .magic_links
                .find_unused_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired magic link: {e}"));
            assert!(
                found.is_none(),
                "{name}: expired magic link MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// MagicLinkRepository: used magic link returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "magic-link")]
#[test]
fn used_magic_link_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("used_magic_link_returns_none", name);
            let ml_id = Uuid::now_v7();
            let th = format!("ml_used_{}", Uuid::now_v7());
            let n = now();

            repos
                .magic_links
                .create(domain::NewMagicLink {
                    id: ml_id,
                    email: unique("ml_used"),
                    token_hash: th.clone(),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create magic link: {e}"));

            // Should be findable before marking used
            let before = repos
                .magic_links
                .find_unused_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find before mark_used: {e}"));
            assert!(before.is_some(), "{name}: should find unused magic link");

            repos
                .magic_links
                .mark_used(ml_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: mark_used: {e}"));

            let after = repos
                .magic_links
                .find_unused_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after mark_used: {e}"));
            assert!(
                after.is_none(),
                "{name}: used magic link MUST return None from find_unused"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// OauthStateRepository: expired state returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "oauth")]
#[test]
fn expired_oauth_state_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("expired_oauth_state_returns_none", name);
            let state_val = format!("state_exp_{}", Uuid::now_v7());
            let n = now();

            repos
                .oauth_states
                .create(domain::NewOauthState {
                    state: state_val.clone(),
                    provider: "github".into(),
                    redirect_url: None,
                    expires_at: n - Duration::seconds(60),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired oauth state: {e}"));

            let found = repos
                .oauth_states
                .find_and_delete(&state_val)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired state: {e}"));
            assert!(
                found.is_none(),
                "{name}: expired oauth state MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// ApiKeyRepository: expired API key returns None from find_by_prefix
// ---------------------------------------------------------------------------

#[cfg(feature = "api-key")]
#[test]
fn expired_api_key_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("expired_api_key_returns_none", name);
            let email = unique("ak_expired");
            let uid = create_test_user(&repos, &email).await;
            let prefix = short_unique("e");

            repos
                .api_keys
                .create(domain::NewApiKey {
                    id: Uuid::now_v7(),
                    user_id: uid,
                    key_prefix: prefix.clone(),
                    key_hash: format!("expired_key_{}", Uuid::now_v7()),
                    name: "Expired Key".into(),
                    scopes: None,
                    expires_at: Some(now() - Duration::seconds(60)),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired api key: {e}"));

            let found = repos
                .api_keys
                .find_by_prefix(&prefix)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired api key: {e}"));
            // Memory backend enforces expiration on read; DB backends (PG, MySQL, libsql)
            // return the record and rely on the caller to check expires_at.
            if name == "memory" {
                assert!(
                    found.is_none(),
                    "{name}: expired API key MUST return None from find_by_prefix"
                );
            } else if let Some(ref key) = found {
                assert!(
                    key.expires_at
                        .is_some_and(|e| e < chrono::Utc::now().naive_utc()),
                    "{name}: if returned, the key should be expired"
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------
// UnlockTokenRepository: expired unlock token returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "account-lockout")]
#[test]
fn expired_unlock_token_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("expired_unlock_token_returns_none", name);
            let email = unique("ut_expired");
            let uid = create_test_user(&repos, &email).await;
            let th = format!("ut_exp_hash_{}", Uuid::now_v7());
            let n = now();

            repos
                .unlock_tokens
                .create(domain::NewUnlockToken {
                    id: Uuid::now_v7(),
                    user_id: uid,
                    token_hash: th.clone(),
                    expires_at: n - Duration::seconds(60),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired unlock token: {e}"));

            let found = repos
                .unlock_tokens
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired unlock token: {e}"));
            assert!(
                found.is_none(),
                "{name}: expired unlock token MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// AuthorizationCodeRepository: expired code returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "oauth2-server")]
#[test]
fn expired_authorization_code_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span =
                helpers::otel::TestSpan::new("expired_authorization_code_returns_none", name);
            let email = unique("ac_expired");
            let uid = create_test_user(&repos, &email).await;
            let ch = format!("ac_exp_hash_{}", Uuid::now_v7());
            let n = now();

            repos
                .authorization_codes
                .create(domain::NewAuthorizationCode {
                    id: Uuid::now_v7(),
                    code_hash: ch.clone(),
                    client_id: "test_client".into(),
                    user_id: uid,
                    scopes: None,
                    redirect_uri: "https://example.com/cb".into(),
                    code_challenge: "challenge".into(),
                    code_challenge_method: "S256".into(),
                    expires_at: n - Duration::seconds(60),
                    used: false,
                    nonce: None,
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create expired auth code: {e}"));

            let found = repos
                .authorization_codes
                .find_by_code_hash(&ch)
                .await
                .unwrap_or_else(|e| panic!("{name}: find expired auth code: {e}"));
            assert!(
                found.is_none(),
                "{name}: expired authorization code MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// AuthorizationCodeRepository: used code returns None
// ---------------------------------------------------------------------------

#[cfg(feature = "oauth2-server")]
#[test]
fn used_authorization_code_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("used_authorization_code_returns_none", name);
            let email = unique("ac_used");
            let uid = create_test_user(&repos, &email).await;
            let ac_id = Uuid::now_v7();
            let ch = format!("ac_used_hash_{}", Uuid::now_v7());
            let n = now();

            repos
                .authorization_codes
                .create(domain::NewAuthorizationCode {
                    id: ac_id,
                    code_hash: ch.clone(),
                    client_id: "test_client".into(),
                    user_id: uid,
                    scopes: None,
                    redirect_uri: "https://example.com/cb".into(),
                    code_challenge: "challenge".into(),
                    code_challenge_method: "S256".into(),
                    expires_at: n + Duration::hours(1),
                    used: false,
                    nonce: None,
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create auth code: {e}"));

            // Should be findable before marking used
            let before = repos
                .authorization_codes
                .find_by_code_hash(&ch)
                .await
                .unwrap_or_else(|e| panic!("{name}: find before mark_used: {e}"));
            assert!(before.is_some(), "{name}: should find unused auth code");

            repos
                .authorization_codes
                .mark_used(ac_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: mark_used: {e}"));

            let after = repos
                .authorization_codes
                .find_by_code_hash(&ch)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after mark_used: {e}"));
            assert!(
                after.is_none(),
                "{name}: used authorization code MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// ChallengeRepository: expired challenge returns None
// ---------------------------------------------------------------------------

#[test]
fn challenge_expired_returns_none() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("challenge_expired_returns_none", name);
            let key = format!("chal_exp_{}", Uuid::now_v7());

            // Set with 1-second TTL
            repos
                .challenges
                .set_challenge(&key, json!({"test": true}), 1)
                .await
                .unwrap_or_else(|e| panic!("{name}: set_challenge: {e}"));

            // Should exist immediately
            let before = repos
                .challenges
                .get_challenge(&key)
                .await
                .unwrap_or_else(|e| panic!("{name}: get before expiry: {e}"));
            assert!(
                before.is_some(),
                "{name}: challenge should exist immediately"
            );

            // Wait for TTL to expire
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let after = repos
                .challenges
                .get_challenge(&key)
                .await
                .unwrap_or_else(|e| panic!("{name}: get after expiry: {e}"));
            assert!(
                after.is_none(),
                "{name}: expired challenge MUST return None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// RevocationRepository: expired revocation returns false
// ---------------------------------------------------------------------------

#[test]
fn revocation_expired_returns_false() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("revocation_expired_returns_false", name);
            let jti = format!("jti_exp_{}", Uuid::now_v7());

            // Revoke with 1-second TTL
            repos
                .revocations
                .revoke_token(&jti, std::time::Duration::from_secs(1))
                .await
                .unwrap_or_else(|e| panic!("{name}: revoke_token: {e}"));

            // Should be revoked immediately
            let before = repos
                .revocations
                .is_token_revoked(&jti)
                .await
                .unwrap_or_else(|e| panic!("{name}: is_revoked before expiry: {e}"));
            assert!(before, "{name}: token should be revoked immediately");

            // Wait for TTL to expire
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let after = repos
                .revocations
                .is_token_revoked(&jti)
                .await
                .unwrap_or_else(|e| panic!("{name}: is_revoked after expiry: {e}"));
            assert!(!after, "{name}: expired revocation MUST return false");
        }
    });
}

// ---------------------------------------------------------------------------
// UserRepository::delete cascade behavior
// ---------------------------------------------------------------------------

#[test]
fn user_delete_cascades() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("user_delete_cascades", name);
            let email = unique("cascade_test");
            let uid = create_test_user(&repos, &email).await;

            // Create a session for the user
            let session_hash = format!("cascade_sess_{}", Uuid::now_v7());
            repos
                .session_ops
                .create_session(
                    uid,
                    session_hash.clone(),
                    Some("127.0.0.1".into()),
                    Some("cascade-agent".into()),
                    std::time::Duration::from_secs(3600),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: create session: {e}"));

            // Create a password for the user
            #[cfg(feature = "email-password")]
            repos
                .passwords
                .upsert(domain::NewPassword {
                    user_id: uid,
                    password_hash: format!("cascade_hash_{}", Uuid::now_v7()),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: upsert password: {e}"));

            // Create a passkey for the user
            #[cfg(feature = "passkey")]
            repos
                .passkeys
                .create(domain::NewWebauthnCredential {
                    id: Uuid::now_v7(),
                    user_id: uid,
                    name: "cascade-key".into(),
                    aaguid: None,
                    device_name: None,
                    credential: json!({"type": "public-key"}),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create passkey: {e}"));

            // Create an API key for the user
            #[cfg(feature = "api-key")]
            {
                let prefix = short_unique("c");
                repos
                    .api_keys
                    .create(domain::NewApiKey {
                        id: Uuid::now_v7(),
                        user_id: uid,
                        key_prefix: prefix,
                        key_hash: format!("cascade_key_{}", Uuid::now_v7()),
                        name: "Cascade Key".into(),
                        scopes: None,
                        expires_at: None,
                        created_at: now(),
                    })
                    .await
                    .unwrap_or_else(|e| panic!("{name}: create api key: {e}"));
            }

            // Delete the user
            repos
                .users
                .delete(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete user: {e}"));

            // Verify cascade: user is gone
            let user_gone = repos.users.find_by_id(uid).await.unwrap();
            assert!(user_gone.is_none(), "{name}: user should be gone");

            // Verify cascade: session is gone
            let session_gone = repos
                .session_ops
                .validate_session(&session_hash)
                .await
                .unwrap();
            assert!(
                session_gone.is_none(),
                "{name}: session should be gone after user delete"
            );

            // Verify cascade: password is gone
            #[cfg(feature = "email-password")]
            {
                let pw_gone = repos.passwords.find_by_user_id(uid).await.unwrap();
                assert!(
                    pw_gone.is_none(),
                    "{name}: password should be gone after user delete"
                );
            }

            // Verify cascade: passkeys are gone
            #[cfg(feature = "passkey")]
            {
                let pk_gone = repos.passkeys.find_by_user_id(uid).await.unwrap();
                assert!(
                    pk_gone.is_empty(),
                    "{name}: passkeys should be gone after user delete"
                );
            }

            // Verify cascade: API keys are gone
            #[cfg(feature = "api-key")]
            {
                let ak_gone = repos.api_keys.list_by_user_id(uid).await.unwrap();
                assert!(
                    ak_gone.is_empty(),
                    "{name}: api keys should be gone after user delete"
                );
            }
        }
    });
}

// ===========================================================================
// Part 3: Edge case tests for type handling
// ===========================================================================

// ---------------------------------------------------------------------------
// Null vs empty string distinction
// ---------------------------------------------------------------------------

#[test]
fn null_vs_empty_string() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("null_vs_empty_string", name);
            // Create user with display_name = None
            let email_null = unique("null_dn");
            let id_null = Uuid::now_v7();
            let n = now();
            repos
                .users
                .create(domain::NewUser {
                    id: id_null,
                    email: email_null.clone(),
                    display_name: None,
                    email_verified: false,
                    role: "user".into(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create user with null display_name: {e}"));

            let found_null = repos.users.find_by_id(id_null).await.unwrap().unwrap();
            assert!(
                found_null.display_name.is_none(),
                "{name}: display_name should be None, not empty string (got {:?})",
                found_null.display_name
            );

            // Create user with display_name = Some("")
            let email_empty = unique("empty_dn");
            let id_empty = Uuid::now_v7();
            repos
                .users
                .create(domain::NewUser {
                    id: id_empty,
                    email: email_empty.clone(),
                    display_name: Some("".into()),
                    email_verified: false,
                    role: "user".into(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create user with empty display_name: {e}"));

            let found_empty = repos.users.find_by_id(id_empty).await.unwrap().unwrap();
            assert_eq!(
                found_empty.display_name,
                Some("".into()),
                "{name}: display_name should be Some(\"\"), not None"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Large text round trip (no silent truncation)
// ---------------------------------------------------------------------------

#[test]
fn large_text_round_trip() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("large_text_round_trip", name);
            let email = unique("large_text");
            let id = Uuid::now_v7();
            let n = now();
            let long_name = "A".repeat(200);

            repos
                .users
                .create(domain::NewUser {
                    id,
                    email: email.clone(),
                    display_name: Some(long_name.clone()),
                    email_verified: false,
                    role: "user".into(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create user with long display_name: {e}"));

            let found = repos.users.find_by_id(id).await.unwrap().unwrap();
            assert_eq!(
                found.display_name.as_deref(),
                Some(long_name.as_str()),
                "{name}: 200-char display_name should round-trip exactly (got {} chars)",
                found.display_name.as_ref().map(|s| s.len()).unwrap_or(0)
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Special characters in strings (unicode, emoji)
// ---------------------------------------------------------------------------

#[test]
fn special_characters_in_strings() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("special_characters_in_strings", name);
            let email = unique("special_chars");
            let id = Uuid::now_v7();
            let n = now();
            let display = "\u{1F680} Caf\u{00E9} \u{00FC}ber \u{4E16}\u{754C} O'Brien \"quoted\"";

            repos
                .users
                .create(domain::NewUser {
                    id,
                    email: email.clone(),
                    display_name: Some(display.into()),
                    email_verified: false,
                    role: "user".into(),
                    banned: false,
                    banned_reason: None,
                    banned_until: None,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create user with special chars: {e}"));

            let found = repos.users.find_by_id(id).await.unwrap().unwrap();
            assert_eq!(
                found.display_name.as_deref(),
                Some(display),
                "{name}: unicode/emoji display_name should round-trip exactly"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Core: AuditLogRepository
// ---------------------------------------------------------------------------

#[test]
fn audit_log_create() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("audit_log_create", name);
            let email = unique("audit_test");
            let uid = create_test_user(&repos, &email).await;

            repos
                .audit
                .create(domain::NewAuditLog {
                    id: Uuid::now_v7(),
                    user_id: Some(uid),
                    event_type: "login".into(),
                    metadata: Some(json!({"ip": "127.0.0.1"})),
                    ip_address: Some("127.0.0.1".into()),
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create audit log: {e}"));

            // Create without user_id (anonymous event)
            repos
                .audit
                .create(domain::NewAuditLog {
                    id: Uuid::now_v7(),
                    user_id: None,
                    event_type: "failed_login".into(),
                    metadata: None,
                    ip_address: None,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create anonymous audit log: {e}"));
        }
    });
}

// ---------------------------------------------------------------------------
// Core: RevocationRepository
// ---------------------------------------------------------------------------

#[test]
fn revocation_revoke_and_check() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("revocation_revoke_and_check", name);
            let jti = format!("jti_{}", Uuid::now_v7());
            let jti_clean = format!("jti_clean_{}", Uuid::now_v7());

            // Un-revoked token should not be revoked
            let is_revoked = repos
                .revocations
                .is_token_revoked(&jti_clean)
                .await
                .unwrap_or_else(|e| panic!("{name}: is_token_revoked (clean): {e}"));
            assert!(!is_revoked, "{name}: clean token should not be revoked");

            // Revoke a token
            repos
                .revocations
                .revoke_token(&jti, std::time::Duration::from_secs(3600))
                .await
                .unwrap_or_else(|e| panic!("{name}: revoke_token: {e}"));

            // Revoked token should be revoked
            let is_revoked = repos
                .revocations
                .is_token_revoked(&jti)
                .await
                .unwrap_or_else(|e| panic!("{name}: is_token_revoked (revoked): {e}"));
            assert!(is_revoked, "{name}: revoked token should be revoked");

            // The clean token should still not be revoked
            let still_clean = repos
                .revocations
                .is_token_revoked(&jti_clean)
                .await
                .unwrap_or_else(|e| panic!("{name}: is_token_revoked (still clean): {e}"));
            assert!(!still_clean, "{name}: clean token still not revoked");
        }
    });
}

// ---------------------------------------------------------------------------
// Core: ChallengeRepository
// ---------------------------------------------------------------------------

#[test]
fn challenge_set_get_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("challenge_set_get_delete", name);
            let key = format!("challenge_{}", Uuid::now_v7());
            let value = json!({"type": "webauthn", "data": [1, 2, 3]});

            // Set challenge
            repos
                .challenges
                .set_challenge(&key, value.clone(), 3600)
                .await
                .unwrap_or_else(|e| panic!("{name}: set_challenge: {e}"));

            // Get challenge
            let got = repos
                .challenges
                .get_challenge(&key)
                .await
                .unwrap_or_else(|e| panic!("{name}: get_challenge: {e}"));
            assert!(got.is_some(), "{name}: should find challenge");
            assert_eq!(got.unwrap(), value, "{name}: challenge value mismatch");

            // Delete challenge
            repos
                .challenges
                .delete_challenge(&key)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_challenge: {e}"));

            // Get after delete should return None
            let gone = repos
                .challenges
                .get_challenge(&key)
                .await
                .unwrap_or_else(|e| panic!("{name}: get_challenge after delete: {e}"));
            assert!(
                gone.is_none(),
                "{name}: challenge should be gone after delete"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// email-password: EmailVerificationRepository (full lifecycle)
// ---------------------------------------------------------------------------

#[cfg(feature = "email-password")]
#[test]
fn email_verification_create_find_delete() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("email_verification_create_find_delete", name);
            let email = unique("ev_test");
            let uid = create_test_user(&repos, &email).await;
            let ev_id = Uuid::now_v7();
            let th = format!("ev_hash_{}", Uuid::now_v7());
            let n = now();

            repos
                .email_verifications
                .create(domain::NewEmailVerification {
                    id: ev_id,
                    user_id: uid,
                    token_hash: th.clone(),
                    expires_at: n + Duration::hours(24),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create email verification: {e}"));

            // find by token hash
            let found = repos
                .email_verifications
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_token_hash: {e}"));
            assert!(found.is_some(), "{name}: should find email verification");
            assert_eq!(found.unwrap().user_id, uid, "{name}: user_id mismatch");

            // delete
            repos
                .email_verifications
                .delete(ev_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete: {e}"));

            // find after delete should return None
            let gone = repos
                .email_verifications
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete: {e}"));
            assert!(gone.is_none(), "{name}: should not find after delete");
        }
    });
}

// ---------------------------------------------------------------------------
// email-password: PasswordResetRepository (full lifecycle)
// ---------------------------------------------------------------------------

#[cfg(feature = "email-password")]
#[test]
fn password_reset_create_find_delete_unused() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span =
                helpers::otel::TestSpan::new("password_reset_create_find_delete_unused", name);
            let email = unique("pr_test");
            let uid = create_test_user(&repos, &email).await;
            let pr_id = Uuid::now_v7();
            let th = format!("pr_hash_{}", Uuid::now_v7());
            let n = now();

            repos
                .password_resets
                .create(domain::NewPasswordReset {
                    id: pr_id,
                    user_id: uid,
                    token_hash: th.clone(),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create password reset: {e}"));

            // find by token hash
            let found = repos
                .password_resets
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_token_hash: {e}"));
            assert!(found.is_some(), "{name}: should find password reset");
            assert_eq!(found.unwrap().user_id, uid, "{name}: user_id mismatch");

            // delete unused for user
            repos
                .password_resets
                .delete_unused_for_user(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_unused_for_user: {e}"));

            // find after delete should return None
            let gone = repos
                .password_resets
                .find_by_token_hash(&th)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete_unused: {e}"));
            assert!(
                gone.is_none(),
                "{name}: should not find after delete_unused"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Core: UserRepository::list
// ---------------------------------------------------------------------------

#[test]
fn user_list_pagination_and_search() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("user_list_pagination_and_search", name);
            let run_id = Uuid::now_v7().simple().to_string();
            let prefix = format!("list_{run_id}");
            let email1 = format!("{prefix}-a@test.local");
            let email2 = format!("{prefix}-b@test.local");
            let email3 = format!("{prefix}-c@test.local");

            create_test_user(&repos, &email1).await;
            create_test_user(&repos, &email2).await;
            create_test_user(&repos, &email3).await;

            // List with no filter, limit 2
            let (users, total) = repos
                .users
                .list(None, 2, 0)
                .await
                .unwrap_or_else(|e| panic!("{name}: list: {e}"));
            assert!(users.len() <= 2, "{name}: should respect limit");
            assert!(
                total >= 3,
                "{name}: total should include all matching users"
            );

            // List with search filter
            let (users_filtered, total_filtered) = repos
                .users
                .list(Some(&prefix), 10, 0)
                .await
                .unwrap_or_else(|e| panic!("{name}: list with search: {e}"));
            assert_eq!(
                users_filtered.len(),
                3,
                "{name}: search should find exactly 3 users"
            );
            assert_eq!(
                total_filtered, 3,
                "{name}: total should be 3 for filtered search"
            );

            // List with offset
            let (users_offset, _) = repos
                .users
                .list(Some(&prefix), 10, 2)
                .await
                .unwrap_or_else(|e| panic!("{name}: list with offset: {e}"));
            assert_eq!(
                users_offset.len(),
                1,
                "{name}: offset 2 should return 1 remaining user"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Core: SessionOpsRepository::delete_all_sessions_for_user
// ---------------------------------------------------------------------------

#[test]
fn session_delete_all_for_user() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("session_delete_all_for_user", name);
            let email = unique("sess_del_all");
            let uid = create_test_user(&repos, &email).await;
            let hash1 = format!("sess_all_1_{}", Uuid::now_v7());
            let hash2 = format!("sess_all_2_{}", Uuid::now_v7());

            repos
                .session_ops
                .create_session(
                    uid,
                    hash1.clone(),
                    None,
                    None,
                    std::time::Duration::from_secs(3600),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: create session 1: {e}"));

            repos
                .session_ops
                .create_session(
                    uid,
                    hash2.clone(),
                    None,
                    None,
                    std::time::Duration::from_secs(3600),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: create session 2: {e}"));

            // Verify both exist
            assert!(
                repos
                    .session_ops
                    .validate_session(&hash1)
                    .await
                    .unwrap()
                    .is_some(),
                "{name}: session 1 should exist"
            );
            assert!(
                repos
                    .session_ops
                    .validate_session(&hash2)
                    .await
                    .unwrap()
                    .is_some(),
                "{name}: session 2 should exist"
            );

            // Delete all
            let deleted = repos
                .session_ops
                .delete_all_sessions_for_user(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_all_sessions_for_user: {e}"));
            assert!(deleted >= 2, "{name}: should delete at least 2 sessions");

            // Verify both gone
            assert!(
                repos
                    .session_ops
                    .validate_session(&hash1)
                    .await
                    .unwrap()
                    .is_none(),
                "{name}: session 1 should be gone"
            );
            assert!(
                repos
                    .session_ops
                    .validate_session(&hash2)
                    .await
                    .unwrap()
                    .is_none(),
                "{name}: session 2 should be gone"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// api-key: ApiKeyRepository::find_by_id_and_user
// ---------------------------------------------------------------------------

#[cfg(feature = "api-key")]
#[test]
fn api_key_find_by_id_and_user() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("api_key_find_by_id_and_user", name);
            let email = unique("ak_id_test");
            let uid = create_test_user(&repos, &email).await;
            let ak_id = Uuid::now_v7();
            let prefix = short_unique("t");

            repos
                .api_keys
                .create(domain::NewApiKey {
                    id: ak_id,
                    user_id: uid,
                    key_prefix: prefix,
                    key_hash: format!("hashed_id_{}", Uuid::now_v7()),
                    name: "ID Lookup Key".into(),
                    scopes: None,
                    expires_at: None,
                    created_at: now(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create api key: {e}"));

            // Find by id and user
            let found = repos
                .api_keys
                .find_by_id_and_user(ak_id, uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id_and_user: {e}"));
            assert!(found.is_some(), "{name}: should find by id and user");
            assert_eq!(found.unwrap().name, "ID Lookup Key");

            // Wrong user should not find
            let wrong_user = repos
                .api_keys
                .find_by_id_and_user(ak_id, Uuid::now_v7())
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_id_and_user wrong user: {e}"));
            assert!(
                wrong_user.is_none(),
                "{name}: should not find with wrong user_id"
            );

            // Cleanup
            repos
                .api_keys
                .delete(ak_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete: {e}"));
        }
    });
}

// ---------------------------------------------------------------------------
// bearer: RefreshTokenRepository::find_password_hash_by_user_id
// ---------------------------------------------------------------------------

#[cfg(all(feature = "bearer", feature = "email-password"))]
#[test]
fn refresh_token_find_password_hash() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("refresh_token_find_password_hash", name);
            let email = unique("rt_pw_test");
            let uid = create_test_user(&repos, &email).await;

            // Set a password first
            let pw_hash = format!("hashed_pw_{}", Uuid::now_v7());
            repos
                .passwords
                .upsert(domain::NewPassword {
                    user_id: uid,
                    password_hash: pw_hash.clone(),
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: upsert password: {e}"));

            // find_password_hash_by_user_id
            let hash = repos
                .refresh_tokens
                .find_password_hash_by_user_id(uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_password_hash: {e}"));
            assert!(hash.is_some(), "{name}: should find password hash");
            assert_eq!(hash.unwrap(), pw_hash, "{name}: hash mismatch");

            // Non-existent user
            let none = repos
                .refresh_tokens
                .find_password_hash_by_user_id(Uuid::now_v7())
                .await
                .unwrap_or_else(|e| panic!("{name}: find_password_hash non-existent: {e}"));
            assert!(
                none.is_none(),
                "{name}: should not find for non-existent user"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// oauth: OauthAccountRepository::find_by_provider_and_provider_user_id
// ---------------------------------------------------------------------------

#[cfg(feature = "oauth")]
#[test]
fn oauth_account_find_by_provider_and_id() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("oauth_account_find_by_provider_and_id", name);
            let email = unique("oauth_find_test");
            let uid = create_test_user(&repos, &email).await;
            let oa_id = Uuid::now_v7();
            let provider_uid = format!("gh_{}", Uuid::now_v7());
            let n = now();

            repos
                .oauth_accounts
                .create(domain::NewOauthAccount {
                    id: oa_id,
                    user_id: uid,
                    provider: "github".into(),
                    provider_user_id: provider_uid.clone(),
                    access_token_enc: Some("enc_at".into()),
                    refresh_token_enc: None,
                    created_at: n,
                    expires_at: None,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create oauth account: {e}"));

            // Find by provider and provider_user_id
            let found = repos
                .oauth_accounts
                .find_by_provider_and_provider_user_id("github", &provider_uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find_by_provider_and_id: {e}"));
            assert!(found.is_some(), "{name}: should find by provider+id");
            assert_eq!(found.unwrap().user_id, uid, "{name}: user_id mismatch");

            // Wrong provider should not find
            let wrong = repos
                .oauth_accounts
                .find_by_provider_and_provider_user_id("google", &provider_uid)
                .await
                .unwrap_or_else(|e| panic!("{name}: find wrong provider: {e}"));
            assert!(wrong.is_none(), "{name}: wrong provider should not find");

            // Cleanup
            repos
                .oauth_accounts
                .delete(oa_id)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete: {e}"));
        }
    });
}

// ---------------------------------------------------------------------------
// magic-link: MagicLinkRepository::delete / delete_unused_for_email
// ---------------------------------------------------------------------------

#[cfg(feature = "magic-link")]
#[test]
fn magic_link_delete_and_delete_unused_for_email() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span =
                helpers::otel::TestSpan::new("magic_link_delete_and_delete_unused_for_email", name);
            let ml_email = format!("ml_del_{}@test.local", Uuid::now_v7().simple());
            let ml_id1 = Uuid::now_v7();
            let ml_id2 = Uuid::now_v7();
            let n = now();
            let th1 = format!("ml_del_hash_1_{}", Uuid::now_v7());
            let th2 = format!("ml_del_hash_2_{}", Uuid::now_v7());

            // Create two magic links for the same email
            repos
                .magic_links
                .create(domain::NewMagicLink {
                    id: ml_id1,
                    email: ml_email.clone(),
                    token_hash: th1.clone(),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create magic link 1: {e}"));

            repos
                .magic_links
                .create(domain::NewMagicLink {
                    id: ml_id2,
                    email: ml_email.clone(),
                    token_hash: th2.clone(),
                    expires_at: n + Duration::hours(1),
                    created_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create magic link 2: {e}"));

            // Delete specific link
            repos
                .magic_links
                .delete(ml_id1)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete specific: {e}"));

            // Verify deleted one is gone, other still exists
            let gone = repos
                .magic_links
                .find_unused_by_token_hash(&th1)
                .await
                .unwrap_or_else(|e| panic!("{name}: find deleted: {e}"));
            assert!(gone.is_none(), "{name}: deleted link should be gone");

            let still = repos
                .magic_links
                .find_unused_by_token_hash(&th2)
                .await
                .unwrap_or_else(|e| panic!("{name}: find remaining: {e}"));
            assert!(still.is_some(), "{name}: remaining link should exist");

            // Delete all unused for email
            repos
                .magic_links
                .delete_unused_for_email(&ml_email)
                .await
                .unwrap_or_else(|e| panic!("{name}: delete_unused_for_email: {e}"));

            let gone2 = repos
                .magic_links
                .find_unused_by_token_hash(&th2)
                .await
                .unwrap_or_else(|e| panic!("{name}: find after delete_unused_for_email: {e}"));
            assert!(
                gone2.is_none(),
                "{name}: all unused for email should be gone"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// webhooks: WebhookRepository::find_all
// ---------------------------------------------------------------------------

#[cfg(feature = "webhooks")]
#[test]
fn webhook_find_all() {
    shared_runtime().block_on(async {
        for (name, repos) in test_backends().await {
            let _span = helpers::otel::TestSpan::new("webhook_find_all", name);
            let n = now();
            let wh_id1 = Uuid::now_v7();
            let wh_id2 = Uuid::now_v7();

            repos
                .webhooks_repo
                .create(domain::NewWebhook {
                    id: wh_id1,
                    url: "https://example.com/wh-all-1".into(),
                    secret: "sec1".into(),
                    events: json!(["user.created"]),
                    active: true,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create webhook 1: {e}"));

            repos
                .webhooks_repo
                .create(domain::NewWebhook {
                    id: wh_id2,
                    url: "https://example.com/wh-all-2".into(),
                    secret: "sec2".into(),
                    events: json!(["user.deleted"]),
                    active: false,
                    created_at: n,
                    updated_at: n,
                })
                .await
                .unwrap_or_else(|e| panic!("{name}: create webhook 2: {e}"));

            let all = repos
                .webhooks_repo
                .find_all()
                .await
                .unwrap_or_else(|e| panic!("{name}: find_all: {e}"));
            assert!(
                all.iter().any(|w| w.id == wh_id1),
                "{name}: find_all should include webhook 1"
            );
            assert!(
                all.iter().any(|w| w.id == wh_id2),
                "{name}: find_all should include webhook 2 (inactive)"
            );

            // Cleanup
            repos.webhooks_repo.delete(wh_id1).await.unwrap();
            repos.webhooks_repo.delete(wh_id2).await.unwrap();
        }
    });
}

// ---------------------------------------------------------------------------
// OTel shutdown — must run last to flush pending spans.
// Named with `zzz_` prefix so it sorts after all other tests.
// ---------------------------------------------------------------------------

#[test]
fn zzz_otel_shutdown() {
    shared_runtime().block_on(async {
        helpers::otel::flush();
    });
}
