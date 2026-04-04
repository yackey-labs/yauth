//! Integration tests for the diesel-async database backend.
//!
//! Uses testcontainers to spin up a disposable PostgreSQL instance per test —
//! no external database or `DATABASE_URL` required.
//!
//! ```text
//! cargo test --workspace --features "email-password" -- diesel
//! ```

use std::time::Duration;

use uuid::Uuid;
use yauth::backends::diesel_pg::{DieselBackend, RunQueryDsl};

use yauth::config::YAuthConfig;
use yauth::prelude::*;

mod helpers;
use helpers::{TestDb, drop_yauth_tables};

macro_rules! require_db {
    () => {
        match TestDb::try_new().await {
            Some(db) => db,
            None => {
                eprintln!("No database available — skipping test");
                return;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// 1. Migration runner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_run_migrations_creates_tables() {
    let db = require_db!();
    drop_yauth_tables(&db.pool).await;

    yauth::backends::diesel_pg::migrations::run_migrations(&db.pool)
        .await
        .expect("run_migrations should succeed");

    let tables = yauth::backends::diesel_pg::migrations::list_yauth_tables(&db.pool)
        .await
        .expect("list_yauth_tables should succeed");

    assert!(
        tables.contains(&"yauth_users".to_string()),
        "yauth_users table should exist, got: {tables:?}"
    );
    assert!(
        tables.contains(&"yauth_sessions".to_string()),
        "yauth_sessions table should exist, got: {tables:?}"
    );
    assert!(
        tables.contains(&"yauth_audit_log".to_string()),
        "yauth_audit_log table should exist, got: {tables:?}"
    );

    #[cfg(feature = "email-password")]
    assert!(
        tables.contains(&"yauth_email_verifications".to_string()),
        "yauth_email_verifications table should exist when email-password is enabled, got: {tables:?}"
    );
}

#[tokio::test]
async fn diesel_migrations_are_idempotent() {
    let db = require_db!();

    yauth::backends::diesel_pg::migrations::run_migrations(&db.pool)
        .await
        .expect("first run should succeed");
    yauth::backends::diesel_pg::migrations::run_migrations(&db.pool)
        .await
        .expect("second (idempotent) run should succeed");
}

// ---------------------------------------------------------------------------
// 2. Session lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_session_create_validate_delete() {
    let db = require_db!();

    yauth::backends::diesel_pg::migrations::run_migrations(&db.pool)
        .await
        .expect("migrations");

    let user_id = Uuid::new_v4();

    // Insert a dummy user so the FK (if any) is satisfied.
    {
        let mut conn = db.pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO yauth_users (id, display_name, email, role, banned, email_verified, created_at, updated_at) \
             VALUES ($1, 'Test', 'test@example.com', 'user', false, true, NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .execute(&mut conn)
        .await
        .expect("insert dummy user");
    }

    // Build state for session operations
    let config = YAuthConfig::default();
    let backend = DieselBackend::from_pool(db.pool.clone());
    use yauth::repo::{DatabaseBackend, EnabledFeatures};
    backend
        .migrate(&EnabledFeatures::from_compile_flags())
        .await
        .expect("migrate");
    let mut builder = YAuthBuilder::new(backend, config);
    #[cfg(feature = "bearer")]
    {
        builder = builder.with_bearer(yauth::config::BearerConfig {
            jwt_secret: "test-secret".into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(86400),
            audience: None,
        });
    }
    let state = builder.build().await.expect("build YAuth").into_state();

    // --- Create session ---
    let (token, session_id) = yauth::auth::session::create_session(
        &state,
        user_id,
        Some("127.0.0.1".into()),
        Some("test-agent".into()),
        Duration::from_secs(3600),
    )
    .await
    .expect("create_session should succeed");

    assert!(!token.is_empty(), "token should be non-empty");
    assert_ne!(session_id, Uuid::nil(), "session_id should be non-nil");

    let user = yauth::auth::session::validate_session(
        &state,
        &token,
        Some("127.0.0.1"),
        Some("test-agent"),
    )
    .await
    .expect("validate_session should succeed");

    assert!(user.is_some(), "session should be valid");
    let user = user.unwrap();
    assert_eq!(user.user_id, user_id);
    assert_eq!(user.session_id, session_id);

    // --- Delete session ---
    let deleted = yauth::auth::session::delete_session(&state, &token)
        .await
        .expect("delete_session should succeed");
    assert!(deleted, "delete should report success");

    // Validate again — should now return None
    let user_after = yauth::auth::session::validate_session(
        &state,
        &token,
        Some("127.0.0.1"),
        Some("test-agent"),
    )
    .await
    .expect("validate_session after delete should succeed");
    assert!(user_after.is_none(), "session should be gone after delete");
}

// ---------------------------------------------------------------------------
// 3. Pool sharing — same pool used by YAuth and direct queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_pool_sharing() {
    let db = require_db!();

    yauth::backends::diesel_pg::migrations::run_migrations(&db.pool)
        .await
        .expect("migrations");

    // Build YAuth with the pool
    let config = YAuthConfig::default();
    let backend = DieselBackend::from_pool(db.pool.clone());
    use yauth::repo::{DatabaseBackend, EnabledFeatures};
    backend
        .migrate(&EnabledFeatures::from_compile_flags())
        .await
        .expect("migrate");
    let mut builder = YAuthBuilder::new(backend, config);
    #[cfg(feature = "bearer")]
    {
        builder = builder.with_bearer(yauth::config::BearerConfig {
            jwt_secret: "test-secret".into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(86400),
            audience: None,
        });
    }
    let state = builder.build().await.expect("build YAuth").into_state();

    // Use the pool directly for a raw query
    {
        let mut conn = db.pool.get().await.expect("direct pool connection");
        diesel::sql_query(
            "INSERT INTO yauth_users (id, display_name, email, role, banned, email_verified, created_at, updated_at) \
             VALUES ($1, 'Shared', 'shared@example.com', 'user', false, true, NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::new_v4())
        .execute(&mut conn)
        .await
        .expect("direct insert via shared pool");
    }

    // Verify the user is visible through the repos (pool sharing)
    {
        let (users, total) = state
            .repos
            .users
            .list(None, 10, 0)
            .await
            .expect("list users");
        assert_eq!(total, 1, "should see the user inserted via the shared pool");
        assert_eq!(users.len(), 1);
    }
}
