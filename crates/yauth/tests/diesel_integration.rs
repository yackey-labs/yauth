//! Integration tests for the diesel-async database backend.
//!
//! Uses testcontainers to spin up a disposable PostgreSQL instance per test —
//! no external database or `DATABASE_URL` required.
//!
//! All tests are parallel-safe: unique data per test and rate limits disabled
//! where applicable.
//!
//! ```text
//! cargo test --workspace --features "email-password" -- diesel
//! ```

use std::time::Duration;

use uuid::Uuid;
use yauth::backends::diesel_pg::{DieselPgBackend, RunQueryDsl};

use yauth::config::YAuthConfig;
use yauth::prelude::*;

mod helpers;
use helpers::TestDb;

/// Shared DB — reuses a single instance with schema set up. Safe for parallel tests.
macro_rules! require_db {
    () => {
        match TestDb::shared().await {
            Some(db) => db,
            None => {
                eprintln!("No database available — skipping test");
                return;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// 1. Session lifecycle (migration tests removed — yauth no longer owns migrations)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_session_create_validate_delete() {
    let db = require_db!();

    let user_id = Uuid::now_v7();
    let email = format!("session_test_{}@example.com", Uuid::now_v7());

    // Insert a dummy user so the FK (if any) is satisfied.
    {
        let mut conn = db.pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO yauth_users (id, display_name, email, role, banned, email_verified, created_at, updated_at) \
             VALUES ($1, 'Test', $2, 'user', false, true, NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Text, _>(&email)
        .execute(&mut conn)
        .await
        .expect("insert dummy user");
    }

    // Build state for session operations (shared DB schema set up via raw DDL)
    let config = YAuthConfig::default();
    let backend = DieselPgBackend::from_pool(db.pool.clone());
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

    // Build YAuth with the shared pool (already migrated)
    let config = YAuthConfig::default();
    let backend = DieselPgBackend::from_pool(db.pool.clone());
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
    let shared_email = format!("shared_{}@example.com", Uuid::now_v7());
    {
        let mut conn = db.pool.get().await.expect("direct pool connection");
        diesel::sql_query(
            "INSERT INTO yauth_users (id, display_name, email, role, banned, email_verified, created_at, updated_at) \
             VALUES ($1, 'Shared', $2, 'user', false, true, NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<diesel::sql_types::Text, _>(&shared_email)
        .execute(&mut conn)
        .await
        .expect("direct insert via shared pool");
    }

    // Verify the user is visible through the repos (pool sharing)
    {
        let user = state
            .repos
            .users
            .find_by_email(&shared_email)
            .await
            .expect("find_by_email");
        assert!(
            user.is_some(),
            "user inserted via shared pool should be visible through repos"
        );
    }
}
