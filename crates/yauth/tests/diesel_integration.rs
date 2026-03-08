//! Integration tests for the diesel-async database backend.
//!
//! These tests require a running PostgreSQL instance. Set the `DATABASE_URL`
//! environment variable to a connection string for a **disposable** test
//! database, e.g.:
//!
//! ```text
//! DATABASE_URL=postgres://yauth:yauth@localhost:5432/yauth_test \
//!   cargo test --workspace --no-default-features \
//!     --features "diesel-async,email-password" -- diesel
//! ```
//!
//! If `DATABASE_URL` is not set the tests are silently skipped.
//!
//! ## Compile-time exclusivity
//!
//! The `seaorm` and `diesel-async` features are mutually exclusive —
//! `crates/yauth/src/state.rs` contains:
//!
//! ```ignore
//! #[cfg(all(feature = "seaorm", feature = "diesel-async"))]
//! compile_error!("Features `seaorm` and `diesel-async` are mutually exclusive.");
//! ```
//!
//! Attempting `--features "seaorm,diesel-async"` will fail at compile time.
//! This is intentionally *not* tested at runtime because there is no way to
//! catch a `compile_error!` from a running test.

#![cfg(feature = "diesel-async")]

use std::time::Duration;

use uuid::Uuid;
use yauth::AsyncDieselConnectionManager;
use yauth::AsyncPgConnection;
use yauth::DieselPool;
use yauth::RunQueryDsl;

use yauth::config::YAuthConfig;
use yauth::prelude::*;
use yauth::state::DbPool;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to build a deadpool pool from `DATABASE_URL` and verify the connection
/// works. Returns `None` when the env var is missing or the server is
/// unreachable, so the calling test can skip gracefully.
async fn try_pool() -> Option<DbPool> {
    let url = std::env::var("DATABASE_URL").ok().or_else(|| {
        eprintln!("DATABASE_URL not set — skipping test");
        None
    })?;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
    let pool = DieselPool::builder(manager)
        .max_size(4)
        .build()
        .expect("failed to build diesel deadpool");

    // Eagerly verify the connection works — skip if the server is unreachable.
    match pool.get().await {
        Ok(_) => Some(pool),
        Err(e) => {
            eprintln!("Cannot connect to database — skipping test: {e}");
            None
        }
    }
}

/// Convenience macro: skip the test when no database is available.
macro_rules! require_db {
    () => {
        match try_pool().await {
            Some(pool) => pool,
            None => return,
        }
    };
}

/// Drop all `yauth_*` tables so every test starts from a clean slate.
async fn drop_yauth_tables(pool: &DbPool) {
    let mut conn = pool.get().await.expect("pool connection");
    diesel::sql_query(
        "DO $$ DECLARE r RECORD; BEGIN \
         FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'yauth_%') LOOP \
         EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(r.tablename) || ' CASCADE'; \
         END LOOP; END $$;",
    )
    .execute(&mut conn)
    .await
    .expect("failed to drop yauth tables");
}

// ---------------------------------------------------------------------------
// 1. Migration runner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_run_migrations_creates_tables() {
    let pool = require_db!();

    // Clean slate
    drop_yauth_tables(&pool).await;

    // Run migrations
    yauth::migration::diesel_migrations::run_migrations(&pool)
        .await
        .expect("run_migrations should succeed");

    // Verify core tables exist
    let tables = yauth::migration::diesel_migrations::list_yauth_tables(&pool)
        .await
        .expect("list_yauth_tables should succeed");

    // Core tables that are always created
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

    // email-password tables (only when feature is enabled)
    #[cfg(feature = "email-password")]
    assert!(
        tables.contains(&"yauth_email_verifications".to_string()),
        "yauth_email_verifications table should exist when email-password is enabled, got: {tables:?}"
    );

    // Clean up
    drop_yauth_tables(&pool).await;
}

#[tokio::test]
async fn diesel_migrations_are_idempotent() {
    let pool = require_db!();
    drop_yauth_tables(&pool).await;

    // Run migrations twice — the SQL uses IF NOT EXISTS, so this must not error.
    yauth::migration::diesel_migrations::run_migrations(&pool)
        .await
        .expect("first run should succeed");
    yauth::migration::diesel_migrations::run_migrations(&pool)
        .await
        .expect("second (idempotent) run should succeed");

    drop_yauth_tables(&pool).await;
}

// ---------------------------------------------------------------------------
// 2. Session lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_session_create_validate_delete() {
    let pool = require_db!();
    drop_yauth_tables(&pool).await;

    yauth::migration::diesel_migrations::run_migrations(&pool)
        .await
        .expect("migrations");

    let user_id = Uuid::new_v4();

    // Insert a dummy user so the FK (if any) is satisfied.
    {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "INSERT INTO yauth_users (id, display_name, email, role, is_banned, email_verified, created_at, updated_at) \
             VALUES ($1, 'Test', 'test@example.com', 'user', false, true, NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .execute(&mut conn)
        .await
        .expect("insert dummy user");
    }

    // --- Create session ---
    let (token, session_id) = yauth::auth::session::create_session(
        &pool,
        user_id,
        Some("127.0.0.1".into()),
        Some("test-agent".into()),
        Duration::from_secs(3600),
    )
    .await
    .expect("create_session should succeed");

    assert!(!token.is_empty(), "token should be non-empty");
    assert_ne!(session_id, Uuid::nil(), "session_id should be non-nil");

    // --- Validate session ---
    let config = YAuthConfig::default();
    let state = YAuthBuilder::new(pool.clone(), config).build().into_state();

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
    let deleted = yauth::auth::session::delete_session(&pool, &token)
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

    drop_yauth_tables(&pool).await;
}

// ---------------------------------------------------------------------------
// 3. Pool sharing — same pool used by YAuth and direct queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diesel_pool_sharing() {
    let pool = require_db!();
    drop_yauth_tables(&pool).await;

    yauth::migration::diesel_migrations::run_migrations(&pool)
        .await
        .expect("migrations");

    // Build YAuth with the pool
    let config = YAuthConfig::default();
    let state = YAuthBuilder::new(pool.clone(), config).build().into_state();

    // Use the pool directly for a raw query
    {
        let mut conn = pool.get().await.expect("direct pool connection");
        diesel::sql_query(
            "INSERT INTO yauth_users (id, display_name, email, role, is_banned, email_verified, created_at, updated_at) \
             VALUES ($1, 'Shared', 'shared@example.com', 'user', false, true, NOW(), NOW())",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::new_v4())
        .execute(&mut conn)
        .await
        .expect("direct insert via shared pool");
    }

    // Use the pool through YAuth state to verify sharing works
    {
        let mut conn = state.db.get().await.expect("state pool connection");

        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            cnt: i64,
        }

        let row: CountRow = diesel::sql_query("SELECT COUNT(*) AS cnt FROM yauth_users")
            .get_result(&mut conn)
            .await
            .expect("count via state pool");

        assert_eq!(
            row.cnt, 1,
            "should see the user inserted via the shared pool"
        );
    }

    drop_yauth_tables(&pool).await;
}
