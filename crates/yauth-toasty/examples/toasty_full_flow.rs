//! End-to-end flow exercising the yauth-toasty repository layer.
//!
//! Demonstrates: create, query (case-insensitive email), update, session
//! lifecycle, and cascade-delete on a single SQLite file-backed database.
//!
//! Run with:
//!
//! ```bash
//! cargo run --manifest-path crates/yauth-toasty/Cargo.toml \
//!     --example toasty_full_flow \
//!     --features email-password,sqlite
//! ```

use std::time::Duration;

use tempfile::NamedTempFile;
use uuid::Uuid;
use yauth::domain::{NewUser, UpdateUser};
use yauth::repo::DatabaseBackend;
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a file-backed SQLite database — Toasty's SQLite driver opens a new
    // connection per query, so `:memory:` would give each query its own empty
    // schema. A temp file gives us an isolated DB that lives only for this
    // process.
    let tmp = NamedTempFile::new()?;
    let url = format!("sqlite:{}", tmp.path().display());

    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .models(yauth_toasty::all_models!())
        .connect(&url)
        .await?;

    apply_migrations(&db).await?;

    let backend = ToastySqliteBackend::from_db(db);
    let repos = backend.repositories();

    // === Create a user ===
    let user_id = Uuid::now_v7();
    let now = chrono::Utc::now().naive_utc();
    let created = repos
        .users
        .create(NewUser {
            id: user_id,
            email: "alice@example.com".to_string(),
            display_name: Some("Alice".to_string()),
            email_verified: false,
            role: "user".to_string(),
            banned: false,
            banned_reason: None,
            banned_until: None,
            created_at: now,
            updated_at: now,
        })
        .await?;
    println!("Created user: {} ({})", created.email, created.id);

    // === Query by email (case-insensitive per repo contract) ===
    let found = repos.users.find_by_email("ALICE@EXAMPLE.COM").await?;
    assert!(found.is_some(), "case-insensitive lookup should find user");
    println!("Found by email: {:?}", found.unwrap().display_name);

    // === Update user ===
    let updated = repos
        .users
        .update(
            user_id,
            UpdateUser {
                email_verified: Some(true),
                display_name: Some(Some("Alice Wonderland".to_string())),
                updated_at: Some(chrono::Utc::now().naive_utc()),
                ..Default::default()
            },
        )
        .await?;
    println!(
        "Updated: email_verified={}, name={:?}",
        updated.email_verified, updated.display_name
    );

    // === Create a session (relationship: user has_many sessions) ===
    let token_hash = "token_hash_abc123".to_string();
    let session_id = repos
        .session_ops
        .create_session(
            user_id,
            token_hash.clone(),
            Some("127.0.0.1".to_string()),
            Some("Mozilla/5.0 (example)".to_string()),
            Duration::from_secs(3600),
        )
        .await?;
    println!("Created session: {session_id}");

    // === Validate session ===
    let session = repos.session_ops.validate_session(&token_hash).await?;
    assert!(session.is_some(), "session should validate");
    println!("Session valid for user: {}", session.unwrap().user_id);

    // === Cascade delete: deleting the user removes their sessions ===
    repos.users.delete(user_id).await?;
    let after = repos.session_ops.validate_session(&token_hash).await?;
    assert!(after.is_none(), "session should be gone after user delete");
    println!("After user delete: session gone (cascade works)");

    println!("\n\u{2713} All operations succeeded!");
    Ok(())
}
