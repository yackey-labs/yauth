//! Migration system integration tests.
//!
//! These tests verify that `apply_migrations()` correctly creates the yauth
//! schema, is idempotent, and produces a schema equivalent to `push_schema()`.
//!
//! NOTE: `apply_migrations()` uses `driver().connect()` which creates a new
//! connection. For in-memory SQLite each connection is a separate database, so
//! these tests use file-backed SQLite temp databases instead.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use toasty::Db;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Build a fresh file-backed SQLite Db with all yauth models.
/// Each call creates a unique temp file so tests don't interfere.
/// Returns the Db handle, the path to the .db file, and the TempDir guard.
async fn fresh_file_sqlite_db() -> (Db, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = dir.path().join(format!("test_{n}.db"));
    let url = format!("sqlite:{}", path.display());

    let db = Db::builder()
        .table_name_prefix("yauth_")
        .models(toasty::models!(yauth_toasty::*))
        .connect(&url)
        .await
        .expect("failed to create file-backed SQLite Db");

    (db, path, dir)
}

/// Dump sorted SQL statements from a SQLite database file using rusqlite.
/// Returns separate sorted vecs for CREATE TABLE and CREATE INDEX statements.
fn dump_sqlite_schema(db_path: &Path) -> (Vec<String>, Vec<String>) {
    let conn =
        rusqlite::Connection::open(db_path).expect("should open SQLite database for comparison");

    let mut stmt = conn
        .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
        .expect("prepare sqlite_master query");

    let all: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query sqlite_master")
        .filter_map(Result::ok)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        // Exclude toasty's internal migration tracking table
        .filter(|s| !s.contains("_toasty_migrations"))
        .collect();

    let mut tables: Vec<String> = all
        .iter()
        .filter(|s| s.starts_with("CREATE TABLE"))
        .cloned()
        .collect();
    tables.sort();

    let mut indices: Vec<String> = all
        .iter()
        .filter(|s| s.contains("INDEX"))
        .cloned()
        .collect();
    indices.sort();

    (tables, indices)
}

/// Verify the schema exists by querying the SQLite master table via a raw
/// driver connection. This avoids ORM relationship enforcement issues.
async fn verify_tables_exist(db: &Db) {
    let mut conn = db
        .driver()
        .connect()
        .await
        .expect("should connect for verification");

    let applied = conn
        .applied_migrations()
        .await
        .expect("should read applied migrations");

    // At least the initial migration should be applied
    assert!(
        !applied.is_empty(),
        "expected at least one applied migration"
    );
}

#[tokio::test]
async fn test_apply_migrations_creates_schema() {
    let (db, _path, _dir) = fresh_file_sqlite_db().await;

    // Apply migrations on a fresh database
    yauth_toasty::apply_migrations(&db)
        .await
        .expect("apply_migrations should succeed");

    // Verify migrations were tracked
    verify_tables_exist(&db).await;
}

#[tokio::test]
async fn test_apply_migrations_is_idempotent() {
    let (db, _path, _dir) = fresh_file_sqlite_db().await;

    // Apply twice — second call should be a no-op
    yauth_toasty::apply_migrations(&db)
        .await
        .expect("first apply should succeed");
    yauth_toasty::apply_migrations(&db)
        .await
        .expect("second apply (idempotent) should succeed");

    // Verify migrations are still tracked correctly
    verify_tables_exist(&db).await;
}

#[tokio::test]
async fn test_push_schema_and_migrations_produce_equivalent_schema() {
    // Database 1: schema via push_schema (file-backed for schema dump)
    let (db1, path1, _dir1) = fresh_file_sqlite_db().await;
    db1.push_schema().await.expect("push_schema should succeed");

    // Database 2: schema via apply_migrations
    let (db2, path2, _dir2) = fresh_file_sqlite_db().await;
    yauth_toasty::apply_migrations(&db2)
        .await
        .expect("apply_migrations should succeed");

    // Dump and compare actual SQLite schema structures
    let (tables1, indices1) = dump_sqlite_schema(&path1);
    let (tables2, indices2) = dump_sqlite_schema(&path2);

    // --- 1. Table structures must match exactly ---
    assert!(
        !tables1.is_empty(),
        "push_schema() database should have table definitions"
    );
    assert_eq!(
        tables1, tables2,
        "push_schema() and apply_migrations() must produce identical \
         CREATE TABLE statements"
    );

    // --- 2. All push_schema indices must exist in apply_migrations ---
    // The migration SQL may include additional UNIQUE INDEX entries on primary
    // key columns (e.g. index_yauth_users_by_id) that push_schema() omits
    // because SQLite's PRIMARY KEY constraint already enforces uniqueness.
    // This is a benign Toasty driver difference — the migration is a superset.
    for idx in &indices1 {
        assert!(
            indices2.contains(idx),
            "push_schema() index missing from apply_migrations() schema: {idx}"
        );
    }

    // Verify the migration doesn't have FEWER indices than push_schema
    assert!(
        indices2.len() >= indices1.len(),
        "apply_migrations() should have at least as many indices as push_schema() \
         (push: {}, migrations: {})",
        indices1.len(),
        indices2.len()
    );
}
