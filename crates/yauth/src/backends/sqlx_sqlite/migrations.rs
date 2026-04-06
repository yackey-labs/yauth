//! Migration runner for sqlx-sqlite backend.
//! Uses the declarative schema system from yauth-migration.

use sqlx::SqlitePool;

pub(crate) async fn run_migrations(
    pool: &SqlitePool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let table_lists = crate::schema::collect_feature_gated_schemas();
    let merged = crate::schema::collect_schema(table_lists)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Enable WAL mode and foreign keys
    sqlx::raw_sql("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .execute(pool)
        .await?;

    // Create tracking table
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS yauth_schema_migrations (\
         id INTEGER PRIMARY KEY AUTOINCREMENT, \
         schema_hash TEXT NOT NULL, \
         applied_at TEXT NOT NULL DEFAULT (datetime('now'))\
         )",
    )
    .execute(pool)
    .await?;

    // Check schema hash
    let hash = crate::schema::schema_hash(&merged);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM yauth_schema_migrations WHERE schema_hash = ?")
            .bind(&hash)
            .fetch_one(pool)
            .await?;

    if count.0 > 0 {
        return Ok(());
    }

    // Generate and run SQLite DDL
    let ddl = crate::schema::generate_sqlite_ddl(&merged);

    for statement in ddl.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        sqlx::raw_sql(trimmed).execute(pool).await?;
    }

    // Record the schema hash
    sqlx::query("INSERT INTO yauth_schema_migrations (schema_hash) VALUES (?)")
        .bind(&hash)
        .execute(pool)
        .await?;

    Ok(())
}
