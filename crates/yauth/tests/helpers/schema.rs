//! Test helper: sets up yauth schema via raw DDL for all backends.
//!
//! Uses `yauth-migration` (a dev-dependency) to generate CREATE TABLE statements,
//! then executes them on the given pool/connection.

use yauth_migration::{
    ALL_PLUGINS, collect_schema_for_plugins, generate_mysql_ddl, generate_postgres_ddl,
    generate_sqlite_ddl,
};

fn all_plugins_schema() -> yauth_migration::YAuthSchema {
    let plugins: Vec<String> = ALL_PLUGINS.iter().map(|s| (*s).to_string()).collect();
    collect_schema_for_plugins(&plugins, "yauth_").expect("collect schema")
}

/// Split DDL on semicolons into individual non-empty statements.
fn ddl_statements(ddl: &str) -> Vec<&str> {
    ddl.split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── Diesel PG ──────────────────────────────────────────────────────────────

#[cfg(feature = "diesel-pg-backend")]
pub async fn setup_pg_schema_diesel(pool: &yauth::state::DbPool) {
    use yauth::backends::diesel_pg::RunQueryDsl;

    let ddl = generate_postgres_ddl(&all_plugins_schema());
    let mut conn = pool
        .get()
        .await
        .expect("pg pool connection for schema setup");
    for stmt in ddl_statements(&ddl) {
        diesel::sql_query(stmt)
            .execute(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("PG DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── Diesel MySQL ───────────────────────────────────────────────────────────

#[cfg(feature = "diesel-mysql-backend")]
pub async fn setup_mysql_schema_diesel(pool: &yauth::backends::diesel_mysql::MysqlPool) {
    use diesel_async_crate::SimpleAsyncConnection;

    let ddl = generate_mysql_ddl(&all_plugins_schema());
    let mut conn = pool
        .get()
        .await
        .expect("mysql pool connection for schema setup");
    for stmt in ddl_statements(&ddl) {
        (*conn)
            .batch_execute(stmt)
            .await
            .unwrap_or_else(|e| panic!("MySQL DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── Diesel SQLite ──────────────────────────────────────────────────────────

#[cfg(feature = "diesel-sqlite-backend")]
pub async fn setup_sqlite_schema_diesel(pool: &yauth::backends::diesel_sqlite::SqlitePool) {
    use diesel_async_crate::SimpleAsyncConnection;

    let ddl = generate_sqlite_ddl(&all_plugins_schema());
    let mut conn = pool
        .get()
        .await
        .expect("sqlite pool connection for schema setup");
    (*conn)
        .batch_execute("PRAGMA foreign_keys = ON")
        .await
        .expect("PRAGMA foreign_keys");
    for stmt in ddl_statements(&ddl) {
        (*conn)
            .batch_execute(stmt)
            .await
            .unwrap_or_else(|e| panic!("SQLite DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── Diesel libsql ──────────────────────────────────────────────────────────

#[cfg(feature = "diesel-libsql-backend")]
pub async fn setup_libsql_schema_diesel(pool: &yauth::backends::diesel_libsql::LibsqlPool) {
    use diesel_async_crate::SimpleAsyncConnection;

    let ddl = generate_sqlite_ddl(&all_plugins_schema());
    let mut conn = pool
        .get()
        .await
        .expect("libsql pool connection for schema setup");
    (*conn)
        .batch_execute("PRAGMA foreign_keys = ON")
        .await
        .expect("PRAGMA foreign_keys");
    for stmt in ddl_statements(&ddl) {
        (*conn)
            .batch_execute(stmt)
            .await
            .unwrap_or_else(|e| panic!("libsql DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── sqlx PG ────────────────────────────────────────────────────────────────

#[cfg(feature = "sqlx-pg-backend")]
pub async fn setup_pg_schema_sqlx(pool: &sqlx::PgPool) {
    let ddl = generate_postgres_ddl(&all_plugins_schema());
    for stmt in ddl_statements(&ddl) {
        sqlx::raw_sql(stmt)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("sqlx PG DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── sqlx MySQL ─────────────────────────────────────────────────────────────

#[cfg(feature = "sqlx-mysql-backend")]
pub async fn setup_mysql_schema_sqlx(pool: &sqlx::MySqlPool) {
    let ddl = generate_mysql_ddl(&all_plugins_schema());
    for stmt in ddl_statements(&ddl) {
        sqlx::raw_sql(stmt)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("sqlx MySQL DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── sqlx SQLite ────────────────────────────────────────────────────────────

#[cfg(feature = "sqlx-sqlite-backend")]
pub async fn setup_sqlite_schema_sqlx(pool: &sqlx::SqlitePool) {
    sqlx::raw_sql("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .execute(pool)
        .await
        .expect("PRAGMA setup");
    let ddl = generate_sqlite_ddl(&all_plugins_schema());
    for stmt in ddl_statements(&ddl) {
        sqlx::raw_sql(stmt)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("sqlx SQLite DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── SeaORM PG ─────────────────────────────────────────────────────────────

#[cfg(feature = "seaorm-pg-backend")]
pub async fn setup_pg_schema_seaorm(db: &sea_orm::DatabaseConnection) {
    use sea_orm::ConnectionTrait;
    let ddl = generate_postgres_ddl(&all_plugins_schema());
    for stmt in ddl_statements(&ddl) {
        db.execute_unprepared(stmt)
            .await
            .unwrap_or_else(|e| panic!("SeaORM PG DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── SeaORM MySQL ──────────────────────────────────────────────────────────

#[cfg(feature = "seaorm-mysql-backend")]
pub async fn setup_mysql_schema_seaorm(db: &sea_orm::DatabaseConnection) {
    use sea_orm::ConnectionTrait;
    let ddl = generate_mysql_ddl(&all_plugins_schema());
    for stmt in ddl_statements(&ddl) {
        db.execute_unprepared(stmt)
            .await
            .unwrap_or_else(|e| panic!("SeaORM MySQL DDL failed: {e}\nStatement: {stmt}"));
    }
}

// ── SeaORM SQLite ─────────────────────────────────────────────────────────

#[cfg(feature = "seaorm-sqlite-backend")]
pub async fn setup_sqlite_schema_seaorm(db: &sea_orm::DatabaseConnection) {
    use sea_orm::ConnectionTrait;
    db.execute_unprepared("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .await
        .expect("PRAGMA setup");
    let ddl = generate_sqlite_ddl(&all_plugins_schema());
    for stmt in ddl_statements(&ddl) {
        db.execute_unprepared(stmt)
            .await
            .unwrap_or_else(|e| panic!("SeaORM SQLite DDL failed: {e}\nStatement: {stmt}"));
    }
}
