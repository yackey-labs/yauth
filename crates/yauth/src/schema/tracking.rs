//! Schema tracking table — records applied schema hashes to make migrations idempotent.

use super::collector::YAuthSchema;

/// Compute a deterministic hash of the schema for tracking purposes.
///
/// The hash is based on a canonical text representation of all tables,
/// columns, types, constraints, and foreign keys — sorted deterministically.
pub fn schema_hash(schema: &YAuthSchema) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    for table in &schema.tables {
        hasher.update(b"TABLE:");
        hasher.update(table.name.as_bytes());
        hasher.update(b"\n");

        for col in &table.columns {
            hasher.update(b"  COL:");
            hasher.update(col.name.as_bytes());
            hasher.update(b":");
            hasher.update(format!("{:?}", col.col_type).as_bytes());
            hasher.update(b":");
            hasher.update(if col.nullable {
                b"NULL" as &[u8]
            } else {
                b"NOT_NULL"
            });
            hasher.update(b":");
            hasher.update(if col.primary_key { b"PK" as &[u8] } else { b"" });
            hasher.update(b":");
            hasher.update(if col.unique { b"UQ" as &[u8] } else { b"" });
            hasher.update(b":");
            if let Some(default) = col.default {
                hasher.update(b"DEFAULT=");
                hasher.update(default.as_bytes());
            }
            hasher.update(b":");
            if let Some(ref fk) = col.foreign_key {
                hasher.update(b"FK=");
                hasher.update(fk.references_table.as_bytes());
                hasher.update(b".");
                hasher.update(fk.references_column.as_bytes());
                hasher.update(b":");
                hasher.update(format!("{:?}", fk.on_delete).as_bytes());
            }
            hasher.update(b"\n");
        }
    }

    let result = hasher.finalize();
    hex::encode(result)
}

/// Ensure the `yauth_schema_migrations` tracking table exists.
#[cfg(feature = "diesel-backend")]
pub async fn ensure_tracking_table(
    conn: &mut diesel_async_crate::AsyncPgConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::RunQueryDsl;

    diesel::sql_query(
        "CREATE TABLE IF NOT EXISTS yauth_schema_migrations (\
            id SERIAL PRIMARY KEY, \
            schema_hash VARCHAR(64) NOT NULL, \
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\
        )",
    )
    .execute(conn)
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(())
}

/// Check if the given schema hash has already been applied.
#[cfg(feature = "diesel-backend")]
pub async fn is_schema_applied(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    hash: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::QueryableByName;
    use diesel::sql_types::BigInt;
    use diesel_async_crate::RunQueryDsl;

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    let rows: Vec<CountRow> = diesel::sql_query(
        "SELECT COUNT(*)::bigint AS count FROM yauth_schema_migrations WHERE schema_hash = $1",
    )
    .bind::<diesel::sql_types::Text, _>(hash)
    .load(conn)
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(rows
        .into_iter()
        .next()
        .map(|r| r.count > 0)
        .unwrap_or(false))
}

/// Record that a schema hash has been applied.
#[cfg(feature = "diesel-backend")]
pub async fn record_schema_applied(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    hash: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::RunQueryDsl;

    diesel::sql_query("INSERT INTO yauth_schema_migrations (schema_hash) VALUES ($1)")
        .bind::<diesel::sql_types::Text, _>(hash)
        .execute(conn)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(())
}
